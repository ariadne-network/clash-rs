//! HTTPS decryption (MITM, our fork). For the hosts listed, the engine
//! completes TLS with the client itself, with a certificate for the host
//! that the configured CA signs, reads the HTTP/1.1 or HTTP/2 requests and
//! sends each through the rule's outbound, over its own TLS to the server.
//! Requests and responses pass an `HttpProcessor` on the way (rewrites,
//! scripts). The upstream handshake goes first, with the client's server
//! name and protocols, so the client gets the protocol the server chose.
//!
//! Only TLS that carries HTTP is decrypted; a pinned client refuses the
//! certificate, so its hosts belong out of the list. QUIC to listed hosts
//! is refused (`blocks_quic`), so clients fall back to TCP.
//!
//! With rewrites, plain HTTP passes the processor too: TCP to the hosts of
//! `force-http-engine-hosts` when the client's first bytes are an HTTP
//! request, and to port 80 when the first request is one a rewrite takes.
//! Anything else is relayed as it came.
//!
//! Above `memory_ceiling` (the iOS packet tunnel's limit is about 50 MiB),
//! new connections are relayed as they are: decrypted ones hold two TLS
//! sessions and HTTP buffers each.

mod ca;
mod rewrite;

use std::{
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use async_trait::async_trait;
use bytes::Bytes;
use http::{Method, Request, Response, StatusCode, header};
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::{body::Incoming, service::service_fn};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::{
    ClientConfig, ServerConfig,
    pki_types::ServerName,
    server::{Acceptor, ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio_rustls::{LazyConfigAcceptor, TlsConnector};
use tracing::{debug, info, warn};

pub use ca::{Authority, generate_ca};
pub use rewrite::{RewriteConfig, Rewriter};

use crate::{
    common::{
        tls::{DefaultTlsVerifier, GLOBAL_ROOT_STORE},
        utils::memory_footprint,
    },
    config::def::MitmConfig,
    proxy::ProxyStream,
    session::{Network, Session, SocksAddr},
};

pub type Body = BoxBody<Bytes, hyper::Error>;

/// What happens to a request: it goes on (maybe changed), or gets an
/// answer here.
pub enum RequestOutcome {
    Forward(Request<Body>),
    Respond(Response<Body>),
    /// No answer: the connection (HTTP/1.1) or the stream (HTTP/2) is
    /// dropped.
    Drop,
}

/// Rewrites and scripts on decrypted HTTP. `url` is the request's full URL.
#[async_trait]
pub trait HttpProcessor: Send + Sync {
    /// Whether anything applies to requests for `url`: a plain HTTP
    /// connection is relayed as it is otherwise.
    fn wants(&self, _url: &str) -> bool {
        true
    }

    async fn request(&self, _url: &str, req: Request<Body>) -> RequestOutcome {
        RequestOutcome::Forward(req)
    }

    async fn response(
        &self,
        _url: &str,
        _method: &Method,
        resp: Response<Body>,
    ) -> Response<Body> {
        resp
    }
}

/// Changes nothing.
pub struct Passthrough;

impl HttpProcessor for Passthrough {}

/// A body of these bytes.
pub fn full_body(bytes: impl Into<Bytes>) -> Body {
    Full::new(bytes.into())
        .map_err(|never| match never {})
        .boxed()
}

pub struct Mitm {
    hosts: HostList,
    /// None: nothing is decrypted, only plain HTTP rewritten.
    authority: Option<Authority>,
    /// Plain HTTP besides port 80; read only with rewrites.
    plain_hosts: HostList,
    rewrites: bool,
    h2: bool,
    quic_block: bool,
    processor: Arc<dyn HttpProcessor>,
    /// Upstream configurations by what the client offered: h2 and
    /// HTTP/1.1, h2 only, HTTP/1.1 only.
    upstream_h2_h1: Arc<ClientConfig>,
    upstream_h2: Arc<ClientConfig>,
    upstream_h1: Arc<ClientConfig>,
}

impl std::fmt::Debug for Mitm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Mitm").finish()
    }
}

impl Mitm {
    /// None when there is nothing to do: no hosts and CA to decrypt with,
    /// and no rewrites.
    pub fn new(
        mitm: Option<&MitmConfig>,
        rewrite: Option<&RewriteConfig>,
    ) -> Result<Option<Arc<Self>>, String> {
        let rewrite = rewrite.filter(|r| !r.is_empty());
        let hosts = HostList::new(mitm.map_or(&[][..], |m| &m.hostname), 443);
        let authority = match mitm {
            Some(MitmConfig {
                ca_cert: Some(cert),
                ca_key: Some(key),
                ..
            }) if !hosts.is_empty() => Some(Authority::new(cert, key)?),
            _ => None,
        };
        if authority.is_none() && rewrite.is_none() {
            return Ok(None);
        }
        let skip = mitm.is_some_and(|m| m.skip_server_cert_verify);
        let upstream = |alpn: &[&[u8]]| {
            let mut c = ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(DefaultTlsVerifier::new(
                    None, skip,
                )))
                .with_no_client_auth();
            c.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
            Arc::new(c)
        };
        let _ = &GLOBAL_ROOT_STORE; // the verifier's roots
        let processor: Arc<dyn HttpProcessor> = match rewrite {
            Some(r) => Arc::new(Rewriter::new(r.clone())),
            None => Arc::new(Passthrough),
        };
        Ok(Some(Arc::new(Self {
            hosts,
            authority,
            plain_hosts: HostList::new(
                rewrite.map_or(&[][..], |r| &r.force_http_engine_hosts),
                80,
            ),
            rewrites: rewrite.is_some(),
            h2: mitm.is_some_and(|m| m.h2),
            quic_block: mitm.is_some_and(|m| m.auto_quic_block),
            processor,
            upstream_h2_h1: upstream(&[b"h2", b"http/1.1"]),
            upstream_h2: upstream(&[b"h2"]),
            upstream_h1: upstream(&[b"http/1.1"]),
        })))
    }

    /// Whether this TCP connection may be decrypted or read as HTTP
    /// (`serve`).
    pub fn handles(&self, sess: &Session) -> bool {
        sess.network == Network::Tcp
            && (self.decrypts(&sess.destination)
                || self.decrypts_by_name(&sess.destination)
                || self.reads_plain(&sess.destination))
            && !over_memory_ceiling()
    }

    /// A connection to an address, as from apps that resolve names
    /// themselves (HTTPDNS): decrypted when the server name its TLS asks
    /// for is listed.
    fn decrypts_by_name(&self, dest: &SocksAddr) -> bool {
        self.authority.is_some()
            && matches!(dest, SocksAddr::Ip(_))
            && self.hosts.has_port(dest.port())
    }

    fn decrypts(&self, dest: &SocksAddr) -> bool {
        self.authority.is_some() && self.listed(dest)
    }

    fn reads_plain(&self, dest: &SocksAddr) -> bool {
        self.rewrites && (dest.port() == 80 || self.forced_plain(dest))
    }

    /// force-http-engine-hosts: read as HTTP whatever the requests are.
    fn forced_plain(&self, dest: &SocksAddr) -> bool {
        self.plain_hosts.matches(&dest.host(), dest.port())
    }

    /// Whether this UDP session is refused, so the client tries TCP, where
    /// it can be decrypted: QUIC to a listed host, or to an address (an app
    /// that resolves names itself), whose server name QUIC does not show.
    pub fn blocks_quic(&self, sess: &Session) -> bool {
        self.quic_block
            && sess.network == Network::Udp
            && sess.destination.port() == 443
            && (self.decrypts(&sess.destination)
                || self.decrypts_by_name(&sess.destination))
    }

    fn listed(&self, dest: &SocksAddr) -> bool {
        match dest {
            SocksAddr::Domain(host, port) => self.hosts.matches(host, *port),
            SocksAddr::Ip(addr) => {
                self.hosts.matches(&addr.ip().to_string(), addr.port())
            }
        }
    }

    /// Serves a connection `handles` took: `lhs` the client's, `rhs` the
    /// outbound to the server. TLS to a listed host is decrypted, HTTP read;
    /// anything else comes back, to be relayed as it is.
    pub async fn serve<R>(
        self: Arc<Self>,
        sess: &Session,
        mut lhs: Box<dyn ProxyStream>,
        rhs: R,
    ) -> Option<(Box<dyn ProxyStream>, R)>
    where
        R: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        let (mut prefix, kind) = sniff(&mut lhs, deadline).await;
        let host = match sess.destination.port() {
            80 => sess.destination.host(),
            port => format!("{}:{port}", sess.destination.host()),
        };
        // Port 80: only when a rewrite takes the first request.
        let plain = kind == Kind::Http
            && self.reads_plain(&sess.destination)
            && (self.forced_plain(&sess.destination) || {
                read_head(&mut lhs, &mut prefix, deadline).await;
                first_url(&prefix, &host)
                    .is_some_and(|url| self.processor.wants(&url))
            });
        let decrypt = kind == Kind::Tls
            && (self.decrypts(&sess.destination)
                || self.decrypts_by_name(&sess.destination) && {
                    read_record(&mut lhs, &mut prefix, deadline).await;
                    server_name(&prefix).is_some_and(|name| {
                        self.hosts.matches(&name, sess.destination.port())
                    })
                });
        let lhs = Rewind {
            prefix: prefix.into(),
            inner: lhs,
        };
        let result = match kind {
            Kind::Tls if decrypt => self.serve_tls(sess, lhs, rhs).await,
            Kind::Http if plain => {
                let site = Arc::new(Site {
                    mitm: self,
                    scheme: "http",
                    host,
                });
                debug!("HTTP {}", site.host);
                serve_h1(site, lhs, rhs).await
            }
            _ => return Some((Box::new(lhs), rhs)),
        };
        if let Err(e) = result
            && !is_dropped(&e)
        {
            warn!("MITM {}: {}", sess, e);
        }
        None
    }

    /// Decrypts the connection: `lhs` the client's, `rhs` the outbound to
    /// the server.
    async fn serve_tls<L, R>(
        self: Arc<Self>,
        sess: &Session,
        lhs: L,
        rhs: R,
    ) -> io::Result<()>
    where
        L: AsyncRead + AsyncWrite + Unpin + Send + 'static,
        R: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let start = LazyConfigAcceptor::new(Acceptor::default(), lhs).await?;
        let hello = start.client_hello();
        let host = hello
            .server_name()
            .map(str::to_owned)
            .unwrap_or_else(|| sess.destination.host());
        let offered: Vec<Vec<u8>> = hello
            .alpn()
            .map(|it| it.map(<[u8]>::to_vec).collect())
            .unwrap_or_default();
        let h2 = self.h2 && offered.iter().any(|p| p == b"h2");
        let h1 = offered.is_empty() || offered.iter().any(|p| p == b"http/1.1");
        let upstream_config = match (h2, h1) {
            (true, true) => self.upstream_h2_h1.clone(),
            (true, false) => self.upstream_h2.clone(),
            (false, true) => self.upstream_h1.clone(),
            (false, false) => {
                return Err(io::Error::other(format!(
                    "{host}: TLS without HTTP ({offered:?}); not decrypted"
                )));
            }
        };
        let name = ServerName::try_from(host.clone())
            .map_err(|e| io::Error::other(format!("{host}: {e}")))?;
        let upstream = TlsConnector::from(upstream_config)
            .connect(name, rhs)
            .await
            .map_err(|e| io::Error::other(format!("{host}: server TLS: {e}")))?;
        let upstream_h2 = upstream.get_ref().1.alpn_protocol() == Some(b"h2");

        let authority = self
            .authority
            .as_ref()
            .ok_or_else(|| io::Error::other("no CA"))?;
        let certified = authority.certify(&host).map_err(io::Error::other)?;
        let mut server = ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(Fixed(certified)));
        server.alpn_protocols = if upstream_h2 {
            vec![b"h2".to_vec()]
        } else if offered.is_empty() {
            vec![]
        } else {
            vec![b"http/1.1".to_vec()]
        };
        let client = start.into_stream(Arc::new(server)).await.map_err(|e| {
            io::Error::other(format!(
                "{host}: the client refused the certificate ({e}); is the CA \
                 trusted, or does the app pin its certificates?"
            ))
        })?;
        debug!(
            "MITM {host} ({})",
            if upstream_h2 { "h2" } else { "http/1.1" }
        );

        let site = Arc::new(Site {
            mitm: self.clone(),
            scheme: "https",
            host,
        });
        if !upstream_h2 {
            return serve_h1(site, client, upstream).await;
        }
        let (sender, conn) = hyper::client::conn::http2::handshake(
            TokioExecutor::new(),
            TokioIo::new(upstream),
        )
        .await
        .map_err(io::Error::other)?;
        tokio::spawn(conn);
        let upstream = Upstream::H2(sender);
        let service = service_fn(move |req| {
            let site = site.clone();
            let upstream = upstream.clone();
            async move { site.handle(req, upstream).await }
        });
        hyper::server::conn::http2::Builder::new(TokioExecutor::new())
            .serve_connection(TokioIo::new(client), service)
            .await
            .map_err(io::Error::other)
    }
}

/// HTTP/1.1 between `client` and `server`, request by request.
async fn serve_h1<C, S>(site: Arc<Site>, client: C, server: S) -> io::Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(server))
        .await
        .map_err(io::Error::other)?;
    tokio::spawn(async move {
        let _ = conn.with_upgrades().await;
    });
    let upstream = Upstream::H1(Arc::new(tokio::sync::Mutex::new(sender)));
    let service = service_fn(move |req| {
        let site = site.clone();
        let upstream = upstream.clone();
        async move { site.handle(req, upstream).await }
    });
    hyper::server::conn::http1::Builder::new()
        .serve_connection(TokioIo::new(client), service)
        .with_upgrades()
        .await
        .map_err(io::Error::other)
}

/// A request left unanswered: a rule dropped it (`RequestOutcome::Drop`),
/// or the server's connection broke.
#[derive(Debug)]
struct Dropped;

impl std::fmt::Display for Dropped {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("dropped")
    }
}

impl std::error::Error for Dropped {}

fn is_dropped(e: &io::Error) -> bool {
    let mut source: Option<&(dyn std::error::Error + 'static)> =
        e.get_ref().map(|e| e as _);
    while let Some(s) = source {
        if s.is::<Dropped>() {
            return true;
        }
        source = s.source();
    }
    false
}

/// What the client sends first.
#[derive(Debug, PartialEq)]
enum Kind {
    Tls,
    Http,
    Other,
}

const METHODS: &[&[u8]] = &[
    b"GET ",
    b"POST ",
    b"HEAD ",
    b"PUT ",
    b"DELETE ",
    b"OPTIONS ",
    b"PATCH ",
    b"TRACE ",
    b"CONNECT ",
];

/// Reads the client's first bytes: a TLS handshake, an HTTP request, or
/// something else (also when the client waits for the server to speak).
async fn sniff<S: AsyncRead + Unpin>(
    s: &mut S,
    deadline: tokio::time::Instant,
) -> (Vec<u8>, Kind) {
    let mut buf = Vec::new();
    loop {
        let kind = if buf.first() == Some(&0x16) {
            Some(Kind::Tls)
        } else if METHODS.iter().any(|m| buf.starts_with(m)) {
            Some(Kind::Http)
        } else if !buf.is_empty() && !METHODS.iter().any(|m| m.starts_with(&buf)) {
            Some(Kind::Other)
        } else {
            None
        };
        if let Some(kind) = kind {
            return (buf, kind);
        }
        let mut chunk = [0u8; 2048];
        match tokio::time::timeout_at(deadline, s.read(&mut chunk)).await {
            Ok(Ok(n)) if n > 0 => buf.extend_from_slice(&chunk[..n]),
            _ => return (buf, Kind::Other),
        }
    }
}

/// Reads on until `buf` holds a whole TLS record (the ClientHello).
async fn read_record<S: AsyncRead + Unpin>(
    s: &mut S,
    buf: &mut Vec<u8>,
    deadline: tokio::time::Instant,
) {
    loop {
        let need = match buf.get(3..5) {
            Some(len) => 5 + u16::from_be_bytes([len[0], len[1]]) as usize,
            None => 5,
        };
        if buf.len() >= need {
            return;
        }
        let mut chunk = [0u8; 2048];
        match tokio::time::timeout_at(deadline, s.read(&mut chunk)).await {
            Ok(Ok(n)) if n > 0 => buf.extend_from_slice(&chunk[..n]),
            _ => return,
        }
    }
}

/// The server name a TLS ClientHello asks for, from its first record.
fn server_name(buf: &[u8]) -> Option<String> {
    struct Reader<'a>(&'a [u8]);
    impl<'a> Reader<'a> {
        fn take(&mut self, n: usize) -> Option<&'a [u8]> {
            let (head, rest) = (self.0.get(..n)?, self.0.get(n..)?);
            self.0 = rest;
            Some(head)
        }
        fn int(&mut self, n: usize) -> Option<usize> {
            Some(self.take(n)?.iter().fold(0, |v, b| v << 8 | *b as usize))
        }
        fn vec(&mut self, len_bytes: usize) -> Option<Reader<'a>> {
            let n = self.int(len_bytes)?;
            self.take(n).map(Reader)
        }
    }
    let mut record = Reader(buf);
    if record.int(1)? != 0x16 {
        return None;
    }
    record.take(2)?;
    let mut handshake = record.vec(2)?;
    if handshake.int(1)? != 1 {
        return None;
    }
    let mut hello = handshake.vec(3)?;
    hello.take(2 + 32)?; // version, random
    hello.vec(1)?; // session id
    hello.vec(2)?; // cipher suites
    hello.vec(1)?; // compression methods
    let mut extensions = hello.vec(2)?;
    while let (Some(kind), Some(mut data)) = (extensions.int(2), extensions.vec(2)) {
        if kind != 0 {
            continue;
        }
        let mut names = data.vec(2)?;
        while let (Some(name_type), Some(name)) = (names.int(1), names.vec(2)) {
            if name_type == 0 {
                return std::str::from_utf8(name.0)
                    .ok()
                    .map(str::to_ascii_lowercase);
            }
        }
        return None;
    }
    None
}

/// Reads on until `buf` holds a request's head (up to 16 KiB).
async fn read_head<S: AsyncRead + Unpin>(
    s: &mut S,
    buf: &mut Vec<u8>,
    deadline: tokio::time::Instant,
) {
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") && buf.len() < 16 * 1024 {
        let mut chunk = [0u8; 2048];
        match tokio::time::timeout_at(deadline, s.read(&mut chunk)).await {
            Ok(Ok(n)) if n > 0 => buf.extend_from_slice(&chunk[..n]),
            _ => return,
        }
    }
}

/// The URL of the request whose head starts `buf`, as `Site::url` makes
/// it.
fn first_url(buf: &[u8], fallback_host: &str) -> Option<String> {
    let end = buf.windows(4).position(|w| w == b"\r\n\r\n")?;
    let head = std::str::from_utf8(&buf[..end]).ok()?;
    let mut lines = head.split("\r\n");
    let target = lines.next()?.split(' ').nth(1)?;
    if target.starts_with("http://") {
        return Some(target.to_owned());
    }
    let host = lines
        .filter_map(|l| l.split_once(':'))
        .find(|(name, _)| name.trim().eq_ignore_ascii_case("host"))
        .map_or(fallback_host, |(_, value)| value.trim());
    Some(format!("http://{}{target}", host.to_ascii_lowercase()))
}

/// The footprint above which new connections are relayed as they are
/// (bytes; 0: none). On iOS, where the packet tunnel may use about 50 MiB,
/// 36 MiB by default.
static MEMORY_CEILING: AtomicU64 =
    AtomicU64::new(if cfg!(target_os = "ios") { 36 << 20 } else { 0 });
static OVER_CEILING: AtomicBool = AtomicBool::new(false);

pub fn set_memory_ceiling(bytes: u64) {
    MEMORY_CEILING.store(bytes, Ordering::Relaxed);
}

/// Whether the process is above the ceiling; says so when that changes.
fn over_memory_ceiling() -> bool {
    let ceiling = MEMORY_CEILING.load(Ordering::Relaxed);
    if ceiling == 0 {
        return false;
    }
    let Some(footprint) = memory_footprint() else {
        return false;
    };
    let over = footprint > ceiling;
    if OVER_CEILING.swap(over, Ordering::Relaxed) != over {
        let mib = |b: u64| b >> 20;
        if over {
            warn!(
                "memory {} MiB, above {} MiB: new connections are relayed \
                 without decryption or rewrites",
                mib(footprint),
                mib(ceiling)
            );
        } else {
            info!("memory {} MiB: decrypting again", mib(footprint));
        }
    }
    over
}

/// A stream with the bytes already read from it put back in front.
struct Rewind<S> {
    prefix: Bytes,
    inner: S,
}

impl<S: AsyncRead + Unpin> AsyncRead for Rewind<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.prefix.is_empty() {
            let n = this.prefix.len().min(buf.remaining());
            buf.put_slice(&this.prefix.split_to(n));
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Rewind<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

impl<S: AsyncRead + AsyncWrite + Send + Unpin> ProxyStream for Rewind<S> {}

/// One host's certificate, whatever the client asks.
#[derive(Debug)]
struct Fixed(Arc<CertifiedKey>);

impl ResolvesServerCert for Fixed {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
}

/// The server side of a decrypted connection.
#[derive(Clone)]
enum Upstream {
    H1(Arc<tokio::sync::Mutex<hyper::client::conn::http1::SendRequest<Body>>>),
    H2(hyper::client::conn::http2::SendRequest<Body>),
}

impl Upstream {
    async fn send(&self, req: Request<Body>) -> hyper::Result<Response<Incoming>> {
        match self {
            Upstream::H1(sender) => {
                // One request at a time on an HTTP/1.1 connection.
                let mut sender = sender.lock().await;
                sender.ready().await?;
                sender.send_request(req).await
            }
            Upstream::H2(sender) => {
                let mut sender = sender.clone();
                sender.ready().await?;
                sender.send_request(req).await
            }
        }
    }
}

/// A decrypted or plain HTTP connection's requests.
struct Site {
    mitm: Arc<Mitm>,
    /// "https" or "http".
    scheme: &'static str,
    host: String,
}

impl Site {
    async fn handle(
        &self,
        mut req: Request<Incoming>,
        upstream: Upstream,
    ) -> Result<Response<Body>, Dropped> {
        let url = self.url(&req);
        let client_upgrade = is_upgrade(&req).then(|| hyper::upgrade::on(&mut req));
        let req = req.map(BodyExt::boxed);
        let req = match self.mitm.processor.request(&url, req).await {
            RequestOutcome::Forward(req) => req,
            RequestOutcome::Respond(resp) => return Ok(resp),
            RequestOutcome::Drop => return Err(Dropped),
        };
        let method = req.method().clone();
        let mut resp = match upstream.send(req).await {
            Ok(resp) => resp,
            Err(e) => {
                // The server's connection broke: the client's closes too
                // (HTTP/2: the stream), and the client tries again.
                debug!("MITM {}: server: {e}", self.host);
                return Err(Dropped);
            }
        };
        // WebSocket and other upgrades: the two sides joined as they are.
        if resp.status() == StatusCode::SWITCHING_PROTOCOLS
            && let Some(client_upgrade) = client_upgrade
        {
            let server_upgrade = hyper::upgrade::on(&mut resp);
            tokio::spawn(async move {
                if let (Ok(client), Ok(server)) =
                    (client_upgrade.await, server_upgrade.await)
                {
                    let mut client = TokioIo::new(client);
                    let mut server = TokioIo::new(server);
                    let _ = tokio::io::copy_bidirectional(&mut client, &mut server)
                        .await;
                }
            });
        }
        let resp = resp.map(BodyExt::boxed);
        Ok(self.mitm.processor.response(&url, &method, resp).await)
    }

    /// The full URL: HTTP/2 requests carry it, HTTP/1.1 ones the path and
    /// a Host header.
    fn url<B>(&self, req: &Request<B>) -> String {
        let uri = req.uri();
        let host = match uri.authority() {
            Some(authority) => authority.as_str(),
            None => req
                .headers()
                .get(header::HOST)
                .and_then(|h| h.to_str().ok())
                .unwrap_or(&self.host),
        };
        let scheme = uri.scheme_str().unwrap_or(self.scheme);
        let path = uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
        // The host in lower case, as browsers write URLs.
        format!("{scheme}://{}{path}", host.to_ascii_lowercase())
    }
}

fn is_upgrade<B>(req: &Request<B>) -> bool {
    req.headers().contains_key(header::UPGRADE)
}

/// Surge's MITM host list: `*` and `?` wildcards, a leading `-` excludes,
/// in order; a bare name is the default port (443 for decryption),
/// `host:port` another port, `host:0` every port.
#[derive(Debug, Default)]
struct HostList(Vec<HostEntry>);

#[derive(Debug)]
struct HostEntry {
    pattern: String,
    port: u16,
    exclude: bool,
}

impl HostList {
    fn new(entries: &[String], default_port: u16) -> Self {
        Self(
            entries
                .iter()
                .filter_map(|e| {
                    let e = e.trim();
                    let (exclude, e) = match e.strip_prefix('-') {
                        Some(rest) => (true, rest),
                        None => (false, e),
                    };
                    let (pattern, port) = match e.rsplit_once(':') {
                        Some((host, port))
                            if port.chars().all(|c| c.is_ascii_digit())
                                && !port.is_empty() =>
                        {
                            (host, port.parse().ok()?)
                        }
                        _ => (e, default_port),
                    };
                    (!pattern.is_empty()).then(|| HostEntry {
                        pattern: pattern.to_ascii_lowercase(),
                        port,
                        exclude,
                    })
                })
                .collect(),
        )
    }

    fn is_empty(&self) -> bool {
        self.0.iter().all(|e| e.exclude)
    }

    /// Whether some host is listed on this port.
    fn has_port(&self, port: u16) -> bool {
        self.0
            .iter()
            .any(|e| !e.exclude && (e.port == 0 || e.port == port))
    }

    fn matches(&self, host: &str, port: u16) -> bool {
        let host = host.to_ascii_lowercase();
        self.0
            .iter()
            .find(|e| (e.port == 0 || e.port == port) && wildcard(&e.pattern, &host))
            .is_some_and(|e| !e.exclude)
    }
}

/// `*` any run, `?` one character.
fn wildcard(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti, mut star, mut mark) = (0, 0, None, 0);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_list() {
        let list = HostList::new(
            &[
                "-*.apple.com".into(),
                "*.example.com".into(),
                "api.test:8443".into(),
                "all.test:0".into(),
            ],
            443,
        );
        assert!(list.matches("www.example.com", 443));
        assert!(!list.matches("www.example.com", 8443));
        assert!(!list.matches("example.com", 443));
        assert!(!list.matches("itunes.apple.com", 443));
        assert!(list.matches("api.test", 8443) && !list.matches("api.test", 443));
        assert!(list.matches("all.test", 80) && list.matches("all.test", 443));
        assert!(wildcard("a?c*", "abcdef") && !wildcard("a?c", "ac"));
        assert!(HostList::new(&["-x.test".into()], 443).is_empty());
    }

    #[test]
    fn server_name_of_a_client_hello() {
        crate::setup_default_crypto_provider();
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        let mut client = rustls::ClientConnection::new(
            Arc::new(config),
            ServerName::try_from("API.Example.com").unwrap(),
        )
        .unwrap();
        let mut hello = Vec::new();
        client.write_tls(&mut hello).unwrap();
        assert_eq!(server_name(&hello).as_deref(), Some("api.example.com"));
        assert_eq!(server_name(&hello[..hello.len() - 1]), None);
        assert_eq!(server_name(b"GET / HTTP/1.1\r\n\r\n"), None);
        let list = HostList::new(&["*.example.com".into(), "-x.test:0".into()], 443);
        assert!(list.has_port(443) && !list.has_port(8443));
    }

    #[test]
    fn quic_refused_to_listed_hosts_and_addresses() {
        crate::setup_default_crypto_provider();
        let (cert, key) = generate_ca("Test CA").unwrap();
        let config = MitmConfig {
            hostname: vec!["*.example.com".into()],
            ca_cert: Some(cert),
            ca_key: Some(key),
            auto_quic_block: true,
            ..Default::default()
        };
        let mitm = Mitm::new(Some(&config), None).unwrap().unwrap();
        let udp = |destination: SocksAddr| Session {
            network: Network::Udp,
            destination,
            ..Default::default()
        };
        assert!(
            mitm.blocks_quic(&udp(SocksAddr::Domain("a.example.com".into(), 443)))
        );
        assert!(
            mitm.blocks_quic(&udp("203.0.113.1:443"
                .parse::<std::net::SocketAddr>()
                .unwrap()
                .into()))
        );
        assert!(
            !mitm.blocks_quic(&udp(SocksAddr::Domain("other.test".into(), 443)))
        );
        assert!(
            !mitm.blocks_quic(&udp(SocksAddr::Domain("a.example.com".into(), 8443)))
        );
    }

    #[test]
    fn first_request_url_and_footprint() {
        let head = b"GET /a?b HTTP/1.1\r\nHOST: Ex.Test\r\nX: y\r\n\r\nbody";
        assert_eq!(
            first_url(head, "1.2.3.4").as_deref(),
            Some("http://ex.test/a?b")
        );
        let no_host = b"GET / HTTP/1.0\r\n\r\n";
        assert_eq!(
            first_url(no_host, "1.2.3.4").as_deref(),
            Some("http://1.2.3.4/")
        );
        let absolute = b"GET http://a.test/x HTTP/1.1\r\n\r\n";
        assert_eq!(first_url(absolute, "b").as_deref(), Some("http://a.test/x"));
        assert_eq!(first_url(b"GET / HTTP/1.1\r\nHost: a", "b"), None);
        #[cfg(target_os = "macos")]
        {
            let bytes = memory_footprint().unwrap();
            assert!(bytes > 1 << 20 && bytes < 1 << 34, "{bytes}");
            set_memory_ceiling(1 << 20);
            assert!(over_memory_ceiling());
            set_memory_ceiling(0);
            assert!(!over_memory_ceiling());
        }
    }

    #[tokio::test]
    async fn port_80_is_read_only_for_a_rewrite() {
        use tokio::io::AsyncWriteExt;

        use crate::config::def::UrlRewrite;
        let rewrite = RewriteConfig {
            url: vec![UrlRewrite {
                pattern: r"^http://a\.test/taken".into(),
                kind: "reject-dict".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let mitm = Mitm::new(None, Some(&rewrite)).unwrap().unwrap();
        let sess = Session {
            network: Network::Tcp,
            destination: SocksAddr::Domain("a.test".into(), 80),
            ..Default::default()
        };
        assert!(mitm.handles(&sess));
        for (path, answered) in [("/taken", true), ("/other", false)] {
            let (client, engine_side) = tokio::io::duplex(4096);
            let (_server, upstream) = tokio::io::duplex(4096);
            let request =
                format!("GET {path} HTTP/1.1\r\nHost: A.test\r\nX-Case: 1\r\n\r\n");
            let mut client = client;
            client.write_all(request.as_bytes()).await.unwrap();
            let lhs: Box<dyn ProxyStream> = Box::new(Rewind {
                prefix: Bytes::new(),
                inner: engine_side,
            });
            let serving = tokio::spawn({
                let (mitm, sess) = (mitm.clone(), sess.clone());
                async move { mitm.serve(&sess, lhs, upstream).await.map(|(l, _)| l) }
            });
            if answered {
                // The rewrite's answer, and the connection served here.
                let mut reply = vec![0u8; 512];
                let n = tokio::time::timeout(
                    Duration::from_secs(3),
                    client.read(&mut reply),
                )
                .await
                .unwrap()
                .unwrap();
                let reply = String::from_utf8_lossy(&reply[..n]).into_owned();
                assert!(
                    reply.starts_with("HTTP/1.1 200") && reply.ends_with("{}"),
                    "{reply}"
                );
                drop(client);
                assert!(serving.await.unwrap().is_none());
            } else {
                // Handed back for relaying, with the request as it came.
                let mut lhs = serving.await.unwrap().expect("relayed");
                let mut back = vec![0u8; request.len()];
                lhs.read_exact(&mut back).await.unwrap();
                assert_eq!(back, request.as_bytes());
            }
        }
    }

    #[tokio::test]
    async fn sniffed_bytes_are_put_back() {
        use tokio::io::AsyncWriteExt;
        let cases: [(&[u8], Kind); 5] = [
            (b"GET / HTTP/1.1\r\n\r\n", Kind::Http),
            (b"\x16\x03\x01\x00\x05hello", Kind::Tls),
            (b"SSH-2.0-x\r\n", Kind::Other),
            (b"GE", Kind::Other),
            (b"", Kind::Other),
        ];
        for (input, kind) in cases {
            let (mut a, mut b) = tokio::io::duplex(64);
            b.write_all(input).await.unwrap();
            drop(b);
            let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
            let (prefix, k) = sniff(&mut a, deadline).await;
            assert_eq!(k, kind, "{input:?}");
            let mut out = Vec::new();
            Rewind {
                prefix: prefix.into(),
                inner: a,
            }
            .read_to_end(&mut out)
            .await
            .unwrap();
            assert_eq!(out, input);
        }
    }
}
