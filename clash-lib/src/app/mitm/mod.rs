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

mod ca;

use std::{io, sync::Arc};

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
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::{LazyConfigAcceptor, TlsConnector};
use tracing::{debug, warn};

pub use ca::{Authority, generate_ca};

use crate::{
    common::tls::{DefaultTlsVerifier, GLOBAL_ROOT_STORE},
    config::def::MitmConfig,
    session::{Network, Session, SocksAddr},
};

pub type Body = BoxBody<Bytes, hyper::Error>;

/// What happens to a request: it goes on (maybe changed), or gets an
/// answer here.
pub enum RequestOutcome {
    Forward(Request<Body>),
    Respond(Response<Body>),
}

/// Rewrites and scripts on decrypted HTTP. `url` is the request's full URL.
#[async_trait]
pub trait HttpProcessor: Send + Sync {
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
    Full::new(bytes.into()).map_err(|never| match never {}).boxed()
}

pub struct Mitm {
    hosts: HostList,
    authority: Authority,
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
    /// None without hosts or without a CA.
    pub fn new(
        config: &MitmConfig,
        processor: Arc<dyn HttpProcessor>,
    ) -> Result<Option<Arc<Self>>, String> {
        let hosts = HostList::new(&config.hostname);
        let (Some(cert), Some(key)) = (&config.ca_cert, &config.ca_key) else {
            return Ok(None);
        };
        if hosts.is_empty() {
            return Ok(None);
        }
        let authority = Authority::new(cert, key)?;
        let upstream = |alpn: &[&[u8]]| {
            let mut c = ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(DefaultTlsVerifier::new(
                    None,
                    config.skip_server_cert_verify,
                )))
                .with_no_client_auth();
            c.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
            Arc::new(c)
        };
        let _ = &GLOBAL_ROOT_STORE; // the verifier's roots
        Ok(Some(Arc::new(Self {
            hosts,
            authority,
            h2: config.h2,
            quic_block: config.auto_quic_block,
            processor,
            upstream_h2_h1: upstream(&[b"h2", b"http/1.1"]),
            upstream_h2: upstream(&[b"h2"]),
            upstream_h1: upstream(&[b"http/1.1"]),
        })))
    }

    /// Whether this TCP connection is decrypted.
    pub fn decrypts(&self, sess: &Session) -> bool {
        sess.network == Network::Tcp && self.listed(&sess.destination)
    }

    /// Whether this UDP session (QUIC to a listed host) is refused, so the
    /// client tries TCP, which is decrypted.
    pub fn blocks_quic(&self, sess: &Session) -> bool {
        self.quic_block
            && sess.network == Network::Udp
            && sess.destination.port() == 443
            && self.listed(&sess.destination)
    }

    fn listed(&self, dest: &SocksAddr) -> bool {
        match dest {
            SocksAddr::Domain(host, port) => self.hosts.matches(host, *port),
            SocksAddr::Ip(addr) => {
                self.hosts.matches(&addr.ip().to_string(), addr.port())
            }
        }
    }

    /// Decrypts the connection: `lhs` the client's, `rhs` the outbound to
    /// the server.
    pub async fn serve<L, R>(
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

        let certified = self.authority.certify(&host).map_err(io::Error::other)?;
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
        debug!("MITM {host} ({})", if upstream_h2 { "h2" } else { "http/1.1" });

        let site = Arc::new(Site {
            mitm: self.clone(),
            host,
        });
        if upstream_h2 {
            let (sender, conn) =
                hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(upstream))
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
        } else {
            let (sender, conn) =
                hyper::client::conn::http1::handshake(TokioIo::new(upstream))
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
    }
}

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

/// A decrypted connection's requests.
struct Site {
    mitm: Arc<Mitm>,
    host: String,
}

impl Site {
    async fn handle(
        &self,
        mut req: Request<Incoming>,
        upstream: Upstream,
    ) -> Result<Response<Body>, hyper::Error> {
        let url = self.url(&req);
        let client_upgrade = is_upgrade(&req).then(|| hyper::upgrade::on(&mut req));
        let req = req.map(BodyExt::boxed);
        let req = match self.mitm.processor.request(&url, req).await {
            RequestOutcome::Forward(req) => req,
            RequestOutcome::Respond(resp) => return Ok(resp),
        };
        let method = req.method().clone();
        let mut resp = match upstream.send(req).await {
            Ok(resp) => resp,
            Err(e) => {
                warn!("MITM {url}: {e}");
                let mut resp = Response::new(full_body(format!("Bad gateway: {e}")));
                *resp.status_mut() = StatusCode::BAD_GATEWAY;
                return Ok(resp);
            }
        };
        // WebSocket and other upgrades: the two sides joined as they are.
        if resp.status() == StatusCode::SWITCHING_PROTOCOLS
            && let Some(client_upgrade) = client_upgrade
        {
            let server_upgrade = hyper::upgrade::on(&mut resp);
            tokio::spawn(async move {
                if let (Ok(client), Ok(server)) = (client_upgrade.await, server_upgrade.await) {
                    let mut client = TokioIo::new(client);
                    let mut server = TokioIo::new(server);
                    let _ = tokio::io::copy_bidirectional(&mut client, &mut server).await;
                }
            });
        }
        let resp = resp.map(BodyExt::boxed);
        Ok(self.mitm.processor.response(&url, &method, resp).await)
    }

    /// The full URL: HTTP/2 requests carry it, HTTP/1.1 ones the path and
    /// a Host header.
    fn url<B>(&self, req: &Request<B>) -> String {
        if req.uri().scheme().is_some() {
            return req.uri().to_string();
        }
        let host = req
            .headers()
            .get(header::HOST)
            .and_then(|h| h.to_str().ok())
            .unwrap_or(&self.host);
        let path = req.uri().path_and_query().map(|p| p.as_str()).unwrap_or("/");
        format!("https://{host}{path}")
    }
}

fn is_upgrade<B>(req: &Request<B>) -> bool {
    req.headers().contains_key(header::UPGRADE)
}

/// Surge's MITM host list: `*` and `?` wildcards, a leading `-` excludes,
/// in order; a bare name is port 443, `host:port` another port, `host:0`
/// every port.
#[derive(Debug, Default)]
struct HostList(Vec<HostEntry>);

#[derive(Debug)]
struct HostEntry {
    pattern: String,
    port: u16,
    exclude: bool,
}

impl HostList {
    fn new(entries: &[String]) -> Self {
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
                        Some((host, port)) if port.chars().all(|c| c.is_ascii_digit()) && !port.is_empty() => {
                            (host, port.parse().ok()?)
                        }
                        _ => (e, 443),
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
        let list = HostList::new(&[
            "-*.apple.com".into(),
            "*.example.com".into(),
            "api.test:8443".into(),
            "all.test:0".into(),
        ]);
        assert!(list.matches("www.example.com", 443));
        assert!(!list.matches("www.example.com", 8443));
        assert!(!list.matches("example.com", 443));
        assert!(!list.matches("itunes.apple.com", 443));
        assert!(list.matches("api.test", 8443) && !list.matches("api.test", 443));
        assert!(list.matches("all.test", 80) && list.matches("all.test", 443));
        assert!(wildcard("a?c*", "abcdef") && !wildcard("a?c", "ac"));
        assert!(HostList::new(&["-x.test".into()]).is_empty());
    }
}
