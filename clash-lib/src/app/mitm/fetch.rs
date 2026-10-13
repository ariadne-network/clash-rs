//! HTTP requests of the engine's own (our fork), as the application's
//! scripts make them: they go through the dispatcher like any connection,
//! so the rules choose their policy and they show among the connections.
//! They are never decrypted (`Type::Ignore`).

use std::{
    io,
    sync::{Arc, RwLock, Weak},
    time::Duration,
};

use http::{Request, Response, Uri, header};
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use rustls::{ClientConfig, pki_types::ServerName};
use tokio_rustls::TlsConnector;

use super::Body;
use crate::{
    app::dispatcher::Dispatcher,
    common::tls::GLOBAL_ROOT_STORE,
    session::{Network, Session, SocksAddr, Type},
};

static DISPATCHER: RwLock<Option<Weak<Dispatcher>>> = RwLock::new(None);
static RUNTIME: RwLock<Option<tokio::runtime::Handle>> = RwLock::new(None);

/// The running engine's dispatcher, and its runtime (called on it).
pub(crate) fn set_dispatcher(dispatcher: &Arc<Dispatcher>) {
    *DISPATCHER.write().unwrap() = Some(Arc::downgrade(dispatcher));
    *RUNTIME.write().unwrap() = tokio::runtime::Handle::try_current().ok();
}

/// The runtime the running engine is on, for work that `fetch`es from
/// outside it (scripts run on a thread of their own).
pub fn engine_runtime() -> Option<tokio::runtime::Handle> {
    RUNTIME.read().unwrap().clone()
}

/// Sends `req` (an absolute http or https URL) through the engine, over
/// HTTP/1.1, and gives the response once its head arrived.
pub async fn fetch(
    mut req: Request<Body>,
    timeout: Duration,
) -> io::Result<Response<Incoming>> {
    let dispatcher = DISPATCHER
        .read()
        .unwrap()
        .as_ref()
        .and_then(Weak::upgrade)
        .ok_or_else(|| io::Error::other("the engine is not running"))?;
    let uri = req.uri().clone();
    let https = match uri.scheme_str() {
        Some("https") => true,
        Some("http") => false,
        _ => return Err(io::Error::other(format!("not an http(s) URL: {uri}"))),
    };
    let host = uri
        .host()
        .ok_or_else(|| io::Error::other("no host"))?
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_owned();
    let port = uri.port_u16().unwrap_or(if https { 443 } else { 80 });
    let destination = match host.parse::<std::net::IpAddr>() {
        Ok(ip) => SocksAddr::Ip((ip, port).into()),
        Err(_) => SocksAddr::Domain(host.clone(), port),
    };
    let sess = Session {
        network: Network::Tcp,
        typ: Type::Ignore,
        destination,
        ..Default::default()
    };
    let (client, engine_side) = tokio::io::duplex(64 * 1024);
    tokio::spawn(async move {
        dispatcher
            .dispatch_stream(sess, Box::new(engine_side))
            .await;
    });

    // Origin form, with the Host header.
    if !req.headers().contains_key(header::HOST)
        && let Ok(value) =
            uri.authority().map(|a| a.as_str()).unwrap_or(&host).parse()
    {
        req.headers_mut().insert(header::HOST, value);
    }
    *req.uri_mut() = uri
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or("/")
        .parse::<Uri>()
        .map_err(io::Error::other)?;

    let exchange = async {
        if https {
            let mut config = ClientConfig::builder()
                .with_root_certificates(GLOBAL_ROOT_STORE.clone())
                .with_no_client_auth();
            config.alpn_protocols = vec![b"http/1.1".to_vec()];
            let name =
                ServerName::try_from(host.clone()).map_err(io::Error::other)?;
            let tls = TlsConnector::from(Arc::new(config))
                .connect(name, client)
                .await?;
            send(TokioIo::new(tls), req).await
        } else {
            send(TokioIo::new(client), req).await
        }
    };
    tokio::time::timeout(timeout, exchange)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "timed out"))?
}

async fn send<T>(io: T, req: Request<Body>) -> io::Result<Response<Incoming>>
where
    T: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .map_err(io::Error::other)?;
    tokio::spawn(conn);
    sender.send_request(req).await.map_err(io::Error::other)
}
