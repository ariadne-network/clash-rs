//! An HTTP proxy as an outbound: CONNECT to the destination, then the
//! stream is the tunnel. Over TLS to the proxy when configured (an "HTTPS
//! proxy"). TCP only.

use crate::{
    app::{
        dispatcher::{
            BoxedInstrumentedDatagram, BoxedInstrumentedStream, InstrumentedStream,
            InstrumentedStreamWrapper,
        },
        dns::ThreadSafeDNSResolver,
    },
    common::errors::new_io_error,
    impl_default_connector,
    proxy::{
        AnyStream, ConnectorType, DialWithConnector, HandlerCommonOptions,
        OutboundHandler, OutboundType, PlainProxyAPIResponse,
        transport::TransportLayer,
        utils::{GLOBAL_DIRECT_CONNECTOR, RemoteConnector},
    },
    session::Session,
};
use async_trait::async_trait;
use base64::Engine;
use erased_serde::Serialize as ErasedSerialize;
use std::{collections::HashMap, fmt::Debug, sync::Arc};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::debug;

#[derive(Default)]
pub struct HandlerOptions {
    pub name: String,
    pub common_opts: HandlerCommonOptions,
    pub server: String,
    pub port: u16,
    pub user: Option<String>,
    pub password: Option<String>,
    pub tls_client: Option<TransportLayer>,
}

pub struct Handler {
    opts: HandlerOptions,
    connector: tokio::sync::RwLock<Option<Arc<dyn RemoteConnector>>>,
}

impl_default_connector!(Handler);

impl Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Http")
            .field("name", &self.opts.name)
            .finish()
    }
}

impl Handler {
    pub fn new(opts: HandlerOptions) -> Self {
        Self {
            opts,
            connector: tokio::sync::RwLock::new(None),
        }
    }

    async fn inner_connect_stream(
        &self,
        s: AnyStream,
        sess: &Session,
    ) -> std::io::Result<AnyStream> {
        let mut s = match self.opts.tls_client.as_ref() {
            Some(tls) => tls.wrap(s).await?,
            None => s,
        };
        let target = sess.destination.to_string();
        let mut request = format!(
            "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nProxy-Connection: Keep-Alive\r\n"
        );
        if let Some(user) = self.opts.user.as_ref() {
            let credentials =
                format!("{user}:{}", self.opts.password.as_deref().unwrap_or(""));
            let encoded =
                base64::engine::general_purpose::STANDARD.encode(credentials);
            request.push_str(&format!("Proxy-Authorization: Basic {encoded}\r\n"));
        }
        request.push_str("\r\n");
        s.write_all(request.as_bytes()).await?;
        s.flush().await?;
        read_connect_response(&mut s).await?;
        Ok(s)
    }
}

/// Reads the proxy's answer up to the blank line, a byte at a time: what
/// follows belongs to the tunnel. Anything but 2xx fails the connection.
async fn read_connect_response(s: &mut AnyStream) -> std::io::Result<()> {
    const LIMIT: usize = 8192;
    let mut head = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() >= LIMIT {
            return Err(new_io_error("HTTP proxy: response header too long"));
        }
        if s.read(&mut byte).await? == 0 {
            return Err(new_io_error(
                "HTTP proxy: connection closed during CONNECT",
            ));
        }
        head.push(byte[0]);
    }
    let status_line = String::from_utf8_lossy(&head);
    let status_line = status_line.lines().next().unwrap_or_default();
    let code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse::<u16>().ok());
    match code {
        Some(code) if (200..300).contains(&code) => Ok(()),
        Some(407) => Err(new_io_error("HTTP proxy: authentication required (407)")),
        _ => Err(new_io_error(format!(
            "HTTP proxy: CONNECT failed: {status_line}"
        ))),
    }
}

#[async_trait]
impl OutboundHandler for Handler {
    fn name(&self) -> &str {
        &self.opts.name
    }

    fn server_name(&self) -> Option<&str> {
        Some(&self.opts.server)
    }

    fn proto(&self) -> OutboundType {
        OutboundType::Http
    }

    async fn support_udp(&self) -> bool {
        false
    }

    async fn connect_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> std::io::Result<BoxedInstrumentedStream> {
        let dialer = self.connector.read().await;
        if let Some(dialer) = dialer.as_ref() {
            debug!("{:?} is connecting via {:?}", self, dialer);
        }
        self.connect_stream_with_connector(
            sess,
            resolver,
            dialer
                .as_ref()
                .unwrap_or(&GLOBAL_DIRECT_CONNECTOR.clone())
                .as_ref(),
        )
        .await
    }

    async fn connect_datagram(
        &self,
        _sess: &Session,
        _resolver: ThreadSafeDNSResolver,
    ) -> std::io::Result<BoxedInstrumentedDatagram> {
        Err(new_io_error("an HTTP proxy carries no UDP"))
    }

    async fn support_connector(&self) -> ConnectorType {
        ConnectorType::Tcp
    }

    async fn connect_stream_with_connector(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
        connector: &dyn RemoteConnector,
    ) -> std::io::Result<BoxedInstrumentedStream> {
        let s = connector
            .connect_stream(
                resolver,
                self.opts.server.as_str(),
                self.opts.port,
                sess.iface.as_ref(),
                #[cfg(target_os = "linux")]
                sess.so_mark,
            )
            .await?;
        let s = self.inner_connect_stream(s, sess).await?;
        let s = InstrumentedStreamWrapper::new(s);
        s.append_to_chain(self.name()).await;
        Ok(Box::new(s))
    }

    fn try_as_plain_handler(&self) -> Option<&dyn PlainProxyAPIResponse> {
        Some(self as _)
    }
}

#[async_trait]
impl PlainProxyAPIResponse for Handler {
    async fn as_map(&self) -> HashMap<String, Box<dyn ErasedSerialize + Send>> {
        let mut m = HashMap::new();
        m.insert("server".to_owned(), Box::new(self.opts.server.clone()) as _);
        m.insert("port".to_owned(), Box::new(self.opts.port) as _);
        if self.opts.tls_client.is_some() {
            m.insert("tls".to_owned(), Box::new(true) as _);
        }
        m
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    async fn answer(response: &'static [u8]) -> std::io::Result<()> {
        let (client, mut server) = duplex(1024);
        tokio::spawn(async move {
            let mut request = vec![0u8; 512];
            let _ = server.read(&mut request).await;
            let _ = server.write_all(response).await;
        });
        let mut stream: AnyStream = Box::new(client);
        stream.write_all(b"CONNECT x:1 HTTP/1.1\r\n\r\n").await?;
        read_connect_response(&mut stream).await
    }

    #[tokio::test]
    async fn connect_responses() {
        assert!(
            answer(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .await
                .is_ok()
        );
        assert!(
            answer(b"HTTP/1.0 200 OK\r\nProxy-Agent: x\r\n\r\n")
                .await
                .is_ok()
        );
        let denied = answer(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
            .await
            .unwrap_err();
        assert!(denied.to_string().contains("407"));
        assert!(answer(b"HTTP/1.1 403 Forbidden\r\n\r\n").await.is_err());
        assert!(answer(b"HTTP/1.1 200").await.is_err());
    }
}
