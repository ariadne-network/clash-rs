use std::{
    cmp,
    fmt::Debug,
    pin::Pin,
    task::{Poll, Waker},
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use futures::{Future, ready};
use http::{HeaderValue, Request};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_tungstenite::{
    WebSocketStream,
    tungstenite::{
        handshake::derive_accept_key,
        protocol::{Role, WebSocketConfig},
    },
};

use crate::{
    common::errors::new_io_error,
    proxy::AnyStream,
};

use super::websocket::WebsocketConn;

pub struct WebsocketEarlyDataConn {
    stream: Option<AnyStream>,
    req: Option<Request<()>>,
    stream_future: Option<
        Pin<
            Box<
                dyn std::future::Future<Output = std::io::Result<AnyStream>>
                    + Send
                    + Sync,
            >,
        >,
    >,
    early_waker: Option<Waker>,
    flush_waker: Option<Waker>,
    ws_config: Option<WebSocketConfig>,
    early_data_header_name: String,
    early_data_len: usize,
    early_data_flushed: bool,
    /// Why the handshake failed: every later call returns it (polling the
    /// finished handshake again panicked, and reads waited forever).
    failure: Option<(std::io::ErrorKind, String)>,
}

impl Debug for WebsocketEarlyDataConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebsocketEarlyDataConn")
            .field("req", &self.req)
            .field("early_waker", &self.early_waker)
            .field("flush_waker", &self.flush_waker)
            .field("ws_config", &self.ws_config)
            .field("early_data_header_name", &self.early_data_header_name)
            .field("early_data_len", &self.early_data_len)
            .field("early_data_flushed", &self.early_data_flushed)
            .finish()
    }
}

impl WebsocketEarlyDataConn {
    pub fn new(
        stream: AnyStream,
        req: Request<()>,
        ws_config: Option<WebSocketConfig>,
        early_data_header_name: String,
        early_data_len: usize,
    ) -> Self {
        Self {
            stream: Some(stream),
            req: Some(req),
            stream_future: None,
            early_waker: None,
            flush_waker: None,
            ws_config,
            early_data_header_name,
            early_data_len,
            early_data_flushed: false,
            failure: None,
        }
    }

    fn failed(&self) -> Option<std::io::Error> {
        self.failure.as_ref().map(|(kind, message)| std::io::Error::new(*kind, message.clone()))
    }

    fn proxy_stream(
        stream: AnyStream,
        req: Request<()>,
        config: Option<WebSocketConfig>,
    ) -> Pin<
        Box<
            dyn std::future::Future<Output = std::io::Result<AnyStream>>
                + Send
                + Sync,
        >,
    > {
        async fn run(
            stream: AnyStream,
            req: Request<()>,
            config: Option<WebSocketConfig>,
        ) -> std::io::Result<AnyStream> {
            let stream = handshake(stream, req, config).await?;
            Ok(Box::new(WebsocketConn::from_websocket(stream)))
        }

        Box::pin(run(stream, req, config))
    }
}

impl AsyncRead for WebsocketEarlyDataConn {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if let Some(e) = self.failed() {
            return Poll::Ready(Err(e));
        }
        if !self.early_data_flushed {
            if self.early_waker.is_none() {
                self.as_mut().early_waker = Some(cx.waker().clone());
            }
            return Poll::Pending;
        }
        let pin = self.get_mut();
        match &mut pin.stream {
            None => unreachable!("bad state"),
            Some(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for WebsocketEarlyDataConn {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        if let Some(e) = self.failed() {
            return Poll::Ready(Err(e));
        }
        if !self.early_data_flushed {
            loop {
                match &mut self.as_mut().stream_future {
                    Some(fut) => {
                        let stream = match ready!(Pin::new(fut).poll(cx)) {
                            Ok(stream) => stream,
                            Err(e) => {
                                self.as_mut().stream_future = None;
                                self.as_mut().failure =
                                    Some((e.kind(), e.to_string()));
                                if let Some(w) = self.as_mut().early_waker.take() {
                                    w.wake();
                                }
                                if let Some(w) = self.as_mut().flush_waker.take() {
                                    w.wake();
                                }
                                return Poll::Ready(Err(e));
                            }
                        };

                        self.as_mut().stream = Some(stream);
                        self.as_mut().early_data_flushed = true;

                        if let Some(w) = self.as_mut().early_waker.take() {
                            w.wake();
                        }
                        if let Some(w) = self.as_mut().flush_waker.take() {
                            w.wake();
                        }
                        return Poll::Ready(Ok(self.as_mut().early_data_len));
                    }
                    _ => {
                        let mut req =
                            self.as_mut().req.take().expect("req must be present");
                        if let Some(v) = req
                            .headers_mut()
                            .get_mut(&self.as_mut().early_data_header_name)
                        {
                            self.as_mut().early_data_len =
                                cmp::min(self.as_mut().early_data_len, buf.len());
                            let header_value = URL_SAFE_NO_PAD
                                .encode(&buf[..self.as_mut().early_data_len]);
                            *v = HeaderValue::from_str(&header_value)
                                .expect("bad header value");
                        }

                        let stream =
                            self.as_mut().stream.take().expect("msg: bad state");
                        let config = self.as_mut().ws_config.take();
                        self.as_mut().stream_future =
                            Some(Self::proxy_stream(stream, req, config));
                    }
                }
            }
        }

        match &mut self.as_mut().stream {
            None => unreachable!("bad state"),
            Some(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        if let Some(e) = self.failed() {
            return Poll::Ready(Err(e));
        }
        if !self.early_data_flushed {
            if self.as_mut().flush_waker.is_none() {
                self.as_mut().flush_waker = Some(cx.waker().clone());
            }
            return Poll::Pending;
        }
        match &mut self.stream {
            None => unreachable!("bad state"),
            Some(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        if self.failure.is_some() {
            return Poll::Ready(Ok(()));
        }
        if !self.early_data_flushed {
            ready!(self.as_mut().poll_flush(cx))?;
        }
        let pin = self.get_mut();
        match &mut pin.stream {
            None => unreachable!("bad state"),
            Some(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

impl crate::proxy::ProxyStream for WebsocketEarlyDataConn {}

/// The client's WebSocket handshake, done here rather than by tungstenite:
/// the early data travels in a request header (Sec-WebSocket-Protocol by
/// convention), and tungstenite rejects a response that does not echo it
/// ("Server sent no subprotocol") although servers commonly do not. The
/// response must still switch protocols with the right
/// Sec-WebSocket-Accept.
async fn handshake(
    mut stream: AnyStream,
    req: Request<()>,
    config: Option<WebSocketConfig>,
) -> std::io::Result<WebSocketStream<AnyStream>> {
    let uri = req.uri();
    let target = uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
    let mut head = format!("GET {target} HTTP/1.1\r\n");
    if !req.headers().contains_key(http::header::HOST) {
        let host = uri.host().unwrap_or_default();
        match uri.port_u16() {
            Some(port) => head.push_str(&format!("Host: {host}:{port}\r\n")),
            None => head.push_str(&format!("Host: {host}\r\n")),
        }
    }
    for (name, value) in req.headers() {
        let value = value.to_str().map_err(|e| new_io_error(format!("header {name}: {e}")))?;
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes()).await?;
    stream.flush().await?;

    // Up to the blank line, a byte at a time: frames may follow at once.
    let mut response = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    while !response.ends_with(b"\r\n\r\n") {
        if response.len() > 16 * 1024 {
            return Err(new_io_error("websocket handshake: response header too long"));
        }
        if stream.read(&mut byte).await? == 0 {
            return Err(new_io_error("websocket handshake: connection closed"));
        }
        response.push(byte[0]);
    }
    let response = String::from_utf8_lossy(&response);
    let mut lines = response.split("\r\n");
    let status = lines.next().unwrap_or_default();
    if status.split_whitespace().nth(1) != Some("101") {
        return Err(new_io_error(format!("websocket handshake failed: {status}")));
    }
    let accept = lines
        .filter_map(|l| l.split_once(':'))
        .find(|(name, _)| name.trim().eq_ignore_ascii_case("sec-websocket-accept"))
        .map(|(_, v)| v.trim().to_owned());
    let key = req
        .headers()
        .get("Sec-WebSocket-Key")
        .ok_or_else(|| new_io_error("websocket handshake: no key"))?;
    if accept.as_deref() != Some(derive_accept_key(key.as_bytes()).as_str()) {
        return Err(new_io_error("websocket handshake: wrong Sec-WebSocket-Accept"));
    }
    Ok(WebSocketStream::from_raw_socket(stream, Role::Client, config).await)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    /// A server that takes the early data but does not echo the header.
    async fn serve(mut server: tokio::io::DuplexStream, echo: bool, accept_right: bool) {
        let mut request = Vec::new();
        let mut byte = [0u8; 1];
        while !request.ends_with(b"\r\n\r\n") {
            if server.read(&mut byte).await.unwrap_or(0) == 0 {
                return;
            }
            request.push(byte[0]);
        }
        let text = String::from_utf8_lossy(&request).to_string();
        let key = text
            .lines()
            .find_map(|l| l.strip_prefix("Sec-WebSocket-Key: ").or_else(|| l.strip_prefix("sec-websocket-key: ")))
            .unwrap_or_default()
            .trim()
            .to_owned();
        let accept = if accept_right { derive_accept_key(key.as_bytes()) } else { "nope".into() };
        let protocol = if echo { "Sec-WebSocket-Protocol: x\r\n" } else { "" };
        let _ = server
            .write_all(format!("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n{protocol}\r\n").as_bytes())
            .await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    fn request() -> Request<()> {
        Request::builder()
            .uri("ws://example.com:443/ws")
            .header("Host", "example.com")
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .header("Sec-WebSocket-Version", "13")
            .header("Sec-WebSocket-Key", tokio_tungstenite::tungstenite::handshake::client::generate_key())
            .header("Sec-WebSocket-Protocol", "ZWFybHk")
            .body(())
            .unwrap()
    }

    #[tokio::test]
    async fn no_echoed_subprotocol_is_fine() {
        for echo in [false, true] {
            let (client, server) = duplex(4096);
            let server = tokio::spawn(serve(server, echo, true));
            assert!(handshake(Box::new(client), request(), None).await.is_ok(), "echo {echo}");
            let _ = server.await;
        }
        let (client, server) = duplex(4096);
        let server = tokio::spawn(serve(server, false, false));
        assert!(handshake(Box::new(client), request(), None).await.is_err());
        let _ = server.await;
    }

    #[tokio::test]
    async fn a_failed_handshake_fails_every_call() {
        let (client, server) = duplex(4096);
        drop(server);
        let mut conn = WebsocketEarlyDataConn::new(Box::new(client), request(), None, "Sec-WebSocket-Protocol".into(), 2048);
        assert!(conn.write_all(b"vless request").await.is_err());
        // Polling again used to panic ("async fn resumed after completion").
        assert!(conn.write_all(b"more").await.is_err());
        let mut buf = [0u8; 8];
        assert!(conn.read(&mut buf).await.is_err());
        assert!(conn.flush().await.is_err());
    }
}
