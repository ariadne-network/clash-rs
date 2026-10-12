//! HTTP upgrade (V2Ray and Xray "httpupgrade", sing-box "httpupgrade",
//! mihomo's ws-opts `v2ray-http-upgrade`): one HTTP/1.1 Upgrade request, a
//! 101 response, then the raw stream without WebSocket framing. CDNs pass
//! it like a WebSocket.

use std::{collections::HashMap, io};

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::Transport;
use crate::proxy::AnyStream;

pub struct Client {
    server: String,
    port: u16,
    path: String,
    headers: HashMap<String, String>,
}

impl Client {
    pub fn new(
        server: String,
        port: u16,
        path: String,
        headers: HashMap<String, String>,
    ) -> Self {
        Self {
            server,
            port,
            path,
            headers,
        }
    }

    fn request(&self) -> String {
        let path = if self.path.starts_with('/') {
            self.path.replace(' ', "%20")
        } else {
            format!("/{}", self.path.replace(' ', "%20"))
        };
        let host = self
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("host"))
            .map(|(_, v)| v.clone())
            .unwrap_or_else(|| match self.port {
                80 | 443 => self.server.clone(),
                port if self.server.contains(':') => {
                    format!("[{}]:{port}", self.server)
                }
                port => format!("{}:{port}", self.server),
            });
        let mut head = format!(
            "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: \
             Upgrade\r\nUpgrade: websocket\r\n"
        );
        for (k, v) in &self.headers {
            if !k.eq_ignore_ascii_case("host") {
                head.push_str(&format!("{k}: {v}\r\n"));
            }
        }
        head.push_str("\r\n");
        head
    }
}

#[async_trait]
impl Transport for Client {
    async fn proxy_stream(&self, mut stream: AnyStream) -> io::Result<AnyStream> {
        stream.write_all(self.request().as_bytes()).await?;
        stream.flush().await?;
        // Byte by byte: what follows the header is the tunnelled stream.
        let mut response = Vec::with_capacity(256);
        let mut byte = [0u8; 1];
        while !response.ends_with(b"\r\n\r\n") {
            if response.len() > 16 * 1024 {
                return Err(io::Error::other(
                    "HTTP upgrade: response header too long",
                ));
            }
            if stream.read(&mut byte).await? == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "HTTP upgrade: connection closed",
                ));
            }
            response.push(byte[0]);
        }
        let text = String::from_utf8_lossy(&response);
        let status = text.lines().next().unwrap_or_default();
        if status.split_whitespace().nth(1) != Some("101") {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("HTTP upgrade failed: {status}"),
            ));
        }
        Ok(stream)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    async fn read_head(server: &mut tokio::io::DuplexStream) -> String {
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            server.read_exact(&mut byte).await.unwrap();
            head.push(byte[0]);
        }
        String::from_utf8(head).unwrap()
    }

    fn client(headers: &[(&str, &str)]) -> Client {
        Client::new(
            "example.com".into(),
            8080,
            "up?ed=2048".into(),
            headers
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        )
    }

    #[tokio::test]
    async fn upgrades_then_carries_the_raw_stream() {
        let (c, mut server) = duplex(4096);
        let task = tokio::spawn(async move {
            let head = read_head(&mut server).await;
            server
                .write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: \
                      websocket\r\nConnection: Upgrade\r\n\r\npong",
                )
                .await
                .unwrap();
            let mut ping = [0u8; 4];
            server.read_exact(&mut ping).await.unwrap();
            (head, ping)
        });
        let mut stream = client(&[("Host", "cdn.example.com"), ("X-A", "1")])
            .proxy_stream(Box::new(c))
            .await
            .unwrap();
        let mut pong = [0u8; 4];
        stream.read_exact(&mut pong).await.unwrap();
        assert_eq!(&pong, b"pong");
        stream.write_all(b"ping").await.unwrap();
        let (head, ping) = task.await.unwrap();
        assert_eq!(&ping, b"ping");
        assert!(head.starts_with("GET /up?ed=2048 HTTP/1.1\r\n"), "{head}");
        assert!(head.contains("\r\nHost: cdn.example.com\r\n"), "{head}");
        assert!(head.contains("\r\nUpgrade: websocket\r\n"), "{head}");
        assert!(head.contains("\r\nX-A: 1\r\n"), "{head}");
        assert_eq!(head.matches("Host:").count(), 1, "{head}");
    }

    #[tokio::test]
    async fn host_defaults_to_the_server_and_refusal_fails() {
        let (c, mut server) = duplex(4096);
        let task = tokio::spawn(async move {
            let head = read_head(&mut server).await;
            server
                .write_all(b"HTTP/1.1 404 Not Found\r\n\r\n")
                .await
                .unwrap();
            head
        });
        let result = client(&[]).proxy_stream(Box::new(c)).await;
        let head = task.await.unwrap();
        assert!(head.contains("\r\nHost: example.com:8080\r\n"), "{head}");
        assert!(result.is_err());
    }
}
