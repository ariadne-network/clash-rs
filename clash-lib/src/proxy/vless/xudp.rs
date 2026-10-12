//! XUDP: UDP over a VLESS Mux.Cool connection. Xray and sing-box servers
//! refuse the plain UDP command with the xtls-rprx-vision flow ("does not
//! support UDP"); their clients send UDP this way instead.
//!
//! Each datagram is one Mux.Cool frame of session 0, the first `New` and
//! the rest `Keep`, each with its destination, so one connection reaches
//! any number of destinations. A frame:
//!
//! ```text
//! u16 metadata length | u16 session | u8 status | u8 option
//!     | u8 network (2 = UDP) | port, address type, address (as VMess)
//! u16 data length | data                      (when option has DATA)
//! ```

use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{BufMut, BytesMut};
use futures::{Sink, Stream, StreamExt, ready};
use tokio_util::codec::{Decoder, Encoder, Framed};
use tracing::debug;

use crate::{
    proxy::{AnyStream, datagram::UdpPacket},
    session::SocksAddr,
};

const STATUS_NEW: u8 = 1;
const STATUS_KEEP: u8 = 2;
const STATUS_END: u8 = 3;
const STATUS_KEEP_ALIVE: u8 = 4;
const OPTION_DATA: u8 = 1;
const OPTION_ERROR: u8 = 2;
const NETWORK_UDP: u8 = 2;
/// Xray drops larger datagrams (its 8 KiB buffers less 666 bytes).
const MAX_PAYLOAD: usize = 8192 - 666;

struct XudpCodec {
    /// The session's first destination: replies without an address
    /// come from it.
    destination: SocksAddr,
    started: bool,
}

impl Encoder<UdpPacket> for XudpCodec {
    type Error = io::Error;

    fn encode(&mut self, packet: UdpPacket, dst: &mut BytesMut) -> io::Result<()> {
        if packet.data.is_empty() || packet.data.len() > MAX_PAYLOAD {
            debug!("XUDP: dropping a {}-byte datagram", packet.data.len());
            return Ok(());
        }
        let mut meta = BytesMut::with_capacity(32);
        meta.put_u16(0);
        meta.put_u8(if self.started {
            STATUS_KEEP
        } else {
            STATUS_NEW
        });
        meta.put_u8(OPTION_DATA);
        meta.put_u8(NETWORK_UDP);
        packet.dst_addr.write_to_buf_vmess(&mut meta);
        self.started = true;
        dst.reserve(4 + meta.len() + packet.data.len());
        dst.put_u16(meta.len() as u16);
        dst.put_slice(&meta);
        dst.put_u16(packet.data.len() as u16);
        dst.put_slice(&packet.data);
        Ok(())
    }
}

impl Decoder for XudpCodec {
    type Error = io::Error;
    type Item = UdpPacket;

    fn decode(&mut self, src: &mut BytesMut) -> io::Result<Option<UdpPacket>> {
        loop {
            if src.len() < 2 {
                return Ok(None);
            }
            let meta_len = u16::from_be_bytes([src[0], src[1]]) as usize;
            if meta_len < 4 {
                return Err(invalid("frame metadata too short"));
            }
            let option = match src.get(5) {
                Some(option) => *option,
                None => return Ok(None),
            };
            let mut total = 2 + meta_len;
            if option & OPTION_DATA != 0 {
                if src.len() < total + 2 {
                    return Ok(None);
                }
                total +=
                    2 + u16::from_be_bytes([src[total], src[total + 1]]) as usize;
            }
            if src.len() < total {
                src.reserve(total - src.len());
                return Ok(None);
            }
            let frame = src.split_to(total);
            match frame[4] {
                STATUS_KEEP => {}
                STATUS_KEEP_ALIVE => continue,
                STATUS_END => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "XUDP session ended",
                    ));
                }
                status => {
                    return Err(invalid(&format!("unexpected frame {status}")));
                }
            }
            if option & OPTION_ERROR != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "XUDP session closed by the server",
                ));
            }
            if option & OPTION_DATA == 0 {
                continue;
            }
            let from = if meta_len > 4 && frame[6] == NETWORK_UDP {
                read_vmess_addr(&frame[7..2 + meta_len])?
            } else {
                self.destination.clone()
            };
            return Ok(Some(UdpPacket {
                data: frame[2 + meta_len + 2..].to_vec(),
                src_addr: from,
                dst_addr: self.destination.clone(),
                inbound_user: None,
            }));
        }
    }
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("XUDP: {message}"))
}

/// Port, then address type (1 IPv4, 2 domain, 3 IPv6) and address.
fn read_vmess_addr(buf: &[u8]) -> io::Result<SocksAddr> {
    let short = || invalid("address too short");
    let port = u16::from_be_bytes([
        *buf.first().ok_or_else(short)?,
        *buf.get(1).ok_or_else(short)?,
    ]);
    let rest = &buf[2..];
    match rest.first() {
        Some(1) => {
            let ip: [u8; 4] = rest.get(1..5).ok_or_else(short)?.try_into().unwrap();
            Ok(SocksAddr::Ip(SocketAddr::from((Ipv4Addr::from(ip), port))))
        }
        Some(3) => {
            let ip: [u8; 16] =
                rest.get(1..17).ok_or_else(short)?.try_into().unwrap();
            Ok(SocksAddr::Ip(SocketAddr::from((Ipv6Addr::from(ip), port))))
        }
        Some(2) => {
            let len = *rest.get(1).ok_or_else(short)? as usize;
            let name = rest.get(2..2 + len).ok_or_else(short)?;
            let name = String::from_utf8(name.to_vec())
                .map_err(|_| invalid("domain is not UTF-8"))?;
            Ok(SocksAddr::Domain(name, port))
        }
        _ => Err(invalid("unknown address type")),
    }
}

/// The datagrams of one XUDP session over a VLESS stream (Mux command).
pub struct OutboundDatagramXudp {
    inner: Framed<AnyStream, XudpCodec>,
}

impl OutboundDatagramXudp {
    pub fn new(stream: AnyStream, destination: SocksAddr) -> Self {
        Self {
            inner: Framed::new(
                stream,
                XudpCodec {
                    destination,
                    started: false,
                },
            ),
        }
    }
}

impl Stream for OutboundDatagramXudp {
    type Item = UdpPacket;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        match ready!(self.inner.poll_next_unpin(cx)) {
            Some(Ok(packet)) => Poll::Ready(Some(packet)),
            Some(Err(e)) => {
                debug!("XUDP: {e}");
                Poll::Ready(None)
            }
            None => Poll::Ready(None),
        }
    }
}

impl Sink<UdpPacket> for OutboundDatagramXudp {
    type Error = io::Error;

    fn poll_ready(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_ready(cx)
    }

    fn start_send(mut self: Pin<&mut Self>, item: UdpPacket) -> io::Result<()> {
        Pin::new(&mut self.inner).start_send(item)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_close(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet(data: &[u8], dst: &str) -> UdpPacket {
        UdpPacket {
            data: data.to_vec(),
            src_addr: SocksAddr::any_ipv4(),
            dst_addr: dst.parse().unwrap(),
            inbound_user: None,
        }
    }

    fn codec() -> XudpCodec {
        XudpCodec {
            destination: "1.2.3.4:53".parse().unwrap(),
            started: false,
        }
    }

    #[test]
    fn frames_new_then_keep_with_the_destination() {
        let mut c = codec();
        let mut out = BytesMut::new();
        c.encode(packet(b"ab", "1.2.3.4:53"), &mut out).unwrap();
        // meta: session 0, New, data, UDP, port 53, IPv4 1.2.3.4
        assert_eq!(
            &out[..],
            &[0, 12, 0, 0, 1, 1, 2, 0, 53, 1, 1, 2, 3, 4, 0, 2, b'a', b'b']
        );
        out.clear();
        c.encode(packet(b"c", "[::1]:443"), &mut out).unwrap();
        assert_eq!(&out[..6], &[0, 24, 0, 0, STATUS_KEEP, OPTION_DATA]);
        assert_eq!(&out[6..10], &[NETWORK_UDP, 1, 187, 3]);
        assert_eq!(&out[out.len() - 3..], &[0, 1, b'c']);
    }

    #[test]
    fn reads_replies_across_partial_input() {
        let mut c = codec();
        // Keep-alive, a reply with an address, a reply without one.
        let mut wire = BytesMut::new();
        wire.extend_from_slice(&[0, 4, 0, 0, STATUS_KEEP_ALIVE, 0]);
        wire.extend_from_slice(&[0, 12, 0, 0, 2, 1, 2, 0, 80, 1, 5, 6, 7, 8]);
        wire.extend_from_slice(&[0, 3, b'x', b'y', b'z']);
        wire.extend_from_slice(&[0, 4, 0, 0, 2, 1, 0, 1, b'q']);
        let mut src = BytesMut::new();
        let mut got = Vec::new();
        for b in wire {
            src.put_u8(b);
            if let Some(p) = c.decode(&mut src).unwrap() {
                got.push(p);
            }
        }
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].data, b"xyz");
        assert_eq!(got[0].src_addr, "5.6.7.8:80".parse::<SocksAddr>().unwrap());
        assert_eq!(got[1].data, b"q");
        assert_eq!(got[1].src_addr, "1.2.3.4:53".parse::<SocksAddr>().unwrap());
    }

    #[test]
    fn ends_on_end_or_error() {
        let mut src = BytesMut::from(&[0u8, 4, 0, 0, STATUS_END, 0][..]);
        assert!(codec().decode(&mut src).is_err());
        let mut src = BytesMut::from(&[0u8, 4, 0, 0, STATUS_KEEP, OPTION_ERROR][..]);
        assert!(codec().decode(&mut src).is_err());
    }
}
