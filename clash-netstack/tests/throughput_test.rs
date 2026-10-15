//! Download throughput through the stack with the app a round trip away
//! (RTT_US microseconds, default 1000; 0 acknowledges at once): the send
//! buffer bounds what is in flight, so the speed is at most its size over
//! the round trip. A measurement, not run by default:
//! `cargo test --release --test throughput_test -- --ignored --nocapture`.

use std::time::{Duration, Instant};

use bytes::{BufMut, Bytes, BytesMut};
use futures::{SinkExt, StreamExt};
use tokio::io::AsyncWriteExt;
use watfaq_netstack::{NetStack, Packet};

#[allow(dead_code)]
mod common;
mod mock_tun;

use common::{
    ipv4_checksum, is_syn_ack, parse_server_isn, parse_tcp_data, tcp_udp_checksum,
};
use mock_tun::MockTun;

const PORT: u16 = 40000;

/// A segment from the client 1.1.1.1:PORT to 2.2.2.2:80, with `options`.
fn segment(flags: u8, seq: u32, ack: u32, window: u16, options: &[u8]) -> Bytes {
    let (src, dst) = ([1u8, 1, 1, 1], [2u8, 2, 2, 2]);
    let len = 40 + options.len();
    let mut buf = BytesMut::with_capacity(len);
    buf.put_slice(&[0x45, 0, 0, len as u8, 0, 1, 0x40, 0, 0x40, 6, 0, 0]);
    buf.put_slice(&src);
    buf.put_slice(&dst);
    buf.put_u16(PORT);
    buf.put_u16(80);
    buf.put_u32(seq);
    buf.put_u32(ack);
    buf.put_u8(((20 + options.len()) / 4 * 16) as u8);
    buf.put_u8(flags);
    buf.put_u16(window);
    buf.put_slice(&[0, 0, 0, 0]);
    buf.put_slice(options);
    let sum = tcp_udp_checksum(src, dst, 6, &buf[20..]);
    buf[36..38].copy_from_slice(&sum.to_be_bytes());
    let sum = ipv4_checksum(&buf[..20]);
    buf[10..12].copy_from_slice(&sum.to_be_bytes());
    buf.freeze()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn download_throughput() {
    const BYTES: usize = 64 * 1024 * 1024;
    let rtt = Duration::from_micros(
        std::env::var("RTT_US")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(1000),
    );
    let (mut tun, tun_in, _) = MockTun::new();
    let (stack, mut listener, _udp) = NetStack::new();
    let (mut sink, mut stream) = stack.split();
    tokio::spawn(async move {
        while let Some(pkt) = tun.next().await {
            sink.send(Packet::new(pkt)).await.unwrap();
        }
    });

    // ACKs go out a round trip after the segments they acknowledge; the
    // timer makes it longer than asked, so the actual mean is reported.
    let (ack_tx, mut ack_rx) =
        tokio::sync::mpsc::unbounded_channel::<(Instant, Bytes)>();
    let delayed_in = tun_in.clone();
    let delays = tokio::spawn(async move {
        let (mut n, mut total) = (0u32, Duration::ZERO);
        while let Some((at, pkt)) = ack_rx.recv().await {
            tokio::time::sleep_until(at.into()).await;
            n += 1;
            total += Instant::now() - (at - rtt);
            if delayed_in.send(pkt).is_err() {
                break;
            }
        }
        total.checked_div(n).unwrap_or_default()
    });

    // MSS 1460, window scale 7: the app's window (8 MiB) is never the limit.
    let options = [2, 4, 0x05, 0xb4, 1, 3, 3, 7];
    tun_in.send(segment(0x02, 0, 0, 65535, &options)).unwrap();
    let client = tokio::spawn(async move {
        let mut cum = loop {
            let pkt = stream.next().await.unwrap().unwrap();
            if is_syn_ack(pkt.data()) {
                break parse_server_isn(pkt.data()).wrapping_add(1);
            }
        };
        tun_in.send(segment(0x10, 1, cum, 65535, &[])).unwrap();
        let start = Instant::now();
        let mut received = 0;
        while received < BYTES {
            let pkt = stream.next().await.unwrap().unwrap();
            if let Some((seq, len)) = parse_tcp_data(pkt.data())
                && len > 0
            {
                let end = seq.wrapping_add(len as u32);
                let advance = end.wrapping_sub(cum);
                if advance > 0 && advance < 1 << 31 {
                    received += advance as usize;
                    cum = end;
                }
                let ack = segment(0x10, 1, cum, 65535, &[]);
                if rtt.is_zero() {
                    tun_in.send(ack).unwrap();
                } else {
                    ack_tx.send((Instant::now() + rtt, ack)).unwrap();
                }
            }
        }
        start.elapsed()
    });

    let mut s = listener.next().await.unwrap();
    let writer = tokio::spawn(async move {
        let chunk = vec![0xab; 16 * 1024];
        for _ in 0..BYTES / chunk.len() {
            s.write_all(&chunk).await.unwrap();
        }
        s
    });
    let elapsed = tokio::time::timeout(Duration::from_secs(120), client)
        .await
        .expect("stalled")
        .unwrap();
    let _s = writer.await.unwrap();
    let mib_s = BYTES as f64 / elapsed.as_secs_f64() / 1_048_576.0;
    if rtt.is_zero() {
        eprintln!("acknowledged at once: {mib_s:.1} MiB/s");
    } else {
        // The client is done, so the queue ends.
        let mean = delays.await.unwrap();
        eprintln!("round trip {mean:.2?} (asked {rtt:?}): {mib_s:.1} MiB/s");
    }
}
