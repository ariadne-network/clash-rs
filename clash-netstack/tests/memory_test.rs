//! What TCP connections cost in memory (our fork): resident pages, as
//! iOS counts them against a packet tunnel's limit (phys_footprint), for
//! new connections and for connections that carried a download and stay
//! open. Each kept its whole send buffer and ring before: 594 KiB here,
//! with the 256 KiB buffers of macOS.
#![cfg(target_vendor = "apple")]

use std::{collections::HashMap, time::Duration};

use bytes::{BufMut, Bytes, BytesMut};
use futures::{SinkExt, StreamExt};
use tokio::io::AsyncWriteExt;
use watfaq_netstack::{NetStack, Packet};

#[allow(dead_code)]
mod common;
mod mock_tun;

use common::{
    build_tcp_syn_packet_with_port, ipv4_checksum, is_syn_ack, parse_server_isn,
    parse_tcp_data, tcp_dst_port, tcp_udp_checksum,
};
use mock_tun::MockTun;

const CONNECTIONS: u16 = 64;
const DOWNLOAD: usize = 512 * 1024;

fn footprint() -> i64 {
    let mut info: libc::rusage_info_v2 = unsafe { std::mem::zeroed() };
    let ptr = (&mut info as *mut libc::rusage_info_v2).cast();
    assert_eq!(
        unsafe {
            libc::proc_pid_rusage(
                std::process::id() as i32,
                libc::RUSAGE_INFO_V2,
                ptr,
            )
        },
        0
    );
    info.ri_phys_footprint as i64
}

/// An ACK from the client 1.1.1.1:`port` to 2.2.2.2:80.
fn ack(port: u16, seq: u32, ack: u32) -> Bytes {
    let (src, dst) = ([1u8, 1, 1, 1], [2u8, 2, 2, 2]);
    let mut buf = BytesMut::with_capacity(40);
    buf.put_slice(&[0x45, 0, 0, 40, 0, 1, 0x40, 0, 0x40, 6, 0, 0]);
    buf.put_slice(&src);
    buf.put_slice(&dst);
    buf.put_u16(port);
    buf.put_u16(80);
    buf.put_u32(seq);
    buf.put_u32(ack);
    buf.put_slice(&[0x50, 0x10, 0xff, 0xff, 0, 0, 0, 0]);
    let sum = tcp_udp_checksum(src, dst, 6, &buf[20..]);
    buf[36..38].copy_from_slice(&sum.to_be_bytes());
    let sum = ipv4_checksum(&buf[..20]);
    buf[10..12].copy_from_slice(&sum.to_be_bytes());
    buf.freeze()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connections_memory() {
    let (mut tun, tun_in, _) = MockTun::new();
    let (stack, mut listener, _udp) = NetStack::new();
    let (mut sink, mut stream) = stack.split();
    tokio::spawn(async move {
        while let Some(pkt) = tun.next().await {
            sink.send(Packet::new(pkt)).await.unwrap();
        }
    });
    // The clients: complete each handshake and ACK each segment at once,
    // as an app reading promptly; report bytes received.
    let (got_tx, mut got_rx) = tokio::sync::mpsc::unbounded_channel::<usize>();
    let client_in = tun_in.clone();
    tokio::spawn(async move {
        let mut acked: HashMap<u16, u32> = HashMap::new();
        while let Some(Ok(pkt)) = stream.next().await {
            let data = pkt.data();
            let Some(port) = tcp_dst_port(data) else {
                continue;
            };
            if is_syn_ack(data) {
                let next = parse_server_isn(data).wrapping_add(1);
                acked.insert(port, next);
                client_in.send(ack(port, 1, next)).unwrap();
            } else if let (Some((seq, len)), Some(cum)) =
                (parse_tcp_data(data), acked.get_mut(&port))
                && len > 0
            {
                let end = seq.wrapping_add(len as u32);
                let advance = end.wrapping_sub(*cum);
                if advance > 0 && advance < 1 << 31 {
                    *cum = end;
                    let _ = got_tx.send(advance as usize);
                }
                client_in.send(ack(port, 1, *cum)).unwrap();
            }
        }
    });
    tokio::time::sleep(Duration::from_millis(200)).await;
    let base = footprint();

    // New connections: their buffers are mapped as they are used.
    for port in 20000..20000 + CONNECTIONS {
        tun_in.send(build_tcp_syn_packet_with_port(port)).unwrap();
    }
    let mut streams = Vec::new();
    for _ in 0..CONNECTIONS {
        streams.push(listener.next().await.unwrap());
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    let new = footprint();

    // Downloads through them, which then stay open.
    let mut writers = Vec::new();
    for mut s in streams {
        writers.push(tokio::spawn(async move {
            // At the pace of a network (800 KiB/s each), which the app
            // keeps up with.
            let chunk = vec![0xab; 16 * 1024];
            for _ in 0..DOWNLOAD / chunk.len() {
                s.write_all(&chunk).await.unwrap();
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            s
        }));
    }
    let mut received = 0;
    tokio::time::timeout(Duration::from_secs(60), async {
        while received < CONNECTIONS as usize * DOWNLOAD {
            received += got_rx.recv().await.unwrap();
        }
    })
    .await
    .expect("downloads stalled");
    let mut idle = Vec::new();
    for w in writers {
        idle.push(w.await.unwrap());
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    let downloaded = footprint();

    let kib = |bytes: i64| bytes / 1024 / CONNECTIONS as i64;
    let (new, downloaded) = (kib(new - base), kib(downloaded - base));
    eprintln!(
        "per connection: {new} KiB new, {downloaded} KiB after a {} KiB download (idle)",
        DOWNLOAD / 1024
    );
    assert!(new < 16, "{new} KiB");
    // About 110 KiB: the rings' first pages, and what the allocator keeps
    // of the packets and the writers' chunks.
    assert!(downloaded < 200, "{downloaded} KiB");
    drop(idle);
}
