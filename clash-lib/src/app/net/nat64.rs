//! IPv4 destinations on IPv6-only networks (our fork): the application,
//! which knows the network, sets how the network's NAT64 reaches an IPv4
//! address (the IPv6 address its prefix makes of it, RFC 6052), and every
//! outbound socket connects there instead.

use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{Arc, RwLock},
};

/// The IPv6 address the network's NAT64 reaches an IPv4 address at; None
/// for one it cannot reach.
pub type Nat64 = Arc<dyn Fn(Ipv4Addr) -> Option<Ipv6Addr> + Send + Sync>;

static NAT64: RwLock<Option<Nat64>> = RwLock::new(None);

/// Sets it while the network is IPv6-only; None otherwise.
pub fn set_nat64(nat64: Option<Nat64>) {
    *NAT64.write().unwrap() = nat64;
}

/// Where to connect to reach `addr`: through the NAT64 on an IPv6-only
/// network, else `addr` itself.
pub fn reachable(addr: SocketAddr) -> SocketAddr {
    let SocketAddr::V4(v4) = addr else {
        return addr;
    };
    let Some(nat64) = NAT64.read().unwrap().clone() else {
        return addr;
    };
    nat64(*v4.ip()).map_or(addr, |v6| SocketAddr::from((v6, v4.port())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn through_the_nat64_when_set() {
        let v4: SocketAddr = "203.0.113.5:443".parse().unwrap();
        assert_eq!(reachable(v4), v4);
        set_nat64(Some(Arc::new(|ip: Ipv4Addr| {
            (!ip.is_private()).then(|| {
                let o = ip.octets();
                Ipv6Addr::new(
                    0x64,
                    0xff9b,
                    0,
                    0,
                    0,
                    0,
                    u16::from_be_bytes([o[0], o[1]]),
                    u16::from_be_bytes([o[2], o[3]]),
                )
            })
        })));
        assert_eq!(reachable(v4), "[64:ff9b::cb00:7105]:443".parse().unwrap());
        let lan: SocketAddr = "192.168.1.2:53".parse().unwrap();
        assert_eq!(reachable(lan), lan);
        let v6: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        assert_eq!(reachable(v6), v6);
        set_nat64(None);
        assert_eq!(reachable(v4), v4);
    }
}
