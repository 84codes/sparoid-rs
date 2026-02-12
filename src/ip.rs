use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use futures::future::join_all;
use if_addrs::IfAddr;

use crate::errors::SparoidError;

pub struct Ipv6WithRange {
    pub ip: Ipv6Addr,
    pub range: u8,
}

pub fn public_ipv6_with_range() -> Vec<Ipv6WithRange> {
    let ifaces = if_addrs::get_if_addrs().unwrap();
    ifaces
        .iter()
        .filter_map(|iface| match &iface.addr {
            IfAddr::V4(_v4) => None,
            IfAddr::V6(v6) => {
                if v6.ip.is_custom_global() {
                    return Some(Ipv6WithRange {
                        ip: v6.ip,
                        range: v6.netmask.to_bits().leading_ones() as u8,
                    });
                }
                None
            }
        })
        .collect()
}

pub trait Ipv6GlobalExt {
    fn is_custom_global(&self) -> bool;
}

impl Ipv6GlobalExt for Ipv6Addr {
    // Monkey patch to allow usage of the current implemented `is_global` method in standard library that's currently
    // marked as unstable.
    // https://github.com/rust-lang/rust/issues/27709
    fn is_custom_global(&self) -> bool {
        !(self.is_unspecified()
            || self.is_loopback()
            // IPv4-mapped Address (`::ffff:0:0/96`)
            || matches!(self.segments(), [0, 0, 0, 0, 0, 0xffff, _, _])
            // IPv4-IPv6 Translat. (`64:ff9b:1::/48`)
            || matches!(self.segments(), [0x64, 0xff9b, 1, _, _, _, _, _])
            // Discard-Only Address Block (`100::/64`)
            || matches!(self.segments(), [0x100, 0, 0, 0, _, _, _, _])
            // IETF Protocol Assignments (`2001::/23`)
            || (matches!(self.segments(), [0x2001, b, _, _, _, _, _, _] if b < 0x200)
                && !(
                    // Port Control Protocol Anycast (`2001:1::1`)
                    u128::from_be_bytes(self.octets()) == 0x2001_0001_0000_0000_0000_0000_0000_0001
                    // Traversal Using Relays around NAT Anycast (`2001:1::2`)
                    || u128::from_be_bytes(self.octets()) == 0x2001_0001_0000_0000_0000_0000_0000_0002
                    // AMT (`2001:3::/32`)
                    || matches!(self.segments(), [0x2001, 3, _, _, _, _, _, _])
                    // AS112-v6 (`2001:4:112::/48`)
                    || matches!(self.segments(), [0x2001, 4, 0x112, _, _, _, _, _])
                    // ORCHIDv2 (`2001:20::/28`)
                    // Drone Remote ID Protocol Entity Tags (DETs) Prefix (`2001:30::/28`)`
                    || matches!(self.segments(), [0x2001, b, _, _, _, _, _, _] if (0x20..=0x3F).contains(&b))
                ))
            // 6to4 (`2002::/16`) – it's not explicitly documented as globally reachable,
            // IANA says N/A.
            || matches!(self.segments(), [0x2002, _, _, _, _, _, _, _])
            || matches!(self.segments(), [0x2001, 0xdb8, ..] | [0x3fff, 0..=0x0fff, ..])
            // Segment Routing (SRv6) SIDs (`5f00::/16`)
            || matches!(self.segments(), [0x5f00, ..])
            || self.is_unique_local()
            || self.is_unicast_link_local())
    }
}

const URLS: [&str; 2] = ["http://ipv4.icanhazip.com/", "http://ipv6.icanhazip.com/"];

pub async fn public_ip() -> Result<Vec<IpAddr>, SparoidError> {
    let futures = URLS.iter().map(|url| async move {
        let response = reqwest::get(*url).await?;
        let text = response.text().await?;
        let trimmed = text.trim().to_string();
        let ipaddr = trimmed
            .parse::<Ipv4Addr>()
            .map(IpAddr::V4)
            .or_else(|_| trimmed.parse::<Ipv6Addr>().map(IpAddr::V6))?;
        Ok::<IpAddr, SparoidError>(ipaddr)
    });

    let results = join_all(futures).await;

    let addresses: Vec<IpAddr> = results.into_iter().filter_map(|r| r.ok()).collect();
    Ok(addresses)
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Addresses that SHOULD be global ---

    #[test]
    fn global_unicast_is_global() {
        // Google public DNS
        let addr: Ipv6Addr = "2607:f8b0:4004:800::200e".parse().unwrap();
        assert!(addr.is_custom_global());
    }

    // --- Addresses that should NOT be global ---

    #[test]
    fn loopback_is_not_global() {
        let addr = Ipv6Addr::LOCALHOST; // ::1
        assert!(!addr.is_custom_global());
    }

    #[test]
    fn unspecified_is_not_global() {
        let addr = Ipv6Addr::UNSPECIFIED; // ::
        assert!(!addr.is_custom_global());
    }

    #[test]
    fn link_local_is_not_global() {
        let addr: Ipv6Addr = "fe80::1".parse().unwrap();
        assert!(!addr.is_custom_global());
    }

    #[test]
    fn unique_local_is_not_global() {
        let addr: Ipv6Addr = "fd00::1".parse().unwrap();
        assert!(!addr.is_custom_global());
    }

    #[test]
    fn ipv4_mapped_is_not_global() {
        let addr: Ipv6Addr = "::ffff:192.168.1.1".parse().unwrap();
        assert!(!addr.is_custom_global());
    }

    #[test]
    fn documentation_range_is_not_global() {
        let addr: Ipv6Addr = "2001:db8::1".parse().unwrap();
        assert!(!addr.is_custom_global());
    }

    #[test]
    fn six_to_four_is_not_global() {
        let addr: Ipv6Addr = "2002::1".parse().unwrap();
        assert!(!addr.is_custom_global());
    }

    // --- IETF exceptions that ARE global despite being in 2001::/23 ---

    #[test]
    fn port_control_protocol_anycast_is_global() {
        let addr: Ipv6Addr = "2001:1::1".parse().unwrap();
        assert!(addr.is_custom_global());
    }

    #[test]
    fn turn_anycast_is_global() {
        let addr: Ipv6Addr = "2001:1::2".parse().unwrap();
        assert!(addr.is_custom_global());
    }

    #[test]
    fn amt_is_global() {
        let addr: Ipv6Addr = "2001:3::1".parse().unwrap();
        assert!(addr.is_custom_global());
    }

    #[test]
    fn as112_v6_is_global() {
        let addr: Ipv6Addr = "2001:4:112::1".parse().unwrap();
        assert!(addr.is_custom_global());
    }

    #[test]
    fn orchidv2_is_global() {
        let addr: Ipv6Addr = "2001:20::1".parse().unwrap();
        assert!(addr.is_custom_global());
    }

    #[test]
    fn drone_remote_id_is_global() {
        let addr: Ipv6Addr = "2001:30::1".parse().unwrap();
        assert!(addr.is_custom_global());
    }

    // --- IETF range that is NOT an exception (should not be global) ---

    #[test]
    fn ietf_non_exception_is_not_global() {
        // 2001:0::1 is in the IETF range but not one of the carved-out exceptions
        let addr: Ipv6Addr = "2001::1".parse().unwrap();
        assert!(!addr.is_custom_global());
    }
}
