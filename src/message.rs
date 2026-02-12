use std::{
    fmt::Display,
    net::{IpAddr, Ipv4Addr},
    time::{SystemTime, UNIX_EPOCH},
};

use rand::{RngCore, rngs::OsRng};

pub enum Message {
    V1(MessageV1),
    V2(MessageV2),
}

impl Message {
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Message::V1(m) => m.to_bytes(),
            Message::V2(m) => m.to_bytes(),
        }
    }
}

impl Display for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Message::V1(m) => m.fmt(f),
            Message::V2(m) => m.fmt(f),
        }
    }
}

pub struct MessageV1 {
    ip: Ipv4Addr,
    timestamp: u64,
    nonce: [u8; 16],
}

impl MessageV1 {
    pub fn new(ip: Ipv4Addr) -> Self {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            * 1000;
        let mut nonce = [0u8; 16];
        OsRng.fill_bytes(&mut nonce);

        Self {
            ip,
            timestamp: ts,
            nonce,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut payload = vec![0u8; 32];
        payload[..4].copy_from_slice(&1u32.to_be_bytes());
        payload[4..12].copy_from_slice(&self.timestamp.to_be_bytes());
        payload[12..28].copy_from_slice(&self.nonce);
        payload[28..32].copy_from_slice(&self.ip.octets());
        payload
    }
}

impl Display for MessageV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "version 1, ip: {}, ts: {}", self.ip, self.timestamp)
    }
}

pub struct MessageV2 {
    ip: IpAddr,
    timestamp: u64,
    nonce: [u8; 16],
    range: u8,
}

impl MessageV2 {
    pub fn new(ip: IpAddr) -> MessageV2 {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            * 1000;
        let mut nonce = [0u8; 16];
        OsRng.fill_bytes(&mut nonce);

        let range = match ip {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };

        Self {
            ip,
            timestamp: ts,
            nonce,
            range,
        }
    }

    pub fn with_range(mut self, range: u8) -> Self {
        self.range = range;
        self
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut payload = vec![0u8; 46];
        payload[..4].copy_from_slice(&2u32.to_be_bytes());
        payload[4..12].copy_from_slice(&self.timestamp.to_be_bytes());
        payload[12..28].copy_from_slice(&self.nonce);
        payload[28..29].copy_from_slice(&self.family_bytes().to_be_bytes());

        match self.ip {
            IpAddr::V4(v4) => {
                payload[29..33].copy_from_slice(&v4.octets());
                payload[33..34].copy_from_slice(&self.range.to_be_bytes());
            }
            IpAddr::V6(v6) => {
                payload[29..45].copy_from_slice(&v6.octets());
                payload[45..46].copy_from_slice(&self.range.to_be_bytes());
            }
        };

        payload
    }

    fn family_bytes(&self) -> u8 {
        match self.ip {
            IpAddr::V4(_) => 4u8,
            IpAddr::V6(_) => 6u8,
        }
    }
}

impl Display for MessageV2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            r"version 2, ip: {}\{}, ts: {}",
            self.ip, self.range, self.timestamp
        )
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv6Addr;

    use super::*;

    #[test]
    fn message_v1_bytes_starts_with_version() {
        let msg = MessageV1::new(Ipv4Addr::LOCALHOST);

        let bytes = msg.to_bytes();

        assert_eq!(&bytes[..4], &1u32.to_be_bytes());
    }

    #[test]
    fn message_v1_bytes_is_32_long() {
        let msg = MessageV1::new(Ipv4Addr::LOCALHOST);

        assert_eq!(msg.to_bytes().len(), 32)
    }

    #[test]
    fn message_v1_bytes_ip_is_correct() {
        let msg = MessageV1::new(Ipv4Addr::LOCALHOST);

        let bytes = msg.to_bytes();

        assert_eq!(&bytes[28..32], [127, 0, 0, 1])
    }

    #[test]
    fn message_v2_bytes_starts_with_version() {
        let msg = MessageV2::new(IpAddr::V4(Ipv4Addr::LOCALHOST));

        let bytes = msg.to_bytes();
        assert_eq!(&bytes[..4], &2u32.to_be_bytes());
    }

    #[test]
    fn message_v2_bytes_is_46_long() {
        let msg = MessageV2::new(IpAddr::V4(Ipv4Addr::LOCALHOST));

        assert_eq!(msg.to_bytes().len(), 46);
    }

    #[test]
    fn message_v2_bytes_ipv4_is_correct() {
        let msg = MessageV2::new(IpAddr::V4(Ipv4Addr::LOCALHOST));

        let bytes = msg.to_bytes();

        assert_eq!(&bytes[29..33], [127, 0, 0, 1]);
    }

    #[test]
    fn message_v2_bytes_ipv6_is_correct() {
        let msg = MessageV2::new(IpAddr::V6(Ipv6Addr::LOCALHOST));

        let bytes = msg.to_bytes();

        assert_eq!(
            &bytes[29..45],
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
        );
    }

    #[test]
    fn message_v2_bytes_with_range_is_respected() {
        let msg = MessageV2::new(IpAddr::V4(Ipv4Addr::LOCALHOST)).with_range(24);

        let bytes = msg.to_bytes();

        assert_eq!(&bytes[33], &24);
    }

    #[test]
    fn message_v2_bytes_ipv6_default_range() {
        let msg = MessageV2::new(IpAddr::V6(Ipv6Addr::LOCALHOST));

        let bytes = msg.to_bytes();

        assert_eq!(&bytes[45], &128);
    }

    #[test]
    fn message_v2_bytes_ipv4_default_range() {
        let msg = MessageV2::new(IpAddr::V4(Ipv4Addr::LOCALHOST));

        let bytes = msg.to_bytes();

        assert_eq!(&bytes[33], &32);
    }

    #[test]
    fn message_v2_bytes_ipv4_correct_family() {
        let msg = MessageV2::new(IpAddr::V4(Ipv4Addr::LOCALHOST));
        let bytes = msg.to_bytes();

        assert_eq!(&bytes[28], &4)
    }

    #[test]
    fn message_v2_bytes_ipv6_correct_family() {
        let msg = MessageV2::new(IpAddr::V6(Ipv6Addr::LOCALHOST));
        let bytes = msg.to_bytes();

        assert_eq!(&bytes[28], &6)
    }
}
