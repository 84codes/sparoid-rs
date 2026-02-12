use aes::Aes256;
use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, Cbc};
use hmac::{Hmac, Mac, NewMac};
use rand::{RngCore, rngs::OsRng};
use sha2::Sha256;
use tokio::net::UdpSocket;

use crate::message::Message;

type HmacSha256 = Hmac<Sha256>;
type Aes256Cbc = Cbc<Aes256, Pkcs7>;
const AES_BLOCK_SIZE: usize = 16;

pub struct Package {
    content: [u8; 96],
}

pub fn new<'a>(key: &'a [u8; 32], hmac_key: &'a [u8; 32], message: &Message) -> Package {
    let mut iv = [0u8; 16];
    OsRng.fill_bytes(&mut iv);

    let message_bytes = message.to_bytes();

    // Creates a buffer that can hold the message payload and AES padding.
    let buffer_size = message_bytes.len() + AES_BLOCK_SIZE - (message_bytes.len() % AES_BLOCK_SIZE);
    let mut payload = vec![0u8; buffer_size];
    payload[..message_bytes.len()].copy_from_slice(message_bytes.as_slice());

    let cipher = Aes256Cbc::new_from_slices(key, &iv).unwrap();
    let ciphertext = cipher.encrypt(&mut payload, message_bytes.len()).unwrap();

    let mut res = [0u8; 32 + 16 + 32 + 16];
    res[32..48].copy_from_slice(&iv);
    res[48..].copy_from_slice(ciphertext);

    let mut mac = HmacSha256::new_from_slice(hmac_key).expect("HMAC can take key of any size");
    mac.update(&res[32..]);
    let result = mac.finalize();

    res[..32].copy_from_slice(&result.into_bytes());
    Package { content: res }
}

impl Package {
    pub async fn send_to(&self, socket: &UdpSocket) {
        socket.send(&self.content).await.unwrap();
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv6Addr;

    use crate::MessageV2;

    use super::*;

    #[test]
    fn test_hmac_verification() {
        let mut key = [0u8; 32];
        let mut hmac_key = [0u8; 32];

        OsRng.fill_bytes(&mut key);
        OsRng.fill_bytes(&mut hmac_key);

        let msg = Message::V2(MessageV2::new(std::net::IpAddr::V6(Ipv6Addr::LOCALHOST)));

        let package = new(&key, &hmac_key, &msg);

        let mut mac = HmacSha256::new_from_slice(&hmac_key).unwrap();
        mac.update(&package.content[32..]);
        let mac_result = mac.finalize().into_bytes();

        assert_eq!(mac_result.as_slice(), &package.content[..32])
    }

    #[test]
    fn test_decryption_round_trip() {
        let mut key = [0u8; 32];
        let mut hmac_key = [0u8; 32];

        OsRng.fill_bytes(&mut key);
        OsRng.fill_bytes(&mut hmac_key);

        let msg = Message::V2(MessageV2::new(std::net::IpAddr::V6(Ipv6Addr::LOCALHOST)));

        let mut package = new(&key, &hmac_key, &msg);
        let iv = &package.content[32..48];
        // let payload: Vec<u8> = Vec::new();
        // package.content[48..].clone_into(&mut payload);

        let cipher = Aes256Cbc::new_from_slices(&key, &iv).unwrap();
        let decrypted = cipher.decrypt(&mut package.content[48..]).unwrap();
        assert_eq!(decrypted[..4], msg.to_bytes()[..4])
    }

    #[test]
    fn test_package_randomness() {
        let mut key = [0u8; 32];
        let mut hmac_key = [0u8; 32];

        OsRng.fill_bytes(&mut key);
        OsRng.fill_bytes(&mut hmac_key);

        let msg = Message::V2(MessageV2::new(std::net::IpAddr::V6(Ipv6Addr::LOCALHOST)));

        let package1 = new(&key, &hmac_key, &msg);
        let package2 = new(&key, &hmac_key, &msg);

        assert_ne!(package1.content, package2.content)
    }
}
