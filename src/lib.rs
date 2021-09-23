use aes::Aes256;
use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, Cbc};
use dnsclient::r#async::DNSClient;
use hmac::{Hmac, Mac, NewMac};
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;
use std::net::Ipv4Addr;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;

type HmacSha256 = Hmac<Sha256>;
type Aes256Cbc = Cbc<Aes256, Pkcs7>;

async fn public_ip(hostname: &str) -> std::io::Result<Vec<Ipv4Addr>> {
    let servers = vec![
        dnsclient::UpstreamServer::new(([208, 67, 220, 222], 53)),
        dnsclient::UpstreamServer::new(([208, 67, 222, 222], 53)),
        dnsclient::UpstreamServer::new(([208, 67, 220, 220], 53)),
    ];
    let client = DNSClient::new(servers);
    client.query_a(hostname).await
}

pub struct Package {
    content: [u8; 96],
}

pub async fn new<'a>(key: &'a [u8; 32], hmac_key: &'a [u8; 32]) -> Package {
    let mut iv = [0u8; 16];
    OsRng.fill_bytes(&mut iv);

    let my_ip = public_ip("myip.opendns.com.").await.unwrap();
    let data: [u8; 4] = my_ip[0].octets();
    let mut payload = [0u8; 64];
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        * 1000;
    let mut nounce = [0u8; 16];
    OsRng.fill_bytes(&mut nounce);
    payload[..4].copy_from_slice(&1u32.to_be_bytes());
    payload[4..12].copy_from_slice(&ts.to_be_bytes());
    payload[12..28].copy_from_slice(&nounce);
    payload[28..32].copy_from_slice(&data);

    let cipher = Aes256Cbc::new_from_slices(key, &iv).unwrap();
    let ciphertext = cipher.encrypt(&mut payload, 32).unwrap();

    let mut res = [0u8; 32 + 16 + 32 + 16];
    res[32..48].copy_from_slice(&iv);
    res[48..].copy_from_slice(ciphertext);

    let mut mac = HmacSha256::new_from_slice(hmac_key).expect("HMAC can take key of any size");
    mac.update(&res[32..]);
    let result = mac.finalize();

    res[..32].copy_from_slice(&result.into_bytes());
    Package { content: res }
}

impl<'a> Package {
    pub async fn send_to(&self, host: &'a str, port: u16) {
        let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
            .await
            .expect("couldn't bind to address");
        let ips = if host == "127.0.0.1" || host == "localhost" {
            vec![[127, 0, 0, 1].into()]
        } else {
            public_ip(host).await.unwrap()
        };
        for ip in ips {
            socket.send_to(&self.content, (ip, port)).await.unwrap();
        }
    }
}
