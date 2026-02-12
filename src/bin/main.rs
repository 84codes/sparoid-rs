use clap::{Args, Parser, Subcommand};
use ini::Ini;
use nix::sys::socket::{ControlMessage, MsgFlags, sendmsg};
use sparoid::{Message, MessageV1, MessageV2, public_ipv6_with_range};
use std::{
    fmt::Debug,
    io::IoSlice,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    os::fd::{AsRawFd, RawFd},
    process::exit,
};
use tokio::net::{TcpSocket, UdpSocket};

/// This doc string acts as a help message when the user runs '--help'
/// as do all doc strings on fields
#[derive(Parser)]
#[command(version = "1.0", author = "Magnus L. <mange@84codes.com>")]
struct Opts {
    /// A level of verbosity, and can be used multiple times
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    #[command(subcommand)]
    subcmd: SubCommand,

    /// Config file for sparoid
    #[arg(long, short, default_value = "~/.sparoid.ini")]
    config_file: String,
}

#[derive(Subcommand)]
enum SubCommand {
    #[arg()]
    Send(Send),
    Connect(Connect),
}

#[derive(Args, Debug)]
struct HostConfig {
    /// Host to send package to
    #[arg(long)]
    host: String,
    /// Port on which to send package to
    #[arg(long, default_value = "8484")]
    port: u16,
}

/// Send a SPA packet to the specified host
#[derive(Parser, Debug)]
struct Send {
    #[command(flatten)]
    config: HostConfig,
}

/// Sends a SPA packet to the specified host and opens a tcp connection
/// to the host and passes the TCP fd back to the calling parent.
#[derive(Parser, Debug)]
struct Connect {
    #[command(flatten)]
    config: HostConfig,

    // Destination port to connect to
    #[arg(long)]
    tcp_port: u16,
}

fn find_secrets(opts: &Opts, key: &mut [u8; 32], hmac_key: &mut [u8; 32]) {
    let real_path = shellexpand::full(&opts.config_file).unwrap().to_string();
    let p = std::path::Path::new(&real_path);
    let i = Ini::load_from_file(p).unwrap();
    for (_, prop) in i.iter() {
        for (k, v) in prop.iter() {
            if k == "key" {
                hex::decode_to_slice(v, key).unwrap();
            } else if k == "hmac-key" {
                hex::decode_to_slice(v, hmac_key).unwrap();
            }
        }
    }
}

#[tokio::main]
async fn main() {
    let opts: Opts = Opts::parse();
    let mut key = [0u8; 32];
    let mut hmac_key = [0u8; 32];
    find_secrets(&opts, &mut key, &mut hmac_key);
    match opts.subcmd {
        SubCommand::Send(o) => {
            send(o.config, &key, &hmac_key).await;
            return;
        }
        SubCommand::Connect(o) => {
            connect(o, &key, &hmac_key).await;
            return;
        }
    }
}

async fn send(config: HostConfig, key: &[u8; 32], hmac_key: &[u8; 32]) -> Vec<SocketAddr> {
    let host_addrs: Vec<SocketAddr> =
        tokio::net::lookup_host(format!("{}:{}", config.host, config.port))
            .await
            .unwrap()
            .collect();
    let my_ips = sparoid::public_ip().await.unwrap();

    let global_ipv6s = public_ipv6_with_range();

    for addr in host_addrs.iter() {
        let mut ipv6_added = false;
        let socket = match addr.ip() {
            IpAddr::V4(_) => &UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
                .await
                .expect("couldn't bind to address"),
            IpAddr::V6(_) => &UdpSocket::bind((Ipv6Addr::UNSPECIFIED, 0))
                .await
                .expect("couldn't bind to address"),
        };

        let mut messages = Vec::new();
        for ip in &global_ipv6s {
            messages.push(Message::V2(
                MessageV2::new(IpAddr::V6(ip.ip)).with_range(ip.range),
            ));
            ipv6_added = true;
        }

        socket.connect(addr).await.unwrap();

        for ip in &my_ips {
            if let IpAddr::V4(v4) = ip {
                messages.push(Message::V1(MessageV1::new(*v4)));
            }

            if let IpAddr::V6(_v6) = ip
                && ipv6_added
            {
                continue;
            }

            messages.push(Message::V2(MessageV2::new(*ip)));
        }

        for message in messages {
            let package = sparoid::new(key, hmac_key, &message);
            package.send_to(socket).await;
        }
    }
    host_addrs
}

async fn connect(o: Connect, key: &[u8; 32], hmac_key: &[u8; 32]) {
    let addrs = send(o.config, key, hmac_key).await;

    for mut addr in addrs {
        let socket = match addr.ip() {
            IpAddr::V4(_v4) => TcpSocket::new_v4(),
            IpAddr::V6(_v6) => TcpSocket::new_v6(),
        }
        .unwrap();

        addr.set_port(o.tcp_port);
        let stream = socket.connect(addr).await;
        if let Ok(s) = stream {
            let passed = pass_fd_to_parent(s.as_raw_fd());
            if passed.is_ok() {
                exit(0)
            } else {
                println!("Could not pass FD to parent {:?}", passed.err())
            }
        }
    }
    exit(1)
}

fn pass_fd_to_parent(fd: RawFd) -> nix::Result<()> {
    let socket_fd = 1;

    let payload = [b'\0'];
    let iov = [IoSlice::new(&payload)];

    let fds = [fd];

    let cmsgs = [ControlMessage::ScmRights(&fds)];

    let _ = sendmsg::<()>(socket_fd, &iov, &cmsgs, MsgFlags::empty(), None)?;

    Ok(())
}
