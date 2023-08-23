use clap::{Parser, Subcommand};
use ini::Ini;

/// This doc string acts as a help message when the user runs '--help'
/// as do all doc strings on fields
#[derive(Parser)]
#[command(version = "1.0", author = "Magnus L. <mange@84codes.com>")]
struct Opts {
    /// A level of verbosity, and can be used multiple times
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: i32,

    #[command(subcommand)]
    subcmd: SubCommand,

    /// Config file for sparoid
    #[arg(long, short, default_value = "~/.sparoid.ini")]
    config_file: String,
}

#[derive(Subcommand)]
enum SubCommand {
    #[arg()]
    Send(Connect),
}

/// Configuration
#[derive(Parser, Debug)]
struct Connect {
    /// Host to send package to
    #[arg(long)]
    host: String,
    /// Port on which to send package to
    #[arg(long, default_value = "8484")]
    port: u16,
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
            let package = sparoid::new(&key, &hmac_key).await;
            package.send_to(&o.host, o.port).await;
        }
    }
}
