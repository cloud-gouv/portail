//! This example sends a single SOCKS5 UDP ASSOCIATE datagram through a proxy.

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::Result;
use clap::Parser;
use fast_socks5::client::Socks5Datagram;
use tokio::net::TcpStream;
use tokio::time::sleep;

#[derive(Parser, Debug)]
#[command(name = "socks5-udp")]
struct Args {
    #[arg(long)]
    proxy: SocketAddr,

    /// UDP datagram destination host.
    #[arg(long)]
    host: String,

    /// UDP datagram destination port.
    #[arg(long)]
    port: u16,

    #[arg(long)]
    payload: String,

    /// Time to keep the TCP control connection open after sending the datagram.
    #[arg(long, default_value_t = 500)]
    wait_before_closing_ms: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let control = TcpStream::connect(args.proxy).await?;

    let datagram = Socks5Datagram::bind(control, "[::]:0").await?;

    datagram
        .send_to(args.payload.as_bytes(), (args.host.as_str(), args.port))
        .await?;

    sleep(Duration::from_millis(args.wait_before_closing_ms)).await;

    Ok(())
}
