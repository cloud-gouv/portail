//! This example multiplexes CONNECT streams to the proxy:
//! - one HTTPS proxy connection (HTTP/2 + ALPN `h2`)
//! - many concurrent CONNECT tunnels multiplexed inside the proxy connection
//!
//! See https://github.com/hyperium/hyper/blob/0d6c7d5469baa09e2fb127ee3758a79b3271a4f0/tests/server.rs#L2051
//!
//! This mimics the following curl command but guarantees that the two requests are multiplexed inside the proxy connection:
//! curl --proxy-http2 --parallel --proxy <proxy_url> -o out1 -o out2 <url_out1> <url_out2>

use anyhow::{Context, Result, anyhow};
use bytes::Bytes;
use clap::Parser;
use http_body_util::{BodyExt, Empty};
use hyper::client::conn::http2;
use hyper::{Request, StatusCode, Uri};
use hyper_util::rt::{TokioExecutor, TokioIo};
use serde_json::Value;
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::{self, ClientConfig, pki_types::ServerName};

#[derive(Parser, Debug)]
#[command(name = "h2-proxy-multiplex")]
struct Args {
    #[arg(long)]
    proxy: String,
    #[arg(long, action = clap::ArgAction::Append, required = true)]
    url: Vec<String>,
}

fn load_roots() -> Result<rustls::RootCertStore> {
    // For e2e tests, we need to inject certificates.
    let path = "/etc/ssl/certs/ca-certificates.crt";
    let mut reader = BufReader::new(File::open(&path).with_context(|| format!("open {path}"))?);
    let mut roots = rustls::RootCertStore::empty();
    let certs: Vec<_> = rustls_pemfile::certs(&mut reader)
        .collect::<std::result::Result<_, _>>()
        .context("parse PEM")?;
    for c in certs {
        roots.add(c)?;
    }
    if roots.is_empty() {
        return Err(anyhow!("no CA certificates in {path}"));
    }
    Ok(roots)
}

fn client_config(roots: rustls::RootCertStore, alpn: Vec<Vec<u8>>) -> Arc<ClientConfig> {
    let mut config = ClientConfig::builder()
        .with_root_certificates(Arc::new(roots))
        .with_no_client_auth();
    config.alpn_protocols = alpn;
    Arc::new(config)
}

/// Send CONNECT through the send channel, then create a TLS connection to the target and send a GET request
async fn fetch_through_tunnel(
    mut send: hyper::client::conn::http2::SendRequest<Empty<Bytes>>,
    target_url: &str,
    target_cfg: Arc<ClientConfig>,
) -> Result<Value> {
    let target_uri: Uri = target_url
        .parse()
        .with_context(|| format!("parse url: {target_url}"))?;
    if target_uri.scheme_str() != Some("https") {
        return Err(anyhow!("only https:// urls are supported"));
    }
    let target_host = target_uri
        .host()
        .ok_or_else(|| anyhow!("missing host: {target_url}"))?
        .to_string();
    let target_port = target_uri.port_u16().unwrap_or(443);

    // CONNECT request to the proxy through the send channel
    let connect_req = Request::connect(&format!("{target_host}:{target_port}"))
        .body(Empty::<Bytes>::new())
        .map_err(|e| anyhow!("CONNECT request: {e}"))?;

    send.ready()
        .await
        .map_err(|e| anyhow!("proxy connection: {e}"))?;
    let mut resp = send
        .send_request(connect_req)
        .await
        .map_err(|e| anyhow!("CONNECT send: {e}"))?;
    if resp.status() != StatusCode::OK {
        return Err(anyhow!("CONNECT failed with {}", resp.status()));
    }

    // This is the usual ceremony to get the subsequent stream
    let upgraded = hyper::upgrade::on(&mut resp)
        .await
        .map_err(|e| anyhow!("CONNECT upgrade: {e}"))?;
    let io = TokioIo::new(upgraded);

    let connector = TlsConnector::from(target_cfg);
    let name = ServerName::try_from(target_host.clone()).map_err(|_| anyhow!("invalid SNI"))?;
    let tls = connector
        .connect(name, io)
        .await
        .map_err(|e| anyhow!("TLS to target: {e}"))?;

    let target_io = TokioIo::new(tls);
    let (mut target_send, target_connection) = http2::handshake(TokioExecutor::new(), target_io)
        .await
        .map_err(|e| anyhow!("HTTP/2 to target: {e}"))?;
    tokio::spawn(async move {
        let _ = target_connection.await;
    });

    // GET request to the target
    let req = Request::get(target_uri)
        .header("host", &target_host)
        .body(Empty::<Bytes>::new())
        .map_err(|e| anyhow!("GET request: {e}"))?;

    target_send
        .ready()
        .await
        .map_err(|e| anyhow!("target connection not ready: {e}"))?;
    let mut resp = target_send
        .send_request(req)
        .await
        .map_err(|e| anyhow!("GET send: {e}"))?;
    if !resp.status().is_success() {
        return Err(anyhow!("GET failed with {}", resp.status()));
    }

    let body = resp
        .body_mut()
        .collect()
        .await
        .map_err(|e| anyhow!("read body: {e}"))?
        .to_bytes();
    serde_json::from_slice(&body).with_context(|| format!("json: {target_url}"))
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let args = Args::parse();
    if args.url.len() < 2 {
        return Err(anyhow!("need at least two --url values for multiplexing"));
    }

    let roots = load_roots()?;
    let proxy_cfg = client_config(roots.clone(), vec![b"h2".to_vec()]);
    let target_cfg = client_config(roots, vec![b"h2".to_vec(), b"http/1.1".to_vec()]);

    let proxy_uri: Uri = args.proxy.parse().context("parse --proxy")?;
    let proxy_host = proxy_uri
        .host()
        .ok_or_else(|| anyhow!("proxy URL missing host"))?
        .to_string();
    let proxy_port = proxy_uri.port_u16().unwrap_or(443);
    let proxy_sni = ServerName::try_from(proxy_host.clone()).map_err(|_| anyhow!("proxy SNI"))?;

    let tcp = TcpStream::connect((proxy_host, proxy_port))
        .await
        .context("TCP to proxy")?;
    let connector = TlsConnector::from(proxy_cfg);
    let tls = connector
        .connect(proxy_sni, tcp)
        .await
        .context("TLS to proxy")?;

    let io = TokioIo::new(tls);
    let (send, connection) = http2::handshake(TokioExecutor::new(), io)
        .await
        .context("HTTP/2 handshake to proxy")?;
    tokio::spawn(async move {
        let _ = connection.await;
    });

    let combined: Vec<Value> = futures_util::future::try_join_all(args.url.iter().map(|url| {
        let send = send.clone();
        let cfg = target_cfg.clone();
        let url = url.clone();
        async move { fetch_through_tunnel(send, url.as_str(), cfg).await }
    }))
    .await?;

    println!("{}", serde_json::to_string(&combined)?);

    Ok(())
}
