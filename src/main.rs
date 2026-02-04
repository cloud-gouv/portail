use std::sync::Arc;
use anyhow::{bail, Result};
use tracing::{info, debug};
use tokio::{net::TcpListener, sync::RwLock};
use tracing_subscriber::EnvFilter;
use std::os::fd::{FromRawFd, RawFd};

mod acl;
mod config;
mod proxy;
mod state;
mod rpc;
mod systemd;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let settings: Arc<config::Settings> = Arc::new(config::init());
    let state: Arc<RwLock<state::State>> = Arc::new(RwLock::new(state::init(&settings)));

    let fds_named = systemd::listen_fds_named();

    let tcp_fd = fds_named.get("proxy")
        .ok_or_else(|| anyhow::anyhow!("missing tcp socket"))?;
    let rpc_fd = fds_named.get("control")
        .ok_or_else(|| anyhow::anyhow!("missing rpc socket"))?;

    let std = unsafe { std::net::TcpListener::from_raw_fd(*tcp_fd) };
    std.set_nonblocking(true)?;
    let tcp_listener = tokio::net::TcpListener::from_std(std)?;
    info!("starting services");

    tokio::try_join!(
        proxy::start(settings.clone(), state.clone(), tcp_listener),
        rpc::start(settings.clone(), *rpc_fd),
    )?;

    info!("exiting");

    Ok(())
}
