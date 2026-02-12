use anyhow::Result;
use clap::{Parser, Subcommand};
use std::os::fd::FromRawFd;
use std::{path::PathBuf, sync::Arc};
use tokio::sync::RwLock;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use crate::systemd::sd_notify_ready;

mod acl;
mod config;
mod proxy;
mod rpc;
mod state;
mod systemd;
mod pkcs11;

#[derive(Parser)]
#[command(name = "Portail")]
#[command(about = "An access proxy for terminals", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

fn get_default_config_path() -> PathBuf {
    "/etc/portail.toml".into()
}

#[derive(Subcommand)]
enum Commands {
    /// Run the portail daemon
    /// Currently, it expect socket activation.
    Daemon {
        #[arg(short, long, default_value = get_default_config_path().into_os_string(), value_name = "FILE")]
        /// Path to the configuration file
        config: PathBuf,
        #[arg(long, value_name = "ADDRESS")]
        /// Address to bind the proxy to when the daemon must create the socket itself
        bind_proxy_address: Option<String>,
        #[arg(long, value_name = "FILE")]
        /// Path where to create the RPC socket if the daemon must create it itself
        bind_rpc_socket: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    tracing_subscriber::fmt::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    match cli.command {
        Commands::Daemon {
            config,
            bind_proxy_address,
            bind_rpc_socket,
        } => {
            let settings: Arc<config::Settings> = Arc::new(config::init(&config));

            let state: Arc<RwLock<state::State>> = Arc::new(RwLock::new(state::init(&settings)));

            let fds_named = systemd::listen_fds_named();

            let tcp_listener = if let Some(proxy_address) = bind_proxy_address {
                tokio::net::TcpListener::bind(proxy_address).await?
            } else {
                let tcp_fd = fds_named
                    .get("proxy")
                    .ok_or_else(|| anyhow::anyhow!("missing tcp socket fd"))?;

                let std = unsafe { std::net::TcpListener::from_raw_fd(*tcp_fd) };
                std.set_nonblocking(true)?;
                tokio::net::TcpListener::from_std(std)?
            };

            let rpc_listener = if let Some(rpc_socket) = bind_rpc_socket {
                tokio::net::UnixListener::bind(rpc_socket)?
            } else {
                let rpc_fd = fds_named
                    .get("control")
                    .ok_or_else(|| anyhow::anyhow!("missing rpc socket fd"))?;

                let std = unsafe { std::os::unix::net::UnixListener::from_raw_fd(*rpc_fd) };
                std.set_nonblocking(true)?;
                tokio::net::UnixListener::from_std(std)?
            };

            info!("starting services");

            if let Err(e) = sd_notify_ready() {
                warn!("failed to notify systemd about readiness: {e}");
            } else {
                info!("notified systemd about readiness");
            }

            tokio::try_join!(
                proxy::start(settings.clone(), state.clone(), tcp_listener),
                rpc::start(settings.clone(), rpc_listener),
            )?;

            info!("exiting");
        }
    }

    Ok(())
}
