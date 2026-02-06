use std::{path::PathBuf, sync::Arc};
use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use tracing::{debug, error, info, level_filters::LevelFilter, warn};
use tokio::{net::TcpListener, sync::RwLock};
use tracing_subscriber::EnvFilter;
use std::os::fd::{FromRawFd, RawFd};

use crate::systemd::sd_notify_ready;

mod acl;
mod config;
mod proxy;
mod state;
mod rpc;
mod systemd;

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
    },

    /// Checks the syntax of this ACL file and returns non-zero if there's a parse error while
    /// printing a diagnostic.
    CheckACLSyntax {
        /// Path to the ACL file
        acl_file: PathBuf
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    tracing_subscriber::fmt::fmt()
        .with_env_filter(EnvFilter::builder().with_default_directive(LevelFilter::INFO.into()).from_env_lossy())
        .init();

        match cli.command {
            Commands::CheckACLSyntax { acl_file } => {
               let contents = String::from_utf8_lossy(&std::fs::read(&acl_file).context("while reading ACL file")?).into_owned();
               match acl::parse_acl_rules(&mut contents.as_str()) {
                   Ok(rules) => info!("Parsed {} ACL rules successfully", rules.len()),
                   Err(e) => {
                       error!("Error while parsing the ACL rules:\n{e}");
                       std::process::exit(1);
                   }
               }
            }

            Commands::Daemon { config } => {
                let settings: Arc<config::Settings> = Arc::new(config::init(&config));

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

                if let Err(e) = sd_notify_ready() {
                    warn!("failed to notify systemd about readiness: {e}");
                } else {
                    info!("notified systemd about readiness");
                }

                tokio::try_join!(
                    proxy::start(settings.clone(), state.clone(), tcp_listener),
                    rpc::start(settings.clone(), *rpc_fd),
                )?;

                info!("exiting");
            }
    }

    Ok(())
}
