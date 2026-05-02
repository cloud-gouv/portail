use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::os::fd::FromRawFd;
use std::{path::PathBuf, sync::Arc};
use tokio::runtime::Handle;
use tokio::sync::RwLock;
use tracing::{error, level_filters::LevelFilter};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use crate::rpc::fr_gouv_portail_control::GetCurrentBackendOutput;
use crate::systemd::sd_notify_ready;

mod acl;
mod config;
mod proxy;
mod rpc;
mod state;
mod systemd;

use rpc::fr_gouv_portail_control::Control;

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

fn get_default_socket_path() -> PathBuf {
    "/run/portail/fr.gouv.portail.Control".into()
}

fn log_tokio_runtime_flavor() {
    let handle = Handle::current();
    let workers = handle.metrics().num_workers();
    let flavor = handle.runtime_flavor();
    info!("tokio runtime: {flavor:?} flavor ({workers} workers)");
}

#[derive(Subcommand)]
enum RpcCommands {
    /// Print default backend via RPC
    PrintCurrentBackend,

    /// Change the current default backend via RPC.
    SetDefaultBackend {
        /// Identifier of the backend in the settings
        backend_id: String,
    },
}

#[derive(Subcommand)]
enum Commands {
    /// Run the portail daemon.
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

    /// Run RPC commands to the daemon.
    Rpc {
        /// Path to the Varlink RPC socket.
        #[arg(long, value_name = "SOCKET", default_value = get_default_socket_path().into_os_string())]
        rpc_socket: PathBuf,

        /// Whether to provide JSON output for scripting.
        #[arg(long, value_name = "BOOLEAN", default_value_t = false)]
        json: bool,

        /// RPC command.
        #[clap(subcommand)]
        command: RpcCommands,
    },

    /// Checks the syntax of this ACL file and returns non-zero if there's a parse error while
    /// printing a diagnostic.
    CheckACLSyntax {
        #[arg(short, long, default_value = get_default_config_path().into_os_string(), value_name = "FILE")]
        /// Path to the configuration file
        config: PathBuf,
        /// Path to the ACL file
        acl_file: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    tracing_subscriber::fmt::fmt()
        .with_env_filter(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .init();

    log_tokio_runtime_flavor();

    match cli.command {
        Commands::Rpc {
            rpc_socket,
            json,
            command,
        } => {
            match command {
                RpcCommands::PrintCurrentBackend => {
                    let mut connection = zlink::unix::connect(&rpc_socket).await.context(
                        format!("Opening the RPC socket at path '{}'", rpc_socket.display()),
                    )?;

                    let cur_backend = connection
                            .get_current_backend()
                            .await
                            .context("During Varlink low-level communications. Are you using same versions of Portail on both sides?")?
                            .context("Failed to get current backend")?
                            .backend_id;

                    if !json {
                        println!("Current backend: {}", cur_backend);
                    } else {
                        serde_json::to_writer(
                            std::io::stdout(),
                            &GetCurrentBackendOutput {
                                backend_id: cur_backend,
                            },
                        )
                        .context("While writing JSON")?;
                    }
                }

                RpcCommands::SetDefaultBackend { backend_id } => {
                    let mut connection = zlink::unix::connect(&rpc_socket).await.context(
                        format!("Opening the RPC socket at path '{}'", rpc_socket.display()),
                    )?;

                    connection
                        .set_default_backend(&backend_id)
                        .await
                        .context("During Varlink low-level communications. Are you using same versions of Portail on both sides?")?
                        .context("Failed to set default backend")?;

                    if !json {
                        println!("Default backend changed successfully.");
                    } else {
                        serde_json::to_writer(
                            std::io::stdout(),
                            &serde_json::json!({
                                "success": true
                            }),
                        )
                        .context("While writing JSON")?;
                    }
                }
            }
        }

        Commands::Daemon {
            config,
            bind_proxy_address,
            bind_rpc_socket,
        } => {
            let settings: Arc<config::Settings> = Arc::new(config::init(&config));

            let state: Arc<RwLock<state::State>> = Arc::new(RwLock::new(
                state::init(&settings).context("While initializing application state")?,
            ));

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
                rpc::start(settings.clone(), state.clone(), rpc_listener),
            )?;

            info!("exiting");
        }
        Commands::CheckACLSyntax { config, acl_file } => {
            let contents = String::from_utf8_lossy(
                &std::fs::read(&acl_file).context("while reading ACL file")?,
            )
            .into_owned();
            let settings: Arc<config::Settings> = Arc::new(config::init(&config));
            match acl::load_rules_from_str(contents.as_str(), &settings) {
                Ok(rules) => info!(
                    "Parsed {} ACL policies and {} routes successfully",
                    rules.hir.policies.len(),
                    rules.hir.routes.len()
                ),
                Err(err) => {
                    error!("Error while parsing the ACL rules:\n{err}");
                    std::process::exit(1);
                }
            }
        }
    }

    Ok(())
}
