use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use std::net::SocketAddr;
use std::os::fd::FromRawFd;
use std::{path::PathBuf, sync::Arc};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use crate::logging::LogPreset;
use crate::rpc::fr_gouv_portail_control::{DynamicBackendSpec, GetCurrentBackendOutput};
use crate::systemd::sd_notify_ready;

mod acl;
mod config;
mod logging;
mod metrics;
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
    "/run/fr.gouv.portail.Control".into()
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

    /// Unset the default backend via RPC.
    UnsetDefaultBackend,

    /// List all available backends via RPC.
    ListBackends,

    /// Update a dynamic backend via RPC
    UpdateDynamicBackend {
        /// Identifier of the backend in the settings
        backend_id: String,

        #[arg(long)]
        target_address: SocketAddr,
    },
}

#[derive(ValueEnum, Debug, Clone, Copy)]
pub enum UserLogPreset {
    /// All logs will be printed nicely on stdout (traces) and stderr (errors)
    Development,
    /// Errors will be printed nicely on stderr but traces and errors will be routed into files as
    /// well in /var/log/portail in JSON format
    Systemd,
    /// All traces (errors included) will be printed in JSON format on stdout and stderr
    Container,
}

impl From<UserLogPreset> for LogPreset {
    fn from(value: UserLogPreset) -> Self {
        match value {
            UserLogPreset::Development => Self::Development,
            UserLogPreset::Systemd => Self::Systemd,
            UserLogPreset::Container => Self::Container,
        }
    }
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
        #[arg(long, value_name = "ADDRESS")]
        bind_metrics_address: Option<String>,
        #[arg(long, value_name = "FILE")]
        /// Path where to create the RPC socket if the daemon must create it itself
        bind_rpc_socket: Option<String>,
        /// Preset for logging, defaults to development
        #[arg(long, default_value = "development")]
        log_preset: UserLogPreset,
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
        /// Whether to provide JSON output for scripting.
        #[arg(long, value_name = "BOOLEAN", default_value_t = false)]
        json: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Rpc {
            rpc_socket,
            json,
            command,
        } => {
            let preset = if json {
                LogPreset::Scripting
            } else {
                LogPreset::Cli
            };
            let _guards = logging::init(preset).expect("Failed to initialize logging");

            let mut connection = zlink::unix::connect(&rpc_socket).await.context(format!(
                "Opening the RPC socket at path '{}'",
                rpc_socket.display()
            ))?;

            match command {
                RpcCommands::PrintCurrentBackend => {
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
                    connection
                        .set_default_backend(Some(&backend_id))
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

                RpcCommands::UnsetDefaultBackend => {
                    connection
                        .set_default_backend(None)
                        .await
                        .context("During Varlink low-level communications. Are you using same versions of Portail on both sides?")?
                        .context("Failed to unset default backend")?;

                    if !json {
                        println!("Default backend unset successfully.");
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

                RpcCommands::ListBackends => {
                    let backends = connection
                        .list_backends()
                        .await
                        .context("During Varlink low-level communications. Are you using same versions of Portail on both sides?")?
                        .context("Failed to list backends")?.backends;

                    if !json {
                        println!("List of backends:");
                        for backend in backends {
                            if backend.current {
                                println!("\t{} (active)", backend.id);
                            } else {
                                println!("\t{}", backend.id);
                            }
                        }
                    } else {
                        serde_json::to_writer(std::io::stdout(), &serde_json::json!(backends))
                            .context("While writing JSON")?;
                    }
                }

                RpcCommands::UpdateDynamicBackend {
                    backend_id,
                    target_address,
                } => {
                    let mut connection = zlink::unix::connect(&rpc_socket).await.context(
                        format!("Opening the RPC socket at path '{}'", rpc_socket.display()),
                    )?;
                    connection
                        .update_dynamic_backend(&backend_id, DynamicBackendSpec {
                            target_address: format!("{}", target_address),
                            identity_aware: false,
                            tls_server_name: None
                        })
                        .await
                        .context("During Varlink low-level communications. Are you using same versions of Portail on both sides?")?
                        .context("Failed to update the dynamic backend")?;

                    if !json {
                        println!("Backend updated.");
                    } else {
                        serde_json::to_writer(
                            std::io::stdout(),
                            &serde_json::json!({"success": true}),
                        )
                        .context("While writing JSON")?;
                    }
                }
            }
        }

        Commands::Daemon {
            config,
            bind_proxy_address,
            bind_metrics_address,
            bind_rpc_socket,
            log_preset,
        } => {
            let _guards = logging::init(log_preset.into()).expect("Failed to initialize logging");
            info!("Reading Portail settings from '{}'", config.display());
            let settings: Arc<config::Settings> = Arc::new(config::init(&config));

            let state: Arc<RwLock<state::State>> = Arc::new(RwLock::new(
                state::init(&settings).context("While initializing application state")?,
            ));

            debug!("Loaded Portail settings and state");

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

            let metrics_listener = if let Some(metrics_address) = bind_metrics_address {
                tokio::net::TcpListener::bind(metrics_address).await?
            } else {
                let metrics_fd = fds_named
                    .get("metrics")
                    .ok_or_else(|| anyhow::anyhow!("missing metrics socket fd"))?;

                let std = unsafe { std::net::TcpListener::from_raw_fd(*metrics_fd) };
                std.set_nonblocking(true)?;
                tokio::net::TcpListener::from_std(std)?
            };

            info!("Starting services");

            let (proxy_fut, rpc_fut, metrics_fut) = (
                proxy::start(settings.clone(), state.clone(), tcp_listener),
                rpc::start(settings.clone(), state.clone(), rpc_listener),
                metrics::serve(settings.clone(), state.clone(), metrics_listener),
            );

            if let Err(e) = sd_notify_ready() {
                warn!("Failed to notify systemd about readiness: {e}");
            } else {
                debug!("Notified systemd about readiness");
            }

            info!("Services are ready.");

            tokio::try_join!(proxy_fut, rpc_fut, metrics_fut)?;

            info!("Exiting...");
        }
        Commands::CheckACLSyntax {
            config,
            json,
            acl_file,
        } => {
            let preset = if json {
                LogPreset::Scripting
            } else {
                LogPreset::Cli
            };
            let guards = logging::init(preset).expect("Failed to initialize logging");
            let contents = String::from_utf8_lossy(
                &std::fs::read(&acl_file).context("while reading ACL file")?,
            )
            .into_owned();
            let settings: Arc<config::Settings> = Arc::new(config::init(&config));
            match acl::load_rules_from_str(contents.as_str(), &settings) {
                Ok(rules) => info!(
                    n_policies = %rules.hir.policies.len(),
                    n_routes = %rules.hir.routes.len(),
                    "Parsed ACL policies and routes successfully",
                ),
                Err(err) => {
                    error!("Error while parsing the ACL rules:\n{err}");
                    drop(guards);
                    std::process::exit(1);
                }
            }
        }
    }

    Ok(())
}
