use std::{collections::HashMap, fs::OpenOptions, path::PathBuf};

use anyhow::Context;
use clap::ValueEnum;
use tracing::level_filters::LevelFilter;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{
    EnvFilter, Layer, Registry,
    filter::FilterExt,
    layer::{Filter, SubscriberExt},
    util::SubscriberInitExt,
};

#[derive(Debug, Clone)]
pub enum LogFormat {
    #[allow(dead_code)]
    Full,
    Compact,
    Pretty,
    Json,
}

#[derive(Debug, Clone)]
pub struct LogRoute {
    format: LogFormat,
    output: LogOutput,
}

#[derive(Debug, Clone)]
pub struct LogConfig {
    routes: Vec<LogRoute>,
}

#[derive(Debug, Clone, PartialEq, Hash)]
pub enum LogOutput {
    Stdout,
    Stderr,
    File(PathBuf),
    #[allow(dead_code)]
    Journald,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Subsystem {
    /// All log entries related to the proxy (access logs)
    ProxyAccess,
    /// All log entries related to the proxy (error logs)
    ProxyErrors,
    /// All log entries related to the RPC
    Rpc,
    /// All log entries related to everything else
    System,
}

impl std::str::FromStr for Subsystem {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "proxy_access" => Ok(Self::ProxyAccess),
            "proxy_errors" => Ok(Self::ProxyErrors),
            "rpc" => Ok(Self::Rpc),
            _ => Ok(Self::System),
        }
    }
}

#[derive(Clone)]
pub struct SubsystemFilter {
    destination: Subsystem,
}

impl SubsystemFilter {
    pub fn new(destination: Subsystem) -> Self {
        Self { destination }
    }
}

impl<S> Filter<S> for SubsystemFilter {
    fn enabled(
        &self,
        _metadata: &tracing::Metadata<'_>,
        _ctx: &tracing_subscriber::layer::Context<'_, S>,
    ) -> bool {
        true
    }

    fn event_enabled(
        &self,
        event: &tracing::Event<'_>,
        _ctx: &tracing_subscriber::layer::Context<'_, S>,
    ) -> bool {
        let mut visitor = SubsystemVisitor::default();
        event.record(&mut visitor);

        visitor.subsystem.unwrap_or(Subsystem::System) == self.destination
    }
}

#[derive(Default)]
struct SubsystemVisitor {
    pub subsystem: Option<Subsystem>,
}

const SUBSYSTEM_ROUTING_FIELD: &str = "subsystem";

impl tracing::field::Visit for SubsystemVisitor {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == SUBSYSTEM_ROUTING_FIELD {
            self.subsystem = value.parse().ok();
        }
    }

    fn record_debug(&mut self, _field: &tracing::field::Field, _value: &dyn std::fmt::Debug) {}
}

#[derive(ValueEnum, Debug, Clone, Copy)]
pub enum LogPreset {
    /// Logs are all compact, printed on stdout (traces) and stderr (errors)
    Cli,
    /// Logs are all compact, printed on stdout (traces) and stderr (errors) with JSON output
    Scripting,
    /// All logs will be printed nicely on stdout (traces) and stderr (errors)
    Development,
    /// Errors will be printed nicely on stderr but traces and errors will be routed into files as
    /// well in /var/log/portail in JSON format
    Systemd,
    /// All traces (errors included) will be printed in JSON format on stdout and stderr
    Container,
}

fn preset_to_config(preset: LogPreset) -> HashMap<Subsystem, LogConfig> {
    match preset {
        LogPreset::Cli => {
            let stdout = LogRoute {
                format: LogFormat::Compact,
                output: LogOutput::Stdout,
            };
            let stderr = LogRoute {
                format: LogFormat::Compact,
                output: LogOutput::Stderr,
            };

            [
                (
                    Subsystem::ProxyAccess,
                    LogConfig {
                        routes: vec![stdout.clone()],
                    },
                ),
                (
                    Subsystem::ProxyErrors,
                    LogConfig {
                        routes: vec![stderr],
                    },
                ),
                (
                    Subsystem::Rpc,
                    LogConfig {
                        routes: vec![stdout.clone()],
                    },
                ),
                (
                    Subsystem::System,
                    LogConfig {
                        routes: vec![stdout],
                    },
                ),
            ]
            .into()
        }
        LogPreset::Scripting => {
            let stdout = LogRoute {
                format: LogFormat::Json,
                output: LogOutput::Stdout,
            };
            let stderr = LogRoute {
                format: LogFormat::Json,
                output: LogOutput::Stderr,
            };

            [
                (
                    Subsystem::ProxyAccess,
                    LogConfig {
                        routes: vec![stdout.clone()],
                    },
                ),
                (
                    Subsystem::ProxyErrors,
                    LogConfig {
                        routes: vec![stderr],
                    },
                ),
                (
                    Subsystem::Rpc,
                    LogConfig {
                        routes: vec![stdout.clone()],
                    },
                ),
                (
                    Subsystem::System,
                    LogConfig {
                        routes: vec![stdout],
                    },
                ),
            ]
            .into()
        }
        LogPreset::Development => {
            let stdout = LogRoute {
                format: LogFormat::Pretty,
                output: LogOutput::Stdout,
            };
            let stderr = LogRoute {
                format: LogFormat::Pretty,
                output: LogOutput::Stderr,
            };

            [
                (
                    Subsystem::ProxyAccess,
                    LogConfig {
                        routes: vec![stdout.clone()],
                    },
                ),
                (
                    Subsystem::ProxyErrors,
                    LogConfig {
                        routes: vec![stderr],
                    },
                ),
                (
                    Subsystem::Rpc,
                    LogConfig {
                        routes: vec![stdout.clone()],
                    },
                ),
                (
                    Subsystem::System,
                    LogConfig {
                        routes: vec![stdout],
                    },
                ),
            ]
            .into()
        }
        LogPreset::Systemd => {
            let paccess_file = LogRoute {
                format: LogFormat::Json,
                output: LogOutput::File("/var/log/portail/access.log".into()),
            };

            let perror_file = LogRoute {
                format: LogFormat::Json,
                output: LogOutput::File("/var/log/portail/error.log".into()),
            };

            let rpc_file = LogRoute {
                format: LogFormat::Json,
                output: LogOutput::File("/var/log/portail/rpc.log".into()),
            };

            let stderr = LogRoute {
                format: LogFormat::Pretty,
                output: LogOutput::Stderr,
            };

            [
                (
                    Subsystem::ProxyAccess,
                    LogConfig {
                        routes: vec![paccess_file],
                    },
                ),
                (
                    Subsystem::ProxyErrors,
                    LogConfig {
                        routes: vec![stderr.clone(), perror_file],
                    },
                ),
                (
                    Subsystem::Rpc,
                    LogConfig {
                        routes: vec![rpc_file],
                    },
                ),
                (
                    Subsystem::System,
                    LogConfig {
                        routes: vec![stderr],
                    },
                ),
            ]
            .into()
        }
        LogPreset::Container => {
            let stderr = LogRoute {
                format: LogFormat::Json,
                output: LogOutput::Stderr,
            };

            let stdout = LogRoute {
                format: LogFormat::Json,
                output: LogOutput::Stdout,
            };

            [
                (
                    Subsystem::ProxyAccess,
                    LogConfig {
                        routes: vec![stdout.clone()],
                    },
                ),
                (
                    Subsystem::ProxyErrors,
                    LogConfig {
                        routes: vec![stderr.clone()],
                    },
                ),
                (
                    Subsystem::Rpc,
                    LogConfig {
                        routes: vec![stdout],
                    },
                ),
                (
                    Subsystem::System,
                    LogConfig {
                        routes: vec![stderr],
                    },
                ),
            ]
            .into()
        }
    }
}

fn create_layer_for_route(
    subsystem: Subsystem,
    route: &LogRoute,
) -> Result<(Box<dyn Layer<Registry> + Send + Sync>, WorkerGuard), std::io::Error> {
    let (writer, guard) = match &route.output {
        LogOutput::Stdout => tracing_appender::non_blocking(std::io::stdout()),
        LogOutput::Stderr => tracing_appender::non_blocking(std::io::stderr()),
        LogOutput::File(path) => {
            let file = OpenOptions::new().append(true).create(true).open(path)?;
            tracing_appender::non_blocking(file)
        }
        LogOutput::Journald => unimplemented!(),
    };

    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_target(true)
        .with_thread_ids(true)
        .with_file(true)
        .with_line_number(true);

    let fmt_layer = match route.format {
        LogFormat::Full => fmt_layer.with_writer(writer).boxed(),
        LogFormat::Pretty => fmt_layer.with_writer(writer).pretty().boxed(),
        LogFormat::Compact => fmt_layer.with_writer(writer).compact().boxed(),
        LogFormat::Json => fmt_layer.with_writer(writer).json().boxed(),
    };

    Ok((
        fmt_layer
            .with_filter(
                SubsystemFilter::new(subsystem).and(
                    EnvFilter::builder()
                        .with_default_directive(LevelFilter::INFO.into())
                        .from_env_lossy(),
                ),
            )
            .boxed(),
        guard,
    ))
}

/// Guards for each worker that drains the logging queue.
/// When they are dropped, the corresponding log outputs are closed.
pub struct LogGuard {
    guards: Vec<WorkerGuard>,
}

pub fn init(preset: LogPreset) -> anyhow::Result<LogGuard> {
    let config = preset_to_config(preset);
    let mut layers = Vec::new();
    let mut guards = LogGuard { guards: Vec::new() };

    // For each subsystem, create one layer per route tagged by the subsystem filter.
    for (subsystem, log_config) in config {
        for route in log_config.routes {
            let (layer, guard) = create_layer_for_route(subsystem, &route)
                .context("Creating a layer for a log route")?;
            layers.push(layer);
            guards.guards.push(guard);
        }
    }

    tracing_subscriber::registry().with(layers).init();

    Ok(guards)
}
