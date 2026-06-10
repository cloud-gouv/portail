use std::{collections::HashMap, path::PathBuf};

use tracing::level_filters::LevelFilter;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Clone)]
pub enum LogFormat {
    UnstructuredText,
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
    Journald,
}

#[derive(Debug, Clone, PartialEq, Hash)]
pub enum Subsystems {
    /// All log entries related to the proxy (access logs and error logs)
    Proxy,
    /// All log entries related to the RPC
    RPC,
    /// All log entries related to everything else
    System,
}

pub fn init(config: HashMap<Subsystems, LogConfig>) {
    // For each subsystem, create one layer per route tagged by the subsystem filter.

    tracing_subscriber::fmt::fmt()
        .json()
        .with_env_filter(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .init();
}
