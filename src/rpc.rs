use crate::config::Settings;
use std::sync::Arc;
use std::os::fd::RawFd;

/// Spawn a Varlink server to control the proxy server.
pub async fn start(
    settings: Arc<Settings>,
    listener_fd: RawFd,
) -> anyhow::Result<()> {
    Ok(())
}
