use crate::config::Settings;
use std::sync::Arc;
use tokio::net::UnixListener;

/// Spawn a Varlink server to control the proxy server.
pub async fn start(settings: Arc<Settings>, listener: UnixListener) -> anyhow::Result<()> {
    Ok(())
}
