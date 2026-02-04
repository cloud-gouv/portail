use std::sync::Arc;

use tokio::sync::RwLock;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{config::Settings, proxy::ProxyError, state::State};

pub async fn serve_http_connect<S: AsyncRead + AsyncWrite>(
    settings: Arc<Settings>,
    state: Arc<RwLock<State>>,
    stream: S,
) -> Result<(), ProxyError> {
    unimplemented!();
    Ok(())
}

