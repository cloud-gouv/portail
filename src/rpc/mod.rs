use crate::{
    config::Settings,
    rpc::fr_gouv_portail_control::{ControlError, GetCurrentBackendOutput},
    state::State,
};
use std::sync::Arc;
use tokio::{net::UnixListener, sync::RwLock};
use tracing::info;
use zlink::{Server, connection::socket::FetchPeerCredentials, service, unix::Listener};

pub mod fr_gouv_portail_control;

pub struct Control {
    settings: Arc<Settings>,
    state: Arc<RwLock<State>>,
}

impl Control {
    pub fn new(settings: Arc<Settings>, state: Arc<RwLock<State>>) -> Self {
        Self { settings, state }
    }
}

/// FIXME: `env!()` cannot be used in the proc-macro below alas: https://github.com/z-galaxy/zlink/issues/237
#[service(
    interface = "fr.gouv.portail.Control",
    vendor = "gouv",
    product = "portail",
    version = "0.1.0",
    url = "https://github.com/cloud-gouv/portail"
)]
impl<Sock> Control
where
    Sock::ReadHalf: FetchPeerCredentials,
{
    async fn set_default_backend(
        &mut self,
        backend_id: &str,
        #[zlink(connection)] conn: &mut zlink::Connection<Sock>,
    ) -> Result<(), ControlError> {
        let r = conn
            .peer_credentials()
            .await
            .map_err(|_| ControlError::PermissionDenied)?;

        if r.unix_user_id().is_root() {
            let mut state = self.state.write().await;

            if !self.settings.backends.contains_key(backend_id) {
                return Err(ControlError::BackendNotFound {
                    provided_backend: backend_id.to_string(),
                    available_backends: self.settings.backends.keys().cloned().collect(),
                });
            }

            state.default_backend = Some(backend_id.to_owned());

            Ok(())
        } else {
            Err(ControlError::PermissionDenied)
        }
    }

    async fn get_current_backend(&mut self) -> GetCurrentBackendOutput {
        GetCurrentBackendOutput {
            backend_id: self
                .state
                .read()
                .await
                .default_backend
                .clone()
                .unwrap_or("<none>".to_string()),
        }
    }
}

/// Spawn a Varlink server to control the proxy server.
pub async fn start(
    settings: Arc<Settings>,
    state: Arc<RwLock<State>>,
    listener: UnixListener,
) -> anyhow::Result<()> {
    let server: Server<Listener, _> = Server::new(
        listener.into(),
        Control::new(settings.clone(), state.clone()),
    );

    info!("started Varlink service");
    Ok(server.run().await?)
}
