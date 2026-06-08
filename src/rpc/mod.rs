use crate::{
    config::Settings,
    rpc::fr_gouv_portail_control::{ControlError, GetCurrentBackendOutput},
    state::State,
};
use std::{collections::HashSet, ffi::CStr, sync::Arc};
use tokio::{net::UnixListener, sync::RwLock};
use tracing::info;
use zlink::{
    Server,
    connection::{Gid, socket::FetchPeerCredentials},
    service,
    unix::Listener,
};

pub mod fr_gouv_portail_control;

fn resolve_numeric_groups_to_names(gids: Vec<Gid>) -> HashSet<String> {
    let mut result = HashSet::new();

    for gid in gids {
        let mut buf_size = unsafe { nix::libc::sysconf(nix::libc::_SC_GETGR_R_SIZE_MAX) };
        if buf_size <= 0 {
            buf_size = 1024; // fallback to 1 KB if sysconf fails
        }
        let mut group_name = None;

        loop {
            let mut grp: nix::libc::group = unsafe { std::mem::zeroed() };
            // SAFETY: buf_size is always > 0 due to the conditional above.
            // i64::MAX < usize::MAX therefore there's no overflow risk.
            let mut buf = vec![0u8; buf_size as usize];
            let mut grp_ptr: *mut nix::libc::group = std::ptr::null_mut();

            let ret = unsafe {
                nix::libc::getgrgid_r(
                    gid.as_raw(),
                    &mut grp,
                    buf.as_mut_ptr() as *mut i8,
                    buf.len(),
                    &mut grp_ptr,
                )
            };

            if ret == 0 {
                if !grp_ptr.is_null() {
                    let cstr = unsafe { CStr::from_ptr(grp.gr_name) };
                    group_name = Some(cstr.to_string_lossy().into_owned());
                }
                break;
            } else if ret == nix::libc::ERANGE {
                // Buffer too small, increase and retry
                buf_size *= 2;
                continue;
            } else {
                // NOTE: we silence the error here because
                // we fallback and transform the group name into a numeric GID
                // as a string.
                break;
            }
        }

        // Fallback: we format the numeric GID as a string.
        result.insert(group_name.unwrap_or_else(|| format!("{}", gid)));
    }

    result
}

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

        let mut groups: Vec<Gid> = r.unix_supplementary_group_ids().to_vec();
        groups.push(r.unix_primary_group_id());

        let groups = resolve_numeric_groups_to_names(groups);

        if r.unix_user_id().is_root()
            || self
                .settings
                .rpc
                .trusted_groups
                .iter()
                .any(|trusted_group| groups.contains(trusted_group))
        {
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
