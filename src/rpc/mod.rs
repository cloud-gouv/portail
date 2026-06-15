use crate::{
    config::{BackendSettings, KnownBackend, Settings},
    rpc::fr_gouv_portail_control::{
        BackendListItem, ControlError, DynamicBackendSpec, GetCurrentBackendOutput,
        ListBackendsOutput,
    },
    state::State,
};
use std::{collections::HashSet, ffi::CStr, sync::Arc};
use tokio::{net::UnixListener, sync::RwLock};
use tracing::{debug, info, warn};
use zlink::{
    Server,
    connection::{Gid, Socket, socket::FetchPeerCredentials},
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
                    buf.as_mut_ptr().cast::<nix::libc::c_char>(),
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

impl Control {
    async fn check_authorization<S, I, T>(
        &self,
        conn: &mut zlink::Connection<S>,
        authorized_groups: I,
    ) -> Result<(), ControlError>
    where
        S: Socket,
        S::ReadHalf: FetchPeerCredentials,
        I: IntoIterator<Item = T>,
        T: AsRef<str>,
    {
        let creds = conn
            .peer_credentials()
            .await
            .map_err(|_| ControlError::PermissionDenied)?;

        let mut groups: Vec<Gid> = creds.unix_supplementary_group_ids().to_vec();
        groups.push(creds.unix_primary_group_id());

        let groups = resolve_numeric_groups_to_names(groups);
        let authorized_groups = authorized_groups
            .into_iter()
            .map(|s| s.as_ref().to_owned())
            .collect::<Vec<String>>();

        // TODO: resolve numeric UIDs into usernames proper for better logs.

        if creds.unix_user_id().is_root()
            || authorized_groups
                .iter()
                .any(|trusted| groups.contains(trusted))
        {
            info!(user = %creds.unix_user_id(), subsystem = "rpc", "Privileged RPC allowed");
            Ok(())
        } else {
            warn!(
                user = %creds.unix_user_id(),
                groups = ?groups,
                authorized_groups = ?authorized_groups,
                subsystem = "rpc",
                "Privileged RPC call attempt refused",
            );

            Err(ControlError::PermissionDenied)
        }
    }
}

#[service(
    interface = "fr.gouv.portail.Control",
    vendor = "gouv",
    product = env!("CARGO_PKG_NAME"),
    version = env!("CARGO_PKG_VERSION"),
    url = env!("CARGO_PKG_HOMEPAGE"),
)]
impl<Sock> Control
where
    Sock::ReadHalf: FetchPeerCredentials,
{
    #[tracing::instrument(skip_all, fields(subsystem = "rpc", backend_id = %backend_id))]
    async fn set_default_backend(
        &mut self,
        backend_id: Option<&str>,
        #[zlink(connection)] conn: &mut zlink::Connection<Sock>,
    ) -> Result<(), ControlError> {
        self.check_authorization(conn, self.settings.rpc.trusted_groups.iter())
            .await?;

        let mut state = self.state.write().await;

        if let Some(backend_id) = backend_id {
            if !state.backends.contains_key(backend_id) {
                info!(target_backend = %backend_id, "Backend not found in state");
                return Err(ControlError::BackendNotFound {
                    provided_backend: backend_id.to_string(),
                    available_backends: state.backends.keys().cloned().collect(),
                });
            }

            info!(previous_backend = ?state.default_backend, new_backend = %backend_id, "Default backend changed");
            state.default_backend = Some(backend_id.to_owned());
        } else {
            info!(previous_backend = ?state.default_backend, "Default backend unset");
            state.default_backend = None;
        }

        Ok(())
    }

    #[tracing::instrument(skip_all, fields(subsystem = "rpc", backend_id = %backend_id, backend_spec = %backend_spec))]
    async fn update_dynamic_backend(
        &mut self,
        backend_id: &str,
        backend_spec: DynamicBackendSpec,
        #[zlink(connection)] conn: &mut zlink::Connection<Sock>,
    ) -> Result<(), ControlError> {
        self.check_authorization(conn, self.settings.rpc.admin_groups.iter())
            .await?;

        // This is not a dynamic backend, let's bail out.
        if matches!(
            self.settings.backends.get(backend_id),
            Some(BackendSettings::KnownBackend(_))
        ) {
            warn!(
                backend_target = %backend_id,
                "Attempt to change a non-dynamic backend, rejected"
            );
            return Err(ControlError::ImmutableBackend);
        }

        let mut state = self.state.write().await;
        let new_backend: KnownBackend = backend_spec.try_into()?;

        match state.backends.get_mut(backend_id) {
            Some(backend) => {
                info!(
                    changed_backend = %backend_id,
                    old_spec = ?*backend,
                    new_spec = ?new_backend,
                    "Dynamic backend specification changed"
                );

                *backend = BackendSettings::KnownBackend(new_backend);

                Ok(())
            }
            None => {
                info!(
                    target_backend = %backend_id,
                    "Backend not found"
                );
                Err(ControlError::BackendNotFound {
                    provided_backend: backend_id.to_string(),
                    available_backends: state.backends.keys().cloned().collect(),
                })
            }
        }
    }

    #[tracing::instrument(skip_all, fields(subsystem = "rpc"))]
    async fn get_current_backend(&mut self) -> GetCurrentBackendOutput {
        debug!("Current backend read");
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

    #[tracing::instrument(skip_all, fields(subsystem = "rpc"))]
    async fn list_backends(&mut self) -> ListBackendsOutput {
        let cur_backend = self.state.read().await.default_backend.clone();
        let backends = &self.state.read().await.backends;
        debug!("Backend list read");
        ListBackendsOutput {
            backends: backends
                .iter()
                .map(|(backend_id, backend)| {
                    let current = cur_backend
                        .as_ref()
                        .map(|cur_backend_id| *cur_backend_id == *backend_id)
                        .unwrap_or(false);
                    let id = backend_id.to_owned();

                    match backend {
                        BackendSettings::UnresolvedBackend => BackendListItem {
                            id,
                            current,
                            dynamic: true,
                            spec: None,
                        },
                        BackendSettings::KnownBackend(known) => BackendListItem {
                            id,
                            current,
                            dynamic: matches!(
                                self.settings.backends.get(backend_id.as_str()).unwrap_or_else(|| panic!("Broken invariant: backend {backend_id} exists in state but not in settings")),
                                BackendSettings::UnresolvedBackend
                            ),
                            spec: Some(known.clone().into()),
                        },
                    }
                })
                .collect(),
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
