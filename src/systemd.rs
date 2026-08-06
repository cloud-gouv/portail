use std::collections::HashMap;
use std::env;
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::net::UnixDatagram;

use thiserror::Error;
use tracing::error;

const SD_NOTIFY_SOCKET_PATH: &str = "/run/systemd/notify";
const READY_MESSAGE: &str = "READY=1";

#[derive(Debug, Error)]
pub enum NotifyError {
    #[error("Failed to create an unbound UNIX domain socket: {0}")]
    FailedCreate(std::io::Error),
    #[error("Failed to connect to the systemd notify socket: {0}")]
    FailedConnect(std::io::Error),
    #[error("Failed to send a notification to the systemd notify socket: {0}")]
    FailedSend(std::io::Error),
}

/// Notify systemd about things.
pub fn sd_notify(state: &str) -> Result<(), NotifyError> {
    let sock = UnixDatagram::unbound().map_err(NotifyError::FailedCreate)?;
    sock.connect(SD_NOTIFY_SOCKET_PATH)
        .map_err(NotifyError::FailedConnect)?;

    sock.send(state.as_bytes())
        .map_err(NotifyError::FailedSend)?;

    Ok(())
}

#[inline]
pub fn sd_notify_ready() -> Result<(), NotifyError> {
    sd_notify(READY_MESSAGE)
}

pub fn listen_fds_named() -> HashMap<String, OwnedFd> {
    use nix::sys::socket;

    let pid_ok = env::var("LISTEN_PID")
        .map(|v| v == std::process::id().to_string())
        .unwrap_or(false);
    if !pid_ok {
        return HashMap::new();
    }

    let n_fds = env::var("LISTEN_FDS")
        .ok()
        .and_then(|v| v.parse::<i32>().ok())
        .unwrap_or(0);

    let names = env::var("LISTEN_FDNAMES").unwrap_or_default();
    let names: Vec<String> = names.split(':').map(|s| s.to_owned()).collect(); // FDNAMES are colon-separated

    let mut map = HashMap::new();
    for i in 0..n_fds {
        // SAFETY: the FD is assumed to come from systemd's LISTEN_FDS protocol.
        // See https://www.freedesktop.org/software/systemd/man/latest/sd_listen_fds.html.
        let fd: OwnedFd = unsafe { OwnedFd::from_raw_fd(3 + i) };
        let default = format!("fd{}", 3 + i);
        let name = names.get(i as usize).unwrap_or(&default);

        // TODO: store also in the hashmap the type of the socket so that consumers can assert it.
        if socket::getsockopt(&fd, socket::sockopt::SockType).is_err() {
            error!(
                fd = 3 + i,
                name = name,
                "systemd fd is not a socket, skipping"
            );

            continue;
        }

        map.insert(name.clone(), fd);
    }
    map
}
