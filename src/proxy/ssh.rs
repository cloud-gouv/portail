use std::{net::SocketAddr, sync::Arc};

use russh::{
    client::Msg,
    keys::{agent::AgentIdentity, HashAlg},
    ChannelStream,
};
use thiserror::Error;
use tracing::{debug, warn};

use crate::config::SSHSettings;

#[derive(Debug, Error)]
pub enum SSHProxyError {
    #[error("SSH: {0}")]
    SSH(#[from] russh::Error),
    #[error("SSH keys: {0}")]
    SSHKeyring(#[from] russh::keys::Error),
    #[error("Agent authentication error: {0}")]
    AgentAuthError(#[from] russh::AgentAuthError),
    #[error("No valid identity found to connect to the SSH server")]
    NoValidIdentity,
    #[error("SSH config error: {0}")]
    ConfigError(#[from] russh_config::Error),
}

struct SSHTunnelHandler {
    target_host: String,
    target_port: u16,
}

impl russh::client::Handler for SSHTunnelHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &russh::keys::ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        // TODO: check known hosts keys
        // if not known, demand for prior deployment to known hosts
        Ok(russh::keys::check_known_hosts(
            &self.target_host,
            self.target_port,
            &server_public_key,
        )?)
    }
}

/// Initiate a SSH connection, immediately forwards TCP/IP and return a stream to that target
/// through the SSH connection.
///
/// Authentication is handled via SSH agents.
/// Configuration of the host target is handled using OpenSSH standard configuration files.
pub async fn proxy_via_ssh(
    ssh_options: Option<&SSHSettings>,
    proxy_host: &str,
    target_address: &SocketAddr,
) -> Result<ChannelStream<Msg>, SSHProxyError> {
    let config = russh_config::parse_home(proxy_host)?;

    let mut agent = match ssh_options {
        Some(ssh_opts) => {
            russh::keys::agent::client::AgentClient::connect_uds(&ssh_opts.ssh_agent_socket_path)
                .await?
        }
        None => russh::keys::agent::client::AgentClient::connect_env().await?,
    };

    let ssh_config = Arc::new(russh::client::Config::default());
    let handler = SSHTunnelHandler {
        target_host: config.host().to_owned(),
        target_port: config.port(),
    };

    // TODO: this is using whoami as a last resort...
    let user = config.user();
    let keys = agent.request_identities().await?;

    let mut session = russh::client::connect(
        ssh_config,
        format!("{}:{}", config.host(), config.port()),
        handler,
    )
    .await?;
    let mut successful_authentication = false;
    for key in keys {
        if let AgentIdentity::PublicKey { key, comment } = key {
            if let russh::client::AuthResult::Failure {
                remaining_methods,
                partial_success,
            } = session
                .authenticate_publickey_with(&user, key, Some(HashAlg::Sha256), &mut agent)
                .await?
            {
                debug!(
                    "SSH remaining methods: {:#?}, partial success? {}",
                    remaining_methods, partial_success
                );
                warn!(
                    "Failed to authenticate to the SSH proxy address with key with comment '{}'",
                    comment
                );
            } else {
                successful_authentication = true;
                break;
            }
        }
    }

    if !successful_authentication {
        warn!("Tried all authentication methods available and failed to connect to the SSH proxy address");
        return Err(SSHProxyError::NoValidIdentity);
    }

    Ok(session
        .channel_open_direct_tcpip(
            format!("{}", target_address.ip()),
            target_address.port() as u32,
            "127.0.0.1",
            0,
        )
        .await?
        .into_stream())
}
