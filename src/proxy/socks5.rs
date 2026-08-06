use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};

use fast_socks5::{
    client::Socks5Stream,
    server::Socks5ServerProtocol,
    util::target_addr::{AddrError, TargetAddr},
    ReplyError, Socks5Command, SocksError,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
    time::{timeout, Instant},
};
use tokio_rustls::TlsStream;
use tracing::{debug, info, warn};

use crate::{
    acl::ACLRules,
    backend_routing::{self, ACLDecision, BackendOutcome},
    config::{BackendSettings, KnownBackend},
    dns::{happy_eyeballs_connect, DnsError, HappyEyeballsError},
    proxy::{
        context::{LocalRequestContext, OwnedRequestContext, TargetContext},
        ProxyRuntime,
    },
};

#[allow(clippy::large_enum_variant)]
pub enum OutboundSock5Stream {
    Tls(Socks5Stream<TlsStream<TcpStream>>),
    Plain(Socks5Stream<TcpStream>),
}

enum Decision {
    TerminateWithError(ReplyError),
    RedirectDestination(TargetAddr),
    Continue,
}

fn map_acl_decision(
    decision: ACLDecision,
    start: Instant,
    target_context: &TargetContext,
) -> Result<Decision, fast_socks5::SocksError> {
    match decision {
        ACLDecision::InternalError => {
            return Ok(Decision::TerminateWithError(ReplyError::GeneralFailure));
        }

        ACLDecision::Deny => {
            info!(
                subsystem = "proxy_access",
                target_context = ?target_context,
                duration_us = start.elapsed().as_micros(),
                "SOCKS5 request blocked due to ACL"
            );

            Ok(Decision::TerminateWithError(
                ReplyError::ConnectionNotAllowed,
            ))
        }

        ACLDecision::Redirect(target) => {
            info!(
                subsystem = "proxy_access",
                target_context = ?target_context,
                redirected_to = %target,
                duration_us = start.elapsed().as_micros(),
                "SOCKS5 request redirected due to ACL"
            );

            Ok(Decision::RedirectDestination(TargetAddr::Domain(
                target
                    .host()
                    .expect("BUG: Redirect target should be an FQDN")
                    .to_owned(),
                // FIXME: calculation of the default port should be better and take into account
                // the scheme.
                target.port_u16().unwrap_or(80),
            )))
        }

        ACLDecision::Allow => Ok(Decision::Continue),
    }
}

// TODO: better error type
pub async fn connect_to_backend(
    backend: &KnownBackend,
    final_address: &TargetAddr,
    rt: Arc<ProxyRuntime>,
) -> Result<OutboundSock5Stream, SocksError> {
    let config = fast_socks5::client::Config::default();
    let (target_addr, target_port) = final_address.clone().into_string_and_port();

    if backend.identity_aware {
        debug!("Backend is identity-aware, establishing a TLS connection to the backend first");
        let domain = backend.tls_server_name.clone();
        let target_socket = TcpStream::connect(backend.target_address).await?;
        let stream = crate::proxy::client_tls::connect_using_tls_auth(
            target_socket,
            domain,
            rt.state.clone(),
            vec![],
        )
        .await?;

        Ok(OutboundSock5Stream::Tls(
            Socks5Stream::use_stream(stream, None, config).await?,
        ))
    } else {
        debug!(
            subsystem = "proxy_access",
            "Backend is not identity-aware, establishing a plain SOCKS5 connection to the backend"
        );
        Ok(OutboundSock5Stream::Plain(
            Socks5Stream::connect(backend.target_address, target_addr, target_port, config).await?,
        ))
    }
}

pub async fn route_to_backend<S: AsyncRead + Unpin + AsyncWrite>(
    outbound_stream: OutboundSock5Stream,
    protocol: Socks5ServerProtocol<S, fast_socks5::server::states::CommandRead>,
) -> Result<(), SocksError> {
    let inner = protocol
        .reply_success(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0))
        .await?;

    match outbound_stream {
        OutboundSock5Stream::Tls(s) => fast_socks5::server::transfer(inner, s).await,
        OutboundSock5Stream::Plain(s) => fast_socks5::server::transfer(inner, s).await,
    }

    Ok(())
}

#[tracing::instrument(skip_all, fields(trace_id = %ctx.trace_id, client_address = %ctx.client_address, subsystem = "proxy_access"))]
pub async fn serve_socks5<S: AsyncRead + Unpin + AsyncWrite>(
    rt: Arc<ProxyRuntime>,
    ctx: OwnedRequestContext,
    socket: S,
) -> Result<(), SocksError> {
    let start = Instant::now();

    let handshake = Socks5ServerProtocol::accept_no_auth(socket);

    let (proto, cmd, target_addr) = timeout(rt.settings.handshake_timeout, async {
        let proto = handshake.await?;
        proto.read_command().await
    })
    .await
    .map_err(|_| {
        warn!(subsystem = "proxy_access", "SOCKS5 handshake timed out");

        SocksError::Io(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "SOCKS5 handshake timed out",
        ))
    })??;

    debug!(
        subsystem = "proxy_access",
        target_addr = %target_addr,
        duration_ms = %start.elapsed().as_millis(),
        "SOCKS5 target address obtained"
    );
    let start = Instant::now();

    let target_context = TargetContext {
        initial_target: target_addr.clone().into(),
    };

    let (host, port) = target_context.initial_target.clone().into_string_and_port();

    let mut ctx = ctx.as_local();
    ctx.acl_ctx.insert(
        "proxy.protocol",
        crate::acl::ast::ConcreteOperand::String("socks5"),
    );
    ctx.acl_ctx
        .insert("host", crate::acl::ast::ConcreteOperand::String(&host));
    ctx.acl_ctx.insert(
        "port",
        crate::acl::ast::ConcreteOperand::Number(port.into()),
    );

    let mut final_addr = target_addr;

    // TODO: enable UDP ASSOCIATE once ACL rules are evaluated on each UDP packet
    if cmd != Socks5Command::TCPConnect {
        info!(
            subsystem = "proxy_errors",
            command = ?cmd,
            "Unsupported SOCKS5 command received, terminating connection"
        );
        proto.reply_error(&ReplyError::CommandNotSupported).await?;
        return Err(ReplyError::CommandNotSupported.into());
    }

    if cmd == Socks5Command::TCPConnect {
        ctx.acl_ctx.insert(
            "proxy.cmd",
            crate::acl::ast::ConcreteOperand::String("tcp_connect"),
        );
    }

    if cmd == Socks5Command::UDPAssociate {
        ctx.acl_ctx.insert(
            "proxy.cmd",
            crate::acl::ast::ConcreteOperand::String("udp_associate"),
        );
    }

    debug!(
        subsystem = "proxy_access",
        command = ?cmd,
        "SOCKS5 command allowed"
    );

    let (mut backends, acl) = match backend_routing::build_backend_chain(&rt, &mut ctx).await {
        (Some(b), acl) => (b, acl),
        (None, _) => {
            proto.reply_error(&ReplyError::GeneralFailure).await?;
            return Ok(());
        }
    };

    match map_acl_decision(
        backend_routing::assess_request(&ctx, &acl),
        start,
        &target_context,
    )? {
        Decision::TerminateWithError(error) => {
            proto.reply_error(&error).await?;
            return Ok(());
        }
        Decision::RedirectDestination(tgt_addr) => final_addr = tgt_addr,
        Decision::Continue => {}
    }

    info!(
        subsystem = "proxy_access",
        duration_us = start.elapsed().as_micros(),
        "SOCKS5 request allowed due to ACL"
    );

    let start = Instant::now();
    match backend_routing::try_backends(
        &mut backends,
        &final_addr.to_string(),
        rt.settings.connect_timeout,
        |backend, _target| {
            let rt = Arc::clone(&rt);
            let final_addr = final_addr.clone();
            async move {
                BackendOutcome::from_result_retry(
                    connect_to_backend(&backend, &final_addr, rt).await,
                )
            }
        },
    )
    .await
    {
        Some(Ok((stream, _backend))) => {
            let start = Instant::now();
            route_to_backend(stream, proto).await?;
            debug!(
                subsystem = "proxy_access",
                duration_ms = start.elapsed().as_millis(),
                "SOCKS5 request finished"
            );

            return Ok(());
        }

        Some(Err(err)) => {
            warn!(
                subsystem = "proxy_errors",
                err = %err,
                "BUG: SOCKS5 connection should never produces fatal outcomes"
            );
        }

        // Move on to direct exit.
        None => {}
    }

    // Direct exit: if we get there, this means that we did not have any backend at all.
    {
        debug!(
            subsystem = "proxy_access",
            duration_ms = start.elapsed().as_millis(),
            "No backend, terminating the connection ourself"
        );

        let start = Instant::now();

        backend_routing::mark_direct_exit(&mut ctx);
        match map_acl_decision(
            backend_routing::assess_request(&ctx, &acl),
            start,
            &target_context,
        )? {
            Decision::TerminateWithError(error) => {
                proto.reply_error(&error).await?;
                return Ok(());
            }
            Decision::RedirectDestination(tgt_addr) => final_addr = tgt_addr,
            Decision::Continue => {}
        }

        info!(
            subsystem = "proxy_access",
            duration_us = start.elapsed().as_micros(),
            "SOCKS5 request allowed due to ACL (direct exit)"
        );

        let start = Instant::now();
        match (cmd, rt.settings.public_address) {
            (Socks5Command::TCPConnect, _) => {
                let (host, port) = final_addr.into_string_and_port();
                let (stream, resolved_addr) = happy_eyeballs_connect(
                    &rt.dns,
                    &host,
                    port,
                    rt.settings.connect_timeout,
                    rt.settings.tcp_nodelay,
                )
                .await
                .map_err(|err| {
                    warn!(
                        subsystem = "proxy_errors",
                        host = %host,
                        port = %port,
                        duration_ms = start.elapsed().as_millis(),
                        "SOCKS5 Happy Eyeballs connection failed: {err}",
                    );
                    match err {
                        HappyEyeballsError::Dns(dns_err) => match dns_err {
                            DnsError::LookupFailed { source, .. } => {
                                SocksError::AddrError(AddrError::DNSResolutionFailed(source))
                            }
                            DnsError::TimedOut { .. } => SocksError::AddrError(
                                AddrError::DNSResolutionFailed(std::io::Error::other(dns_err)),
                            ),
                            DnsError::NoRecords { .. } => {
                                SocksError::AddrError(AddrError::NoDNSRecords)
                            }
                        },
                        HappyEyeballsError::AllFailed { .. }
                        | HappyEyeballsError::NoAddresses { .. } => {
                            SocksError::ReplyError(ReplyError::HostUnreachable)
                        }
                    }
                })?;

                debug!(
                    subsystem = "proxy_access",
                    target_addr = %resolved_addr,
                    duration_ms = start.elapsed().as_millis(),
                    "SOCKS5 Happy Eyeballs connection established"
                );

                let inner = proto
                    .reply_success(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0))
                    .await?;
                fast_socks5::server::transfer(inner, stream).await;
            }

            // TODO: enable with ACL rules evaluation
            // (Socks5Command::UDPAssociate, Some(public_address)) => {
            // TODO: fast_socks5 does its own DNS resolution on each UDP packet using the system resolver.
            // https://github.com/dizda/fast-socks5/blob/acb847616ec44b6c2d6cdaddeba090d18c6c5d5c/src/server.rs#L1245
            //    fast_socks5::server::run_udp_proxy(proto, &final_addr, None, public_address, None)
            //        .await?;
            //}
            _ => {
                proto.reply_error(&ReplyError::CommandNotSupported).await?;
                return Err(ReplyError::CommandNotSupported.into());
            }
        }
        debug!(
            subsystem = "proxy_access",
            duration_ms = start.elapsed().as_millis(),
            "SOCKS5 request finished"
        );
    }

    Ok(())
}
