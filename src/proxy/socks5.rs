use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};

use fast_socks5::{
    ReplyError, Socks5Command, SocksError, client::Socks5Stream, server::Socks5ServerProtocol,
    util::target_addr::TargetAddr,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
    sync::RwLock,
    time::{Instant, timeout},
};
use tokio_rustls::TlsStream;
use tracing::{debug, info, warn};

use crate::{
    acl::ACLRules,
    config::{BackendSettings, KnownBackend, Settings},
    proxy::context::{LocalRequestContext, OwnedRequestContext, TargetContext},
    state::State,
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

fn assess_request(
    start: Instant,
    target_context: &TargetContext,
    ctx: &LocalRequestContext<'_>,
    acl: &ACLRules,
) -> Result<Decision, fast_socks5::SocksError> {
    let assessment = match ctx.acl_ctx.evaluate_request(&acl.hir) {
        Ok(assessment) => assessment,
        Err(failure) => {
            warn!(
                subsystem = "proxy_errors",
                "Failed to evaluate a request: {} (Context: {:#?})", failure, ctx
            );
            return Ok(Decision::TerminateWithError(ReplyError::GeneralFailure));
        }
    };

    match assessment.action {
        // FIXME: render the deny template if there's one.
        crate::acl::Action::Deny(_explain_template) => {
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
        crate::acl::Action::Redirect(target) => {
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

        _ => Ok(Decision::Continue),
    }
}

pub async fn connect_to_backend(
    backend: &KnownBackend,
    final_address: &TargetAddr,
    state: Arc<RwLock<State>>, // TODO: better error type
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
            state.clone(),
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
    opts: Arc<Settings>,
    state: Arc<RwLock<State>>,
    ctx: OwnedRequestContext,
    socket: S,
) -> Result<(), SocksError> {
    let should_resolve_dns: bool = state.read().await.default_backend.is_none();
    let start = Instant::now();

    let (proto, cmd, target_addr) = Socks5ServerProtocol::accept_no_auth(socket)
        .await?
        .read_command()
        .await?;

    debug!(
        subsystem = "proxy_access",
        target_addr = %target_addr,
        duration_ms = %start.elapsed().as_millis(),
        "SOCKS5 target address obtained"
    );
    let start = Instant::now();

    let mut target_context = TargetContext {
        initial_target: target_addr.clone().into(),
        resolved_target: None,
    };

    let target_addr = if should_resolve_dns {
        target_addr.resolve_dns().await?
    } else {
        target_addr
    };

    debug!(
        subsystem = "proxy_access",
        target_addr = %target_addr,
        duration_ms = %start.elapsed().as_millis(),
        "SOCKS5 resolved target address obtained"
    );

    let start = Instant::now();

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

    let mut final_addr = target_addr.clone();

    target_context.resolved_target = if should_resolve_dns {
        Some(target_addr.into())
    } else {
        None
    };

    if cmd != Socks5Command::TCPConnect && cmd != Socks5Command::UDPAssociate {
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

    let mut backends: Vec<BackendSettings> = Vec::with_capacity(1);
    let acl = &state.read().await.acl_rules;
    let backend_specs = &state.read().await.backends;

    // We evaluate first the routes as it can influence the ACL in case of a local exit.
    let mut recommended_routes = match ctx.acl_ctx.evaluate_routes(backend_specs, &acl.hir) {
        Ok(routes) => routes,
        Err(failure) => {
            proto.reply_error(&ReplyError::GeneralFailure).await?;
            warn!(
                subsystem = "proxy_errors",
                "Failed to evaluate routes for a request: {} (Context: {:#?})", failure, ctx
            );
            return Ok(());
        }
    };

    if !recommended_routes.is_empty() {
        backends.append(&mut recommended_routes);
    }

    if backends.is_empty()
        && let Some(ref backend_id) = state.read().await.default_backend
    {
        let backend = state
            .read()
            .await
            .backends
            .get(backend_id)
            .unwrap_or_else(|| panic!("BUG: default backend {backend_id} went away from state"))
            .to_owned();

        backends.push(backend);
    }

    backends.reverse();

    if backends.is_empty() {
        ctx.acl_ctx.insert(
            "route.local",
            crate::acl::ast::ConcreteOperand::Boolean(true),
        );
    } else {
        ctx.acl_ctx.insert(
            "route.local",
            crate::acl::ast::ConcreteOperand::Boolean(false),
        );
    }

    match assess_request(start, &target_context, &ctx, acl)? {
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
    // Either, we route to another backend or we do the SOCKS5 proxying ourselves.
    while let Some(backend) = backends.pop() {
        debug!(
            subsystem = "proxy_access",
            backend = ?backend,
            duration_ms = start.elapsed().as_millis(),
            "Backend selected for connection routing"
        );
        match backend {
            BackendSettings::UnresolvedBackend => {
                // TODO: keep the IDs to print them here.
                tracing::error!(
                    "An unresolved backend was selected during SOCKS5 routing. This should not happen, rejecting the request."
                );
                proto.reply_error(&ReplyError::GeneralFailure).await?;
                return Ok(());
            }
            BackendSettings::KnownBackend(backend) => {
                match timeout(
                    opts.request_timeout,
                    connect_to_backend(&backend, &final_addr, state.clone()),
                )
                .await
                {
                    Ok(Ok(stream)) => {
                        debug!(
                            subsystem = "proxy_access",
                            backend = ?backend,
                            duration_ms = start.elapsed().as_millis(),
                            "Connection to upstream backend successful"
                        );

                        let start = Instant::now();

                        route_to_backend(stream, proto).await?;

                        debug!(
                            subsystem = "proxy_access",
                            duration_ms = start.elapsed().as_millis(),
                            "SOCKS5 request finished"
                        );

                        return Ok(());
                    }

                    Ok(Err(err)) => {
                        debug!(
                            subsystem = "proxy_errors",
                            backend = ?backend,
                            "Backend failed to route the request: {err}, trying the next one",
                        );

                        continue;
                    }

                    Err(_) => {
                        debug!(
                            "Backend {} timed out after {:?}, trying the next one",
                            &backend.target_address, opts.request_timeout
                        );
                        continue;
                    }
                }
            }
        }
    }

    // If we get there, this means that we did not have any backend at all.
    {
        debug!(
            subsystem = "proxy_access",
            duration_ms = start.elapsed().as_millis(),
            "No backend, terminating the connection ourself"
        );

        let start = Instant::now();

        ctx.acl_ctx.insert(
            "route.local",
            crate::acl::ast::ConcreteOperand::Boolean(true),
        );
        match assess_request(start, &target_context, &ctx, acl)? {
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
        match (cmd, opts.public_address) {
            (Socks5Command::TCPConnect, _) => {
                fast_socks5::server::run_tcp_proxy(
                    proto,
                    &final_addr,
                    opts.request_timeout,
                    opts.tcp_nodelay,
                )
                .await?;
            }

            (Socks5Command::UDPAssociate, Some(public_address)) => {
                fast_socks5::server::run_udp_proxy(proto, &final_addr, None, public_address, None)
                    .await?;
            }

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
