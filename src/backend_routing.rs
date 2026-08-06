use std::time::Duration;

use tokio::time::Instant;
use tracing::{debug, warn};

use crate::{
    acl::{self, ACLRules},
    config::{BackendSettings, KnownBackend},
    proxy::{ProxyRuntime, context::LocalRequestContext},
};

#[must_use]
#[derive(Debug, PartialEq, Eq)]
pub enum ACLDecision {
    InternalError,
    Deny,
    Redirect(http::Uri),
    Allow,
}

pub fn assess_request(ctx: &LocalRequestContext<'_>, acl: &ACLRules) -> ACLDecision {
    let assessment = match ctx.acl_ctx.evaluate_request(&acl.hir) {
        Ok(assessment) => assessment,
        Err(failure) => {
            warn!(
                subsystem = "proxy_errors",
                "Failed to evaluate a reequest: {} (context: {:#?})", failure, ctx
            );

            return ACLDecision::InternalError;
        }
    };

    match assessment.action {
        acl::Action::Deny(_) => ACLDecision::Deny,
        acl::Action::Redirect(tgt) => ACLDecision::Redirect(tgt),
        acl::Action::Allow => ACLDecision::Allow,
    }
}

/// Builds an ordered backend list from route evaluation, and the default backend.
///
/// Callers use [`Vec::pop()`] for highest-priority first. Sets `route.local = false` in the ACL context
/// so policies can distinguish local exits.
pub async fn build_backend_chain(
    rt: &ProxyRuntime,
    ctx: &mut LocalRequestContext<'_>,
) -> (Option<Vec<BackendSettings>>, ACLRules) {
    let mut backends = Vec::with_capacity(1);

    // Clone ACL data out of the read lock and drop the guard immediately.
    // If you hold the read guard across backend connects, it will starves RPC writers.

    let (backend_specs, acl, default_backend_id) = {
        let state_guard = rt.state.read().await;

        (
            state_guard.backends.clone(),
            state_guard.acl_rules.clone(),
            state_guard.default_backend.clone(),
        )
    };

    let mut recommended_routes = match ctx.acl_ctx.evaluate_routes(&backend_specs, &acl.hir) {
        Ok(routes) => routes,
        Err(failure) => {
            warn!(
                subsystem = "proxy_errors",
                "Failed to evaluate routes for a request: {} (context: {:#?})", failure, ctx
            );

            Vec::new()
        }
    };

    backends.append(&mut recommended_routes);

    if backends.is_empty()
        && let Some(ref backend_id) = default_backend_id
    {
        let backend = match backend_specs.get(backend_id) {
            Some(b) => b.to_owned(),
            None => {
                warn!(
                    subsystem = "proxy_errors",
                    default_backend_id = default_backend_id,
                    "Default backend ID not found in state, rejecting request"
                );

                return (None, acl);
            }
        };

        backends.push(backend);
    }

    // High priority is now last.
    backends.reverse();

    ctx.acl_ctx.insert(
        "route.local",
        crate::acl::ast::ConcreteOperand::Boolean(backends.is_empty()),
    );

    (Some(backends), acl)
}

pub enum BackendOutcome<S, E> {
    Success(S),
    Retry,
    Fatal(E),
}

impl<S, E> BackendOutcome<S, E> {
    pub fn from_result_retry(result: Result<S, E>) -> Self {
        match result {
            Ok(stream) => BackendOutcome::Success(stream),
            Err(_) => BackendOutcome::Retry,
        }
    }
}

/// Iterate through `backends`, calling `connect_fn` for each with timeout.
///
/// Returns `Some(Ok((Stream, backend)))` on first success, `Some(Err(e))` on a fatal error,
/// or `None` when all backends are exhausted.
pub async fn try_backends<F, Fut, S, E>(
    backends: &mut Vec<BackendSettings>,
    target: &str,
    connect_timeout: Duration,
    connect_fn: F,
) -> Option<Result<(S, KnownBackend), E>>
where
    F: Fn(KnownBackend, String) -> Fut,
    Fut: Future<Output = BackendOutcome<S, E>>,
{
    let start = Instant::now();

    while let Some(backend) = backends.pop() {
        match backend {
            BackendSettings::UnresolvedBackend => {
                tracing::error!(
                    "An unresolved backend was selected during routing. This should not happen."
                );

                return None;
            }

            BackendSettings::KnownBackend(known_backend) => {
                debug!(
                    subsystem = "proxy_access",
                    backend = ?known_backend,
                    duration_ms = start.elapsed().as_millis(),
                    "Backend selected for connection routing"
                );

                match tokio::time::timeout(
                    connect_timeout,
                    connect_fn(known_backend.clone(), target.to_owned()),
                )
                .await
                {
                    Ok(BackendOutcome::Success(stream)) => {
                        debug!(
                            subsystem = "proxy_access",
                            backend = ?known_backend,
                            duration_ms = start.elapsed().as_millis(),
                            "Connection to upstream backend successful"
                        );

                        return Some(Ok((stream, known_backend)));
                    }
                    Ok(BackendOutcome::Fatal(err)) => {
                        return Some(Err(err));
                    }
                    Ok(BackendOutcome::Retry) => {
                        debug!(
                            subsystem = "proxy_access",
                            backend = ?known_backend,
                            duration_ms = start.elapsed().as_millis(),
                            "Backend failed, trying the next one"
                        );

                        continue;
                    }
                    Err(_elapsed) => {
                        debug!(
                            subsystem = "proxy_access",
                            backend = ?known_backend,
                            duration_ms = start.elapsed().as_millis(),
                            "Backend timed out, trying the next one"
                        );

                        continue;
                    }
                }
            }
        }
    }

    None
}

pub fn mark_direct_exit(ctx: &mut LocalRequestContext<'_>) {
    ctx.acl_ctx.insert(
        "route.local",
        crate::acl::ast::ConcreteOperand::Boolean(true),
    );
}
