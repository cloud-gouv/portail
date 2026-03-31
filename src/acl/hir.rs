use std::collections::HashMap;
use std::collections::HashSet;

use thiserror::Error;

use crate::acl::Action;
use crate::acl::ast;
use crate::config::BackendSettings;

#[derive(Debug, Clone)]
pub struct RouteDefinition {
    pub name: String,
    pub when: Option<ast::Expression>,
    pub r#use: Vec<BackendSettings>,
}

#[derive(Debug, Clone)]
pub struct PolicyDefinition {
    pub name: String,
    pub when: Option<ast::Expression>,
    pub require: Option<ast::Expression>,
    pub action: Action,
}

#[derive(Debug, Clone)]
pub struct ACLHir {
    pub(crate) routes: Vec<RouteDefinition>,
    pub(crate) policies: Vec<PolicyDefinition>,
}

#[derive(Debug, Error)]
pub enum TransformationError {
    #[error("Route block '{0}' has no backend to route to")]
    NoBackendToRoute(String),
    #[error("Policy block '{0}' is missing an action")]
    MissingAction(String),
    #[error("Block '{0}' of type '{1}' is duplicated")]
    DuplicateBlock(String, &'static str),
    #[error("Backend IDs '{0}' do not exist in current settings")]
    MissingBackendInSettings(String),
    #[error("In route block '{1}', attribute '{0}' occurs more than once")]
    DuplicateAttributeInRoute(&'static str, String),
    #[error("In policy block '{1}', attribute '{0}' occurs more than once")]
    DuplicateAttributeInPolicy(&'static str, String),
}

fn route_to_hir(
    route: ast::RouteDefinition,
    available_backends: &HashMap<String, BackendSettings>,
) -> Result<RouteDefinition, TransformationError> {
    let mut when: Option<ast::Expression> = None;
    let mut r#use: Vec<BackendSettings> = Vec::new();
    let mut missing_backends: Vec<&str> = Vec::new();

    for attribute in route.attributes {
        // Run consistency checks on the expressions as well.
        if let ast::RouteAttribute::When(expr) = attribute {
            if when.is_some() {
                return Err(TransformationError::DuplicateAttributeInRoute(
                    "when",
                    route.name.to_owned(),
                ));
            }

            when = Some(expr);
        } else if let ast::RouteAttribute::Use(backends) = attribute {
            if !r#use.is_empty() {
                return Err(TransformationError::DuplicateAttributeInRoute(
                    "use",
                    route.name.to_owned(),
                ));
            }

            for backend_key in backends {
                if let Some(backend) = available_backends.get(backend_key) {
                    r#use.push(backend.to_owned());
                } else {
                    missing_backends.push(backend_key);
                }
            }
        }
    }

    if !missing_backends.is_empty() {
        return Err(TransformationError::MissingBackendInSettings(
            missing_backends.join(", "),
        ));
    }

    if r#use.is_empty() {
        return Err(TransformationError::NoBackendToRoute(route.name.to_owned()));
    }

    Ok(RouteDefinition {
        name: route.name.to_owned(),
        when,
        r#use: r#use,
    })
}

fn policy_to_hir<'s>(
    policy: ast::PolicyBlock<'s>,
) -> Result<PolicyDefinition, TransformationError> {
    let mut when = None;
    let mut require = None;
    let mut action = None;

    for attribute in policy.attributes {
        // Run consistency checks on the expressions as well.
        if let ast::PolicyAttribute::When(expr) = attribute {
            if when.is_some() {
                return Err(TransformationError::DuplicateAttributeInPolicy(
                    "when",
                    policy.name.to_owned(),
                ));
            }
            when = Some(expr);
        } else if let ast::PolicyAttribute::Require(expr) = attribute {
            if require.is_some() {
                return Err(TransformationError::DuplicateAttributeInPolicy(
                    "require",
                    policy.name.to_owned(),
                ));
            }

            require = Some(expr);
        } else if let ast::PolicyAttribute::Action(inner) = attribute {
            if action.is_some() {
                return Err(TransformationError::DuplicateAttributeInPolicy(
                    "action",
                    policy.name.to_owned(),
                ));
            }
            action = Some(inner);
        }
    }

    let action =
        action.ok_or_else(|| TransformationError::MissingAction(policy.name.to_owned()))?;

    Ok(PolicyDefinition {
        name: policy.name.to_owned(),
        when,
        require,
        action,
    })
}

/// Transform the ACL AST into a higher intermediate representation,
/// ready for quick evaluation.
///
/// Semantic validation occurs during this transformation pass.
pub fn ast_to_hir<'s>(
    ast: ast::ACLAst<'s>,
    backends: &HashMap<String, BackendSettings>,
) -> Result<ACLHir, TransformationError> {
    let mut route_names = HashSet::new();
    let mut policy_names = HashSet::new();

    let mut policies = Vec::new();
    let mut routes = Vec::new();

    for entry in ast.entries {
        match entry {
            ast::ACLEntry::Route(route) => {
                let hir = route_to_hir(route, backends)?;
                if route_names.contains(hir.name.as_str()) {
                    return Err(TransformationError::DuplicateBlock(hir.name, "route"));
                }

                route_names.insert(hir.name.clone());
                routes.push(hir);
            }

            ast::ACLEntry::Policy(policy) => {
                let hir = policy_to_hir(policy)?;
                if policy_names.contains(hir.name.as_str()) {
                    return Err(TransformationError::DuplicateBlock(hir.name, "policy"));
                }

                policy_names.insert(hir.name.clone());
                policies.push(hir);
            }
        }
    }

    Ok(ACLHir { routes, policies })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acl::Action;
    use crate::acl::ast;
    use crate::config::BackendSettings;
    use insta::assert_debug_snapshot;
    use std::collections::HashMap;

    // TODO: check for missing backends

    fn settings_with_backends(ids: &[&str]) -> HashMap<String, BackendSettings> {
        let mut backends = HashMap::new();

        for id in ids {
            backends.insert(
                id.to_string(),
                BackendSettings {
                    target_address: "1.1.1.1:443".parse().unwrap(),
                    identity_aware: false,
                },
            );
        }

        backends
    }

    #[test]
    fn accept_valid_policy() {
        let ast = ast::ACLAst {
            entries: vec![ast::ACLEntry::Policy(ast::PolicyBlock {
                name: "policy1",
                attributes: vec![
                    ast::PolicyAttribute::When(ast::Expression::Group(Box::new(
                        ast::Expression::Comparison(
                            ast::Operand::Boolean(true),
                            ast::Comparator::Eq,
                            ast::Operand::Boolean(true),
                        ),
                    ))),
                    ast::PolicyAttribute::Action(Action::Allow),
                ],
            })],
        };

        let settings = settings_with_backends(&[]);

        let result = ast_to_hir(ast, &settings);

        assert!(result.is_ok());
        assert_debug_snapshot!("valid_hir_for_policy", result);
    }

    #[test]
    fn reject_duplicate_policies() {
        let ast = ast::ACLAst {
            entries: vec![
                ast::ACLEntry::Policy(ast::PolicyBlock {
                    name: "policy",
                    attributes: vec![ast::PolicyAttribute::Action(Action::Allow)],
                }),
                ast::ACLEntry::Policy(ast::PolicyBlock {
                    name: "policy",
                    attributes: vec![ast::PolicyAttribute::Action(Action::Allow)],
                }),
            ],
        };

        let settings = settings_with_backends(&[]);

        let result = ast_to_hir(ast, &settings);

        assert!(matches!(
            result,
            Err(TransformationError::DuplicateBlock(_, "policy"))
        ));
    }

    #[test]
    fn reject_duplicate_routes() {
        let ast = ast::ACLAst {
            entries: vec![
                ast::ACLEntry::Route(ast::RouteDefinition {
                    name: "route",
                    attributes: vec![ast::RouteAttribute::Use(vec!["backend1"])],
                }),
                ast::ACLEntry::Route(ast::RouteDefinition {
                    name: "route",
                    attributes: vec![ast::RouteAttribute::Use(vec!["backend1"])],
                }),
            ],
        };

        let settings = settings_with_backends(&["backend1"]);

        let result = ast_to_hir(ast, &settings);

        assert!(matches!(
            result,
            Err(TransformationError::DuplicateBlock(_, "route"))
        ));
    }

    #[test]
    fn reject_duplicate_actions() {
        let ast = ast::ACLAst {
            entries: vec![ast::ACLEntry::Policy(ast::PolicyBlock {
                name: "policy",
                attributes: vec![
                    ast::PolicyAttribute::Action(Action::Allow),
                    ast::PolicyAttribute::Action(Action::Allow),
                ],
            })],
        };

        let settings = settings_with_backends(&[]);

        let result = ast_to_hir(ast, &settings);

        assert!(result.is_err());
    }

    #[test]
    fn reject_duplicate_when() {
        let expr = ast::Expression::Comparison(
            ast::Operand::Boolean(true),
            ast::Comparator::Eq,
            ast::Operand::Boolean(true),
        );

        let ast = ast::ACLAst {
            entries: vec![ast::ACLEntry::Policy(ast::PolicyBlock {
                name: "policy",
                attributes: vec![
                    ast::PolicyAttribute::When(expr.clone()),
                    ast::PolicyAttribute::When(expr),
                    ast::PolicyAttribute::Action(Action::Allow),
                ],
            })],
        };

        let settings = settings_with_backends(&[]);

        let result = ast_to_hir(ast, &settings);

        assert!(matches!(
            result,
            Err(TransformationError::DuplicateAttributeInPolicy("when", _))
        ));
    }

    #[test]
    fn reject_duplicate_require() {
        let expr = ast::Expression::Comparison(
            ast::Operand::Boolean(true),
            ast::Comparator::Eq,
            ast::Operand::Boolean(true),
        );

        let ast = ast::ACLAst {
            entries: vec![ast::ACLEntry::Policy(ast::PolicyBlock {
                name: "policy",
                attributes: vec![
                    ast::PolicyAttribute::Require(expr.clone()),
                    ast::PolicyAttribute::Require(expr),
                    ast::PolicyAttribute::Action(Action::Allow),
                ],
            })],
        };

        let settings = settings_with_backends(&[]);

        let result = ast_to_hir(ast, &settings);

        assert!(matches!(
            result,
            Err(TransformationError::DuplicateAttributeInPolicy(
                "require",
                _
            ))
        ));
    }

    #[test]
    fn reject_missing_action() {
        let ast = ast::ACLAst {
            entries: vec![ast::ACLEntry::Policy(ast::PolicyBlock {
                name: "policy",
                attributes: vec![],
            })],
        };

        let settings = settings_with_backends(&[]);

        let result = ast_to_hir(ast, &settings);

        assert!(matches!(result, Err(TransformationError::MissingAction(_))));
    }

    #[test]
    fn reject_non_existent_backends() {
        let ast = ast::ACLAst {
            entries: vec![ast::ACLEntry::Route(ast::RouteDefinition {
                name: "route",
                attributes: vec![ast::RouteAttribute::Use(vec!["missing_backend"])],
            })],
        };

        let settings = settings_with_backends(&[]);

        let result = ast_to_hir(ast, &settings);

        assert!(matches!(
            result,
            Err(TransformationError::MissingBackendInSettings(_))
        ));
    }
}
