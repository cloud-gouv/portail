use std::{borrow::Cow, collections::HashMap};

use thiserror::Error;

use crate::{
    acl::{
        ast::{
            Action, ComparisonError, ConcreteOperand, Expression, Operand, OwnedConcreteOperand,
        },
        hir,
    },
    config::BackendSettings,
};

// These structures are useful to explain WHY we are denied.

#[allow(dead_code)]
#[derive(Debug)]
pub struct ExpressionResult<'s> {
    pub expression: &'s Expression,
    pub result: Result<bool, String>,
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct PolicyContext<'s> {
    pub policy_name: &'s str,
    pub when_results: Vec<ExpressionResult<'s>>,
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct RequireContext<'s> {
    pub policy_name: &'s str,
    pub require_results: Vec<ExpressionResult<'s>>,
}

#[derive(Debug, Clone)]
pub struct EvaluationContext<'s> {
    // FIXME: support more complicated variable structures such as entire JSON fragments or well
    // typed structures for dotted identifiers.
    /// Used to resolve variables in a `when` or `requires`.
    pub parent_variables: &'s HashMap<String, OwnedConcreteOperand>,
    pub local_variables: HashMap<&'s str, ConcreteOperand<'s>>,
}

#[derive(Debug, Clone)]
pub struct OwnedEvaluationContext {
    pub variables: HashMap<String, OwnedConcreteOperand>,
}

impl OwnedEvaluationContext {
    pub fn empty() -> Self {
        Self {
            variables: HashMap::new(),
        }
    }

    #[allow(dead_code)]
    pub fn insert(&mut self, key: String, value: OwnedConcreteOperand) {
        self.variables.insert(key, value);
    }

    pub fn fork<'s>(&'s self) -> EvaluationContext<'s> {
        EvaluationContext {
            parent_variables: &self.variables,
            local_variables: HashMap::new(),
        }
    }
}

#[allow(dead_code)]
pub struct RequestAssessment<'s> {
    /// Which policy decided this assessment?
    policy: PolicyContext<'s>,
    /// What is the concrete action to take?
    pub action: Action,
    /// What is the context that lead to the require to be fulfilled?
    direct_require_context: Option<RequireContext<'s>>,
    /// What are the contexts of the previous requires which still fulfills the `when` condition of
    /// this request that enables a positive action, e.g. redirection or allow?
    allow_require_contexts: Vec<RequireContext<'s>>,
    redirect_require_contexts: Vec<RequireContext<'s>>,
}

#[derive(Debug, Error)]
pub enum InterpretationError<'s> {
    #[error("Variable '{0}' is missing in the context")]
    MissingVariableInContext(Cow<'s, str>),
    #[error("Comparison error: '{0}'")]
    ComparisonError(ComparisonError<'s>),
}

#[allow(clippy::result_large_err)]
impl<'s> EvaluationContext<'s> {
    pub fn insert(&mut self, key: &'s str, value: ConcreteOperand<'s>) {
        self.local_variables.insert(key, value);
    }

    pub fn resolve_variable(&self, name: &str) -> Option<ConcreteOperand<'s>> {
        self.local_variables
            .get(name)
            .cloned()
            .or_else(|| self.parent_variables.get(name).map(|var| var.as_ref()))
    }

    fn concretize_operand(
        &self,
        operand: &'s Operand,
    ) -> Result<ConcreteOperand<'s>, InterpretationError<'s>> {
        match operand {
            Operand::Identifier(id) => {
                if let Some(var) = self.resolve_variable(id.as_str()) {
                    Ok(var)
                } else {
                    Err(InterpretationError::MissingVariableInContext(
                        Cow::Borrowed(id),
                    ))
                }
            }
            Operand::DottedIdentifier(id) => {
                let key = id.join(".");
                if let Some(var) = self.resolve_variable(key.as_str()) {
                    Ok(var)
                } else {
                    Err(InterpretationError::MissingVariableInContext(Cow::Owned(
                        key,
                    )))
                }
            }
            Operand::Set(s) => Ok(ConcreteOperand::Set(s.iter().map(|s| s.as_str()).collect())),
            Operand::Regex(r) => Ok(ConcreteOperand::Regex(r)),
            Operand::String(s) => Ok(ConcreteOperand::String(s)),
            Operand::Number(n) => Ok(ConcreteOperand::Number(*n)),
            Operand::Boolean(b) => Ok(ConcreteOperand::Boolean(*b)),
        }
    }

    fn evaluate_expression(&self, expr: &'s Expression) -> Result<bool, InterpretationError<'s>> {
        Ok(match expr {
            Expression::Or(lhs, rhs) => {
                self.evaluate_expression(lhs)? || self.evaluate_expression(rhs)?
            }
            Expression::And(lhs, rhs) => {
                self.evaluate_expression(lhs)? && self.evaluate_expression(rhs)?
            }
            Expression::Not(operand) => !self.evaluate_expression(operand)?,
            Expression::Group(operand) => self.evaluate_expression(operand)?,
            Expression::Comparison(lhs, comp, rhs) => {
                let lhs: ConcreteOperand = self.concretize_operand(lhs)?;
                let rhs: ConcreteOperand = self.concretize_operand(rhs)?;

                ConcreteOperand::compare(lhs, comp, rhs)
                    .map_err(InterpretationError::ComparisonError)?
            }
        })
    }

    /// Given the current context, perform the "ideal" route assessment to open the connection.
    /// The caller can ignore this route if it's dysfunctional but should report it loudly and
    /// failover.
    pub fn evaluate_routes(
        &self,
        rules: &'s hir::ACLHir,
    ) -> Result<Vec<&'s BackendSettings>, InterpretationError<'s>> {
        let mut routes = Vec::new();
        // At this point, we can assume that the set of rules are parsed and validated.
        // So we can assume each policy block contain the relevant amount of information and we
        // can freely panic here if it's not the way intended.
        for entry in &rules.routes {
            let active = if let Some(ref when_expr) = entry.when {
                self.evaluate_expression(when_expr)?
            } else {
                true
            };

            if !active {
                continue;
            }

            // We fulfill when, let's look at the recommended routes.
            routes.reserve(entry.r#use.len());
            for reco in &entry.r#use {
                routes.push(reco);
            }
        }

        Ok(routes)
    }

    /// Given the current context, assess this request.
    /// This means calculating the when conditions and the require conditions and therefore the
    /// associated action.
    /// The system is made to be explainable so it allows for tracing why decisions were taken that
    /// way and contain the trace of all the previous rule evaluations.
    pub fn evaluate_request(
        &self,
        rules: &'s hir::ACLHir,
    ) -> Result<RequestAssessment<'s>, InterpretationError<'s>> {
        for entry in &rules.policies {
            let active = if let Some(ref when_expr) = entry.when {
                self.evaluate_expression(when_expr)?
            } else {
                true
            };

            if !active {
                continue;
            }

            // Evaluate whether we fulfill the `require` conditions.
            let pass_requirements = if let Some(ref require_expr) = entry.require {
                self.evaluate_expression(require_expr)?
            } else {
                true
            };

            if !pass_requirements {
                continue;
            }

            // We fulfill when and require, let's return the action.
            return Ok(RequestAssessment {
                policy: PolicyContext {
                    policy_name: &entry.name,
                    when_results: vec![],
                },
                action: entry.action.clone(),
                direct_require_context: None,
                allow_require_contexts: vec![],
                redirect_require_contexts: vec![],
            });
        }

        // By default, we will deny everything.
        Ok(RequestAssessment {
            policy: PolicyContext {
                policy_name: "internal default policy",
                when_results: vec![],
            },
            action: Action::Deny(None),
            direct_require_context: None,
            allow_require_contexts: vec![],
            redirect_require_contexts: vec![],
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        acl::{Action, OwnedEvaluationContext},
        config::BackendSettings,
    };

    #[cfg(test)]
    mod tests {
        use crate::acl::{
            Action, EvaluationContext, OwnedEvaluationContext,
            ast::{Comparator, ConcreteOperand, Expression, Operand},
            hir::{ACLHir, PolicyDefinition},
        };

        #[test]
        fn test_policy_fail_unknown_variable() {
            let hir = ACLHir {
                routes: vec![],
                policies: vec![PolicyDefinition {
                    name: "check_user".to_string(),
                    when: None,
                    require: Some(Expression::Comparison(
                        Operand::Identifier("user".to_string()),
                        Comparator::Eq,
                        Operand::String("admin".to_string()),
                    )),
                    action: Action::Allow,
                }],
            };

            let ctx = OwnedEvaluationContext::empty();
            let ctx = ctx.fork();
            let assessment = ctx.evaluate_request(&hir);
            assert!(assessment.is_err());
        }

        #[test]
        fn test_policy_fail_wrong_type() {
            let hir = ACLHir {
                routes: vec![],
                policies: vec![PolicyDefinition {
                    name: "check_user".to_string(),
                    when: None,
                    require: Some(Expression::Comparison(
                        Operand::Identifier("user".to_string()),
                        Comparator::Eq,
                        Operand::String("admin".to_string()),
                    )),
                    action: Action::Allow,
                }],
            };

            let ctx = OwnedEvaluationContext::empty();
            let mut ctx = ctx.fork();
            ctx.insert("user", ConcreteOperand::Number(10));

            let assessment = ctx.evaluate_request(&hir);
            assert!(assessment.is_err());
        }

        #[test]
        fn test_policy_pass_with_variables() {
            let hir = ACLHir {
                routes: vec![],
                policies: vec![PolicyDefinition {
                    name: "check_user".to_string(),
                    when: None,
                    require: Some(Expression::Comparison(
                        Operand::Identifier("user".to_string()),
                        Comparator::Eq,
                        Operand::String("admin".to_string()),
                    )),
                    action: Action::Allow,
                }],
            };

            let ctx = OwnedEvaluationContext::empty();
            let mut ctx = ctx.fork();
            ctx.insert("user", ConcreteOperand::String("admin"));

            let assessment = ctx.evaluate_request(&hir).unwrap();
            assert!(matches!(assessment.action, Action::Allow));
        }

        #[test]
        fn test_policy_reject_with_variables() {
            let hir = ACLHir {
                routes: vec![],
                policies: vec![PolicyDefinition {
                    name: "check_user".to_string(),
                    when: None,
                    require: Some(Expression::Comparison(
                        Operand::Identifier("user".to_string()),
                        Comparator::Eq,
                        Operand::String("admin".to_string()),
                    )),
                    action: Action::Allow,
                }],
            };

            let ctx = OwnedEvaluationContext::empty();
            let mut ctx = ctx.fork();
            ctx.insert("user", ConcreteOperand::String("user"));

            let assessment = ctx.evaluate_request(&hir).unwrap();
            assert!(matches!(assessment.action, Action::Deny(_)));
        }

        #[test]
        fn test_in_operator() {
            use crate::acl::Action;
            use crate::acl::EvaluationContext;
            use crate::acl::ast::{Comparator, ConcreteOperand, Expression, Operand};
            use crate::acl::hir::{ACLHir, PolicyDefinition};

            let hir = ACLHir {
                routes: vec![],
                policies: vec![PolicyDefinition {
                    name: "check_group".to_string(),
                    when: None,
                    require: Some(Expression::Comparison(
                        Operand::Identifier("user".to_string()),
                        Comparator::In,
                        Operand::Set(
                            vec!["alice".to_string(), "bob".to_string()]
                                .into_iter()
                                .collect(),
                        ),
                    )),
                    action: Action::Allow,
                }],
            };

            let ctx = OwnedEvaluationContext::empty();
            let mut ctx = ctx.fork();
            ctx.insert("user", ConcreteOperand::String("alice"));

            let assessment = ctx.evaluate_request(&hir).unwrap();
            assert!(matches!(assessment.action, Action::Allow));

            ctx.insert("user", ConcreteOperand::String("eve"));
            let assessment = ctx.evaluate_request(&hir).unwrap();
            assert!(matches!(assessment.action, Action::Deny(_)));
        }
    }

    #[test]
    fn test_regex_match_operator() {
        use crate::acl::Action;
        use crate::acl::EvaluationContext;
        use crate::acl::ast::{Comparator, ConcreteOperand, Expression, Operand};
        use crate::acl::hir::{ACLHir, PolicyDefinition};

        let hir = ACLHir {
            routes: vec![],
            policies: vec![PolicyDefinition {
                name: "check_email".to_string(),
                when: None,
                require: Some(Expression::Comparison(
                    Operand::Identifier("email".to_string()),
                    Comparator::Regex,
                    Operand::Regex(regex::Regex::new(r"^\w+@example\.com$").unwrap()),
                )),
                action: Action::Allow,
            }],
        };

        let ctx = OwnedEvaluationContext::empty();
        let mut ctx = ctx.fork();
        ctx.insert("email", ConcreteOperand::String("user@example.com"));
        let assessment = ctx.evaluate_request(&hir).unwrap();
        assert!(matches!(assessment.action, Action::Allow));

        ctx.insert("email", ConcreteOperand::String("user@gmail.com"));
        let assessment = ctx.evaluate_request(&hir).unwrap();
        assert!(matches!(assessment.action, Action::Deny(_)));
    }

    #[test]
    fn test_fail_close_missing_policies() {
        use crate::acl::EvaluationContext;
        use crate::acl::hir::ACLHir;

        let hir = ACLHir {
            routes: vec![],
            policies: vec![],
        };

        let ctx = OwnedEvaluationContext::empty();
        let mut ctx = ctx.fork();
        let assessment = ctx.evaluate_request(&hir).unwrap();
        assert!(matches!(assessment.action, Action::Deny(_)));
    }

    #[test]
    fn test_complex_boolean_expression() {
        use crate::acl::ast::{Comparator, ConcreteOperand, Expression, Operand};
        use crate::acl::hir::{ACLHir, PolicyDefinition};
        use crate::acl::{Action, EvaluationContext};

        let expr = Expression::Or(
            Box::new(Expression::And(
                Box::new(Expression::Comparison(
                    Operand::Identifier("A".to_string()),
                    Comparator::Eq,
                    Operand::Boolean(true),
                )),
                Box::new(Expression::Not(Box::new(Expression::Comparison(
                    Operand::Identifier("B".to_string()),
                    Comparator::Eq,
                    Operand::Boolean(true),
                )))),
            )),
            Box::new(Expression::Comparison(
                Operand::Identifier("C".to_string()),
                Comparator::Eq,
                Operand::Boolean(true),
            )),
        );

        let hir = ACLHir {
            routes: vec![],
            policies: vec![PolicyDefinition {
                name: "complex_expr".to_string(),
                when: Some(expr),
                require: None,
                action: Action::Allow,
            }],
        };

        let ctx = OwnedEvaluationContext::empty();
        let mut ctx = ctx.fork();
        ctx.insert("A", ConcreteOperand::Boolean(true));
        ctx.insert("B", ConcreteOperand::Boolean(false));
        ctx.insert("C", ConcreteOperand::Boolean(false));

        let assessment = ctx.evaluate_request(&hir).unwrap();
        assert!(matches!(assessment.action, Action::Allow));

        ctx.insert("A", ConcreteOperand::Boolean(false));
        ctx.insert("C", ConcreteOperand::Boolean(false));
        let assessment = ctx.evaluate_request(&hir).unwrap();
        assert!(matches!(assessment.action, Action::Deny(_)));
    }

    #[test]
    fn test_route_evaluation() {
        use crate::acl::hir::{ACLHir, RouteDefinition};

        let backend1 = BackendSettings {
            target_address: "1.1.1.1:443".parse().unwrap(),
            identity_aware: false,
            tls_server_name: None,
        };
        let backend2 = BackendSettings {
            target_address: "1.1.1.2:443".parse().unwrap(),
            identity_aware: false,
            tls_server_name: None,
        };

        let hir = ACLHir {
            routes: vec![RouteDefinition {
                when: None,
                name: "route_to_cf".to_string(),
                r#use: vec![backend1, backend2],
            }],
            policies: vec![],
        };

        let ctx = OwnedEvaluationContext::empty();
        let ctx = ctx.fork();
        let routes = ctx.evaluate_routes(&hir).unwrap();
        assert_eq!(routes.len(), 2);
    }
}
