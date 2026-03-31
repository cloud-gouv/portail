pub mod ast;
pub mod evaluator;
pub mod hir;
pub mod parser;

use std::path::Path;

pub use ast::Action;
pub use evaluator::{EvaluationContext, OwnedEvaluationContext};
pub use hir::{ACLHir, ast_to_hir};
pub use parser::parse_into_ast;
use thiserror::Error;

use crate::config::Settings;

#[derive(Debug, Clone)]
pub struct ACLRules {
    pub hir: ACLHir,
}

#[derive(Debug, Error)]
pub enum LoadError {
    #[error("While reading the ACL rules: {0}")]
    IO(#[from] std::io::Error),
    #[error("While parsing the ACL rules into an AST: {0}")]
    ASTParseError(#[from] parser::ASTError),
    #[error("During the AST to HIR transformation: {0}")]
    HIRTransformationError(#[from] hir::TransformationError),
}

/// This performs parsing and transformation to the target IR for ACLs.
/// This target IR can be used to assess requests and routes to be taken.
pub fn load_rules_from_file<P: AsRef<Path>>(
    path: P,
    settings: &Settings,
) -> Result<ACLRules, LoadError> {
    let acl_contents = std::fs::read_to_string(path)?;
    load_rules_from_str(&acl_contents, settings)
}

pub fn load_rules_from_str<'s>(
    contents: &'s str,
    settings: &Settings,
) -> Result<ACLRules, LoadError> {
    let ast = parse_into_ast(contents)?;
    let hir = ast_to_hir(ast, &settings.backends)?;

    Ok(ACLRules { hir })
}
