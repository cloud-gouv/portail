//! Template rendering for error and explain pages.
//!
//! Templates use a simple `{{ var }}` syntax, similar to Jinja2. All variables are HTML-escaped
//! except `downstream_body`, which is injected as raw HTML (trusted upstream proxy contents).

use std::{collections::HashMap, path::Path};

use crate::acl::ast::OwnedConcreteOperand;

pub mod defaults;

#[derive(Debug, Clone)]
pub struct TemplateContext {
    pub trace_id: uuid::Uuid,
    pub client_address: String,
    pub timestamp: String,
    pub variables: HashMap<String, OwnedConcreteOperand>,
}

pub enum TemplateScenario {
    HttpCode(hyper::StatusCode),
    FilterACL {
        action: crate::acl::Action,
        filter_template: Option<String>,
        explain_template: Option<String>,
    },
}

pub struct TemplateRegistry {
    overrides: HashMap<String, String>,
}

impl TemplateRegistry {
    //pub fn new<P: AsRef<Path>>(template_dir: Option<P>) -> Self {
    //    // Read overrides if necessary.
    //}

    //fn resolve(&self, scenario: &TemplateScenario) -> Option<&str> {
    //    match scenario {
    //        TemplateScenario::HttpCode(status_code) => {}
    //        TemplateScenario::FilterACL {
    //            action,
    //            filter_template,
    //            explain_template,
    //        } => explain_template
    //            .as_ref()
    //            .map(String::as_str)
    //            .or(filter_template.as_ref().map(String::as_str)),
    //    }
    //}

    //pub fn render(&self, scenario: TemplateScenario, ctx: &TemplateContext) -> String {}
}
