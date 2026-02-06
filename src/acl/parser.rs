use std::path::Path;
use anyhow::Context;
use thiserror::Error;
use winnow::{
    ModalResult, Parser, ascii::{Caseless, alphanumeric1, multispace0, multispace1, till_line_ending}, combinator::{alt, opt, preceded, repeat, separated}, error::{ContextError, ParseError, StrContext}, stream::AsChar, token::{take_till, take_while}
};
use tracing::info;

#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    Allow,
    Deny,
    Redirect(fast_socks5::util::target_addr::TargetAddr), // Redirect to a new hostname
    Log(String), // Log action with the log message
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Operator {
    Equals,
    NotEquals,
    LessThan,
    GreaterThan,
    LessThanOrEqual,
    GreaterThanOrEqual,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Condition {
    pub key: String,
    pub value: String,
    pub operator: Operator,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Hostname {
    Exact(String),
    Regex(String),
}

#[derive(Debug, Clone, PartialEq)]
pub struct ACLRule {
    pub hostname: Hostname,
    pub conditions: Vec<Condition>,
    pub backends: Option<Vec<String>>,
    pub action: Action,
}

#[derive(Debug)]
pub struct ACLError {
    message: String,
    span: std::ops::Range<usize>,
    input: String,
}

impl ACLError {
    fn from_parse(error: ParseError<&str, ContextError>) -> Self {
        Self {
            message: error.inner().to_string(),
            input: (*error.input()).to_owned(),
            span: error.char_span()
        }
    }
}

impl std::fmt::Display for ACLError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = annotate_snippets::Level::ERROR.primary_title(&self.message)
            .element(annotate_snippets::Snippet::source(&self.input)
                .fold(true)
                .annotation(annotate_snippets::AnnotationKind::Primary.span(self.span.clone()))
            );
        let renderer = annotate_snippets::Renderer::plain();
        let rendered = renderer.render(&[message]);
        rendered.fmt(f)
    }
}

impl std::error::Error for ACLError { }

fn parse_regex_hostname(input: &mut &str) -> ModalResult<Hostname> {
    take_till(1.., AsChar::is_space)
    .map(|regex: &str| Hostname::Regex(regex.to_string()))
    .parse_next(input)
}

fn parse_plain_hostname(input: &mut &str) -> ModalResult<Hostname> {
    take_till(1.., AsChar::is_space).map(|hostname: &str| Hostname::Exact(hostname.to_string())).parse_next(input)
}

fn parse_hostname(input: &mut &str) -> ModalResult<Hostname> {
    alt((parse_regex_hostname.context(StrContext::Label("a hostname regex")), parse_plain_hostname)).parse_next(input)
}

fn parse_operator(input: &mut &str) -> ModalResult<Operator> {
    alt((
        '='.map(|_| Operator::Equals),
        "!=".map(|_| Operator::NotEquals),
        "<=".map(|_| Operator::LessThanOrEqual),
        ">=".map(|_| Operator::GreaterThanOrEqual),
        "<".map(|_| Operator::LessThan),
        ">".map(|_| Operator::GreaterThan),
    )).parse_next(input)
}

fn parse_key<'a>(input: &mut &'a str) -> ModalResult<&'a str> {
    take_while(
        1..,
        |c: char| c.is_alphanumeric() || c == '.' || c == '_'
    ).parse_next(input)
}

fn parse_condition_with_operator(input: &mut &str) -> ModalResult<Condition> {
    (parse_key.context(StrContext::Label("condition identifier")), parse_operator.context(StrContext::Label("condition operator")), take_till(1.., AsChar::is_space).context(StrContext::Label("condition value")))
        .map(|(key, operator, value): (&str, Operator, &str)| Condition {
            key: key.to_string(),
            value: value.to_string(),
            operator,
        })
        .parse_next(input)
}

fn parse_action(input: &mut &str) -> ModalResult<Action> {
    alt((
        Caseless("allow").map(|_| Action::Allow),
        Caseless("deny").map(|_| Action::Deny),
        preceded(Caseless("log="), till_line_ending)
        .map(
            |s: &str| Action::Log(s.to_string())
        )
    )).parse_next(input)
}

fn parse_backends<'a>(input: &mut &'a str) -> ModalResult<Vec<&'a str>> {
    preceded("backends=", separated(0.., alphanumeric1.context(StrContext::Label("backend")), ",")).parse_next(input)
}

fn parse_conditions(input: &mut &str) -> ModalResult<Vec<Condition>> {
    separated(0.., parse_condition_with_operator.context(StrContext::Label("condition")), " ").parse_next(input)
}

fn parse_comment<'a>(input: &mut &'a str) -> ModalResult<&'a str> {
    preceded('#', till_line_ending).parse_next(input)
}


fn parse_comments_or_empty(input: &mut &str) -> ModalResult<()> {
    repeat(1..,
        alt((
            multispace1.context(StrContext::Label("empty line")).void(),
            parse_comment.context(StrContext::Label("comment")).void(),
        )).void()
    )
    .parse_next(input)
}

fn parse_acl_rule(input: &mut &str) -> ModalResult<ACLRule> {
    // TODO: make use of permutation for the RHS of ->.
    (
        opt(parse_comments_or_empty),
        parse_hostname.context(StrContext::Label("hostname")),
        multispace1,
        parse_conditions.context(StrContext::Label("conditions")),
        multispace1,
        "->",
        multispace1,
        opt((parse_backends.context(StrContext::Label("backends")), multispace1)),
        parse_action.context(StrContext::Label("action")),
        till_line_ending,
        multispace0,
    )
    .map(|(_, hostname, _, conditions, _, _, _, backends, action, _, _)| ACLRule {
        hostname,
        conditions,
        backends: backends.map(|(v, _)| v.into_iter().map(|s| s.to_owned()).collect()),
        action,
    })
    .parse_next(input)
}

pub fn parse_acl_rules<'i>(input: &mut &'i str) -> Result<Vec<ACLRule>, ACLError> {
    // TODO: this is very wrong, this doesn't support broken parses because repeat() will just
    // ignore.
    // we need to peek if after comments + empty + parsing hostname, then the parsing must succeed
    // or this is a malformed ACL rule.
    repeat(0..,
        parse_acl_rule.context(StrContext::Label("ACL rule")),
    )
    .parse(input)
    .map_err(ACLError::from_parse)
}

pub fn load_rules_from_file(path: &Path) -> anyhow::Result<Vec<ACLRule>> {
    let contents = String::from_utf8_lossy(&std::fs::read(path).context("while reading ACL file")?).into_owned();
    let rules = parse_acl_rules(&mut contents.as_str()).context("while parsing ACL rules")?;
    info!("Parsed {} ACL rules", rules.len());
    Ok(rules)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_acl_rule_with_comment_before_rule() {
        let mut input = "# This is a comment\n\n \n # This is another comment\n git.corp.example.com device.trust_level=high -> allow";
        let results = parse_acl_rules(&mut input).unwrap();

        assert_eq!(results, vec![ACLRule {
            hostname: Hostname::Regex("git.corp.example.com".to_string()),
            conditions: vec![
                Condition { key: "device.trust_level".to_string(), value: "high".to_string(), operator: Operator::Equals }
            ],
            backends: None,
            action: Action::Allow,
        }]);
    }

    #[test]
    fn test_parse_acl_rule_with_exact_hostname() {
        let mut input = "git.corp.example.com device.trust_level=high -> allow";
        let result = parse_acl_rule(&mut input).unwrap();

        assert_eq!(result, ACLRule {
            hostname: Hostname::Regex("git.corp.example.com".to_string()),
            conditions: vec![
                Condition { key: "device.trust_level".to_string(), value: "high".to_string(), operator: Operator::Equals }
            ],
            backends: None,
            action: Action::Allow,
        });
    }

    #[test]
    fn test_parse_acl_rule_with_regex_hostname() {
        let mut input = ".*\\.infra.corp.example.com device.trust_level=low -> allow";
        let result = parse_acl_rule(&mut input).unwrap();
        assert_eq!(result, ACLRule {
            hostname: Hostname::Regex(".*\\.infra.corp.example.com".to_string()),
            conditions: vec![
                Condition { key: "device.trust_level".to_string(), value: "low".to_string(), operator: Operator::Equals }
            ],
            backends: None,
            action: Action::Allow,
        });
    }

    #[test]
    fn test_parse_acl_rule_with_regex_star_hostname() {
        let mut input = ".* device.trust_level=low -> allow";
        let result = parse_acl_rule(&mut input);
        assert_eq!(result, Ok(ACLRule {
            hostname: Hostname::Regex(".*".to_string()),
            conditions: vec![
                Condition { key: "device.trust_level".to_string(), value: "low".to_string(), operator: Operator::Equals }
            ],
            backends: None,
            action: Action::Allow,
        }));
    }

    #[test]
    fn test_parse_acl_rule_with_operator() {
        let mut input = "git.corp.example.com device.security_patch_age<1d -> allow";
        let result = parse_acl_rule(&mut input);
        assert_eq!(result, Ok(ACLRule {
            hostname: Hostname::Regex("git.corp.example.com".to_string()),
            conditions: vec![
                Condition { key: "device.security_patch_age".to_string(), value: "1d".to_string(), operator: Operator::LessThan }
            ],
            backends: None,
            action: Action::Allow,
        }));
    }

    #[test]
    fn test_parse_acl_rule_with_log_action() {
        let mut input = "git.corp.example.com device.trust_level=low user.group=eng -> log=slow_patching";
        let result = parse_acl_rule(&mut input);
        assert_eq!(result, Ok(ACLRule {
            hostname: Hostname::Regex("git.corp.example.com".to_string()),
            conditions: vec![
                Condition { key: "device.trust_level".to_string(), value: "low".to_string(), operator: Operator::Equals },
                Condition { key: "user.group".to_string(), value: "eng".to_string(), operator: Operator::Equals }
            ],
            backends: None,
            action: Action::Log("slow_patching".to_string()),
        }));
    }

    #[test]
    fn test_parse_acl_rule_with_multiple_conditions() {
        let mut input = "git.par01.corp.example.com device.trust_level=low user.group=eng -> backends=par01a,par01b,default allow";
        let result = parse_acl_rule(&mut input);
        assert_eq!(result, Ok(ACLRule {
            hostname: Hostname::Regex("git.par01.corp.example.com".to_string()),
            conditions: vec![
                Condition { key: "device.trust_level".to_string(), value: "low".to_string(), operator: Operator::Equals },
                Condition { key: "user.group".to_string(), value: "eng".to_string(), operator: Operator::Equals }
            ],
            backends: Some(vec!["par01a".to_string(), "par01b".to_string(), "default".to_string()]),
            action: Action::Allow,
        }));
    }
}
