use std::collections::HashSet;
use std::path::PathBuf;

use regex::Regex;
use winnow::ModalResult;
use winnow::ascii::{digit1, multispace1};
use winnow::combinator::{alt, cut_err, dispatch, fail, opt, preceded, repeat, separated};
use winnow::error::{
    ContextError, ErrMode, FromExternalError, ParseError, StrContext, StrContextValue,
};
use winnow::token::take;
use winnow::{
    Parser, Result, ascii::multispace0, combinator::delimited, error::ParserError,
    token::take_while,
};

use crate::acl::ast::{
    ACLAst, ACLEntry, Action, Comparator, Expression, Operand, PolicyAttribute, PolicyBlock,
    RouteAttribute, RouteDefinition,
};

fn ws<'a, O, F: Parser<&'a str, O, E>, E: ParserError<&'a str>>(
    inner: F,
) -> impl Parser<&'a str, O, E> {
    delimited(multispace0, inner, multispace0)
}

fn identifier<'s>(input: &mut &'s str) -> ModalResult<&'s str> {
    take_while(1.., |c: char| c.is_alphanumeric() || c == '_' || c == '-')
        .context(StrContext::Label("identifier"))
        .context(StrContext::Expected(StrContextValue::Description(
            "alphanumeric with _ or -",
        )))
        .parse_next(input)
}

fn string_literal<'s>(input: &mut &'s str) -> ModalResult<&'s str> {
    // FIXME: use `take_escaped` or `escaped` here.
    delimited("\"", take_while(0.., |c| c != '"'), "\"")
        .context(StrContext::Label("string literal"))
        .parse_next(input)
}

fn number(input: &mut &str) -> ModalResult<i64> {
    let negative = opt('-').parse_next(input)?.is_some();

    digit1
        .context(StrContext::Label("number"))
        .parse_to()
        .verify_map(|v: i64| if negative { v.checked_neg() } else { Some(v) })
        .parse_next(input)
}

fn boolean(input: &mut &str) -> ModalResult<bool> {
    alt((
        "true",
        "false",
        fail.context(StrContext::Label("boolean"))
            .context(StrContext::Expected(StrContextValue::StringLiteral("true")))
            .context(StrContext::Expected(StrContextValue::StringLiteral(
                "false",
            ))),
    ))
    .parse_to()
    .parse_next(input)
}

fn dotted_identifier(input: &mut &str) -> ModalResult<Vec<String>> {
    (identifier, repeat(1.., preceded(".", identifier)))
        .map(|(first, rest): (_, Vec<_>)| {
            let mut path = Vec::with_capacity(1 + rest.len());
            path.push(first.to_owned());
            path.append(&mut rest.into_iter().map(|s| s.to_owned()).collect());
            path
        })
        .context(StrContext::Label("identifiers separated by dots"))
        .parse_next(input)
}

fn comparator(input: &mut &str) -> ModalResult<Comparator> {
    alt((
        "==".value(Comparator::Eq),
        "!=".value(Comparator::Ne),
        "=~".value(Comparator::Regex),
        "<=".value(Comparator::Lte),
        ">=".value(Comparator::Gte),
        "<".value(Comparator::Lt),
        ">".value(Comparator::Gt),
        "in".value(Comparator::In),
        fail.context(StrContext::Label("comparator")),
    ))
    .parse_next(input)
}

fn operand(input: &mut &str) -> ModalResult<Operand> {
    alt((
        boolean.map(Operand::Boolean),
        number.map(Operand::Number),
        string_literal.map(|s| Operand::String(s.to_owned())),
        dotted_identifier.map(Operand::DottedIdentifier),
        identifier.map(|s| Operand::Identifier(s.to_owned())),
        fail.context(StrContext::Label("operand")),
    ))
    .parse_next(input)
}

fn parse_set_string(input: &mut &str) -> ModalResult<HashSet<String>> {
    delimited(
        "[",
        separated(0.., ws(string_literal), ","),
        (opt(ws(",")), "]"),
    )
    .map(|items: Vec<_>| items.into_iter().map(|s| s.to_owned()).collect())
    .context(StrContext::Label("set of string literals"))
    .parse_next(input)
}

fn parse_regex(input: &mut &str) -> ModalResult<Regex> {
    let raw_regex = string_literal.parse_next(input)?;

    match Regex::new(raw_regex) {
        Ok(re) => Ok(re),
        Err(err) => Err(ErrMode::Cut(ContextError::from_external_error(input, err))),
    }
}

fn comparison(input: &mut &str) -> ModalResult<Expression> {
    let lhs = operand
        .context(StrContext::Label("left operand"))
        .parse_next(input)?;
    let comparator = ws(comparator).parse_next(input)?;
    let rhs = match comparator {
        Comparator::In => cut_err(parse_set_string)
            .map(Operand::Set)
            .context(StrContext::Label("right set of string operand"))
            .parse_next(input)?,
        Comparator::Regex => cut_err(parse_regex)
            .map(Operand::Regex)
            .context(StrContext::Label("right regex operand"))
            .parse_next(input)?,
        Comparator::Lt | Comparator::Gt | Comparator::Lte | Comparator::Gte => cut_err(number)
            .map(Operand::Number)
            .context(StrContext::Label("right number operand"))
            .parse_next(input)?,
        _ => cut_err(operand).parse_next(input)?,
    };

    Ok(Expression::Comparison(lhs, comparator, rhs))
}

fn atom_expression(input: &mut &str) -> ModalResult<Expression> {
    alt((
        ws(comparison),
        delimited(ws("("), cut_err(expression), ws(")")).map(|e| Expression::Group(Box::new(e))),
        fail.context(StrContext::Label("atomic expression")),
    ))
    .context(StrContext::Label("atomic expression"))
    .parse_next(input)
}

fn not_expression(input: &mut &str) -> ModalResult<Expression> {
    (opt("not"), atom_expression)
        .map(|(not_, expr)| {
            if not_.is_some() {
                Expression::Not(Box::new(expr))
            } else {
                expr
            }
        })
        .context(StrContext::Label("not expression"))
        .parse_next(input)
}

fn and_expression(input: &mut &str) -> ModalResult<Expression> {
    (
        not_expression,
        repeat(0.., preceded(ws("and"), not_expression)),
    )
        .map(|(first, rest): (_, Vec<_>)| {
            rest.into_iter()
                .fold(first, |acc, e| Expression::And(Box::new(acc), Box::new(e)))
        })
        .context(StrContext::Label("and expression"))
        .parse_next(input)
}

fn or_expression(input: &mut &str) -> ModalResult<Expression> {
    (
        and_expression,
        repeat(0.., preceded(ws("or"), and_expression)),
    )
        .map(|(first, rest): (_, Vec<_>)| {
            rest.into_iter()
                .fold(first, |acc, e| Expression::Or(Box::new(acc), Box::new(e)))
        })
        .parse_next(input)
}

fn expression(input: &mut &str) -> ModalResult<Expression> {
    or_expression(input)
}

fn policy_when_statement(input: &mut &str) -> ModalResult<PolicyAttribute> {
    expression
        .map(PolicyAttribute::When)
        .context(StrContext::Label("policy when statement"))
        .parse_next(input)
}

fn require_statement(input: &mut &str) -> ModalResult<PolicyAttribute> {
    expression
        .map(PolicyAttribute::Require)
        .context(StrContext::Label("require statement"))
        .parse_next(input)
}

fn action_statement(input: &mut &str) -> ModalResult<Action> {
    // FIXME: move this to dispatch! ?
    alt((
        "allow".value(Action::Allow),
        (
            "deny",
            opt(preceded(
                preceded(multispace1, "explain-template="),
                cut_err(string_literal.parse_to::<PathBuf>()),
            )),
        )
            .map(|(_, tpl)| Action::Deny(tpl)),
        preceded(
            "redirect",
            cut_err(
                preceded(multispace1, string_literal)
                    .parse_to::<http::Uri>()
                    .context(StrContext::Label("URI")),
            ),
        )
        .map(|s| Action::Redirect(s.to_owned())),
        fail.context(StrContext::Label("action statement"))
            .context(StrContext::Expected(StrContextValue::Description(
                "allow, deny [explain-template=] or redirect",
            ))),
    ))
    .context(StrContext::Label("action statement"))
    .parse_next(input)
}

fn braced_body<'s, T, P>(parser: P) -> impl Parser<&'s str, T, ErrMode<ContextError>>
where
    P: Parser<&'s str, T, ErrMode<ContextError>>,
{
    delimited("{", ws(parser), cut_err("}"))
}

fn action_attribute(input: &mut &str) -> ModalResult<PolicyAttribute> {
    // FIXME: move all alt(braced_body(T), T) to dispatch! { take(1usize); "{" => braced_body(T), _
    // => T } rather.
    ws(alt((
        braced_body(cut_err(action_statement)),
        action_statement,
        fail.context(StrContext::Label("action attribute")),
    )))
    .map(PolicyAttribute::Action)
    .context(StrContext::Label("action attribute"))
    .parse_next(input)
}

fn policy_when_attribute(input: &mut &str) -> ModalResult<PolicyAttribute> {
    ws(alt((
        braced_body(cut_err(policy_when_statement)),
        policy_when_statement,
        fail.context(StrContext::Label("policy when attribute")),
    )))
    .context(StrContext::Label("policy when attribute"))
    .parse_next(input)
}

fn require_attribute(input: &mut &str) -> ModalResult<PolicyAttribute> {
    ws(alt((
        braced_body(cut_err(require_statement)),
        require_statement,
    )))
    .context(StrContext::Label("require attribute"))
    .parse_next(input)
}

fn policy_attribute(input: &mut &str) -> ModalResult<PolicyAttribute> {
    dispatch! { take(1usize);
        "w" => preceded("hen ", policy_when_attribute),
        "r" => preceded("equire ", require_attribute),
        "a" => preceded("ction ", action_attribute),
        _ => fail
    }
    .context(StrContext::Label("policy attribute"))
    .parse_next(input)
}

fn policy_block<'s>(input: &mut &'s str) -> ModalResult<ACLEntry<'s>> {
    (
        "policy",
        ws(identifier),
        delimited("{", repeat(0.., ws(policy_attribute)), cut_err(ws("}"))),
    )
        .map(|(_, name, attributes): (_, _, Vec<_>)| {
            ACLEntry::Policy(PolicyBlock { name, attributes })
        })
        .context(StrContext::Label("policy block"))
        .parse_next(input)
}

fn use_attribute<'s>(input: &mut &'s str) -> ModalResult<RouteAttribute<'s>> {
    ws((
        "[",
        separated(1.., ws(string_literal), ","),
        opt(ws(",")),
        "]",
    ))
    .map(|(_, targets, _, _): (_, Vec<_>, _, _)| RouteAttribute::Use(targets))
    .context(StrContext::Label("use attribute"))
    .parse_next(input)
}

fn route_when_statement<'s>(input: &mut &'s str) -> ModalResult<RouteAttribute<'s>> {
    expression
        .map(RouteAttribute::When)
        .context(StrContext::Label("route when statement"))
        .parse_next(input)
}

fn route_when_attribute<'s>(input: &mut &'s str) -> ModalResult<RouteAttribute<'s>> {
    ws(alt((
        braced_body(cut_err(route_when_statement)),
        route_when_statement,
    )))
    .context(StrContext::Label("route when attribute"))
    .parse_next(input)
}

fn route_attribute<'s>(input: &mut &'s str) -> ModalResult<RouteAttribute<'s>> {
    dispatch! { take(1usize);
        "w" => preceded("hen ", route_when_attribute),
        "u" => preceded("se ", use_attribute),
        _ => fail,
    }
    .context(StrContext::Label("route attribute"))
    .parse_next(input)
}

fn route_definition<'s>(input: &mut &'s str) -> ModalResult<ACLEntry<'s>> {
    (
        "route",
        ws(identifier),
        delimited(
            cut_err(ws("{")),
            repeat(0.., ws(route_attribute)),
            cut_err(ws("}")),
        ),
    )
        .map(|(_, name, attributes): (_, _, Vec<_>)| {
            ACLEntry::Route(RouteDefinition { name, attributes })
        })
        .context(StrContext::Label("route definition"))
        .parse_next(input)
}

#[derive(Debug)]
pub struct ASTError {
    message: String,
    span: std::ops::Range<usize>,
    input: String,
}

impl std::error::Error for ASTError {}

impl ASTError {
    fn from_parse(error: ParseError<&str, ContextError>) -> Self {
        let message = error.inner().to_string();
        let input = (*error.input()).to_owned();
        let span = error.char_span();

        Self {
            message,
            span,
            input,
        }
    }
}

impl std::fmt::Display for ASTError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use annotate_snippets::*;

        let message = Level::ERROR
            .primary_title("Failure to parse the ACL rules")
            .element(
                Snippet::source(&self.input)
                    .annotation(
                        AnnotationKind::Primary
                            .span(self.span.clone())
                            .label(&self.message),
                    )
                    .fold(false),
            );

        let renderer = Renderer::plain();
        let rendered = renderer.render(&[message]);

        rendered.fmt(f)
    }
}

pub fn parse_into_ast<'s>(input: &'s str) -> Result<ACLAst<'s>, ASTError> {
    repeat(0.., ws(alt((route_definition, policy_block))))
        .map(|entries| ACLAst { entries })
        .context(StrContext::Label("ACL file"))
        .parse(input)
        .map_err(|e| ASTError::from_parse(e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use insta::{assert_debug_snapshot, assert_snapshot};

    // TODO: test ideas
    // - add a lot of whitespace in plenty of areas and ensure it still parses as expected
    // (whitespace insignificance)
    // - add a bunch of semantically wrong rules and verifies it still parses an AST
    // - try to stuck together commands and operands and verify it rejects it or not.

    #[test]
    fn parse_simple_route() {
        let mut input = r#"
            route main {
                use ["exit1", "exit2"]
                when src_ip == "1.2.3.4"
            }
        "#;

        let rules = parse_into_ast(&mut input).unwrap();

        assert_debug_snapshot!("simple_route", rules);
    }

    #[test]
    fn parse_simple_route_with_trailing_commas() {
        let mut input = r#"
            route main {
                use ["exit1", "exit2",]
                when src_ip == "1.2.3.4"
            }
        "#;

        let rules = parse_into_ast(&mut input).unwrap();

        assert_debug_snapshot!("simple_route_with_trailing_commas", rules);
    }

    #[test]
    fn parse_policy_with_action() {
        let mut input = r#"
            policy allow_web {
                require role == "admin" and not banned == true
                action allow
            }
        "#;

        let rules = parse_into_ast(&mut input).unwrap();
        assert_debug_snapshot!("policy_with_action", rules);
    }

    #[test]
    fn parse_policy_with_redirect_action() {
        let mut input = r#"
            policy allow_web_after_auth {
                require role == "admin" and not banned == true
                action redirect                          "https://sso.example.com/login"
            }
        "#;

        let rules = parse_into_ast(&mut input).unwrap();
        assert_debug_snapshot!("policy_with_redirect_action", rules);
    }

    #[test]
    fn parse_policy_with_dotted_identifiers() {
        let mut input = r#"
            policy allow_web {
                require user.role == "admin"
                action allow
            }
        "#;

        let rules = parse_into_ast(&mut input).unwrap();
        assert_debug_snapshot!("policy_with_dotted_identifiers", rules);
    }

    #[test]
    fn parse_complex_acl() {
        let mut input = r#"
            route main {
                when host =~ ".*.corp.example.com"
                use ["exit1"]
            }

            policy corp {
                when host =~ ".*.corp.example.com"
                require user_authed == true
                action allow
            }

            policy deny_all {
                action deny
            }
        "#;

        let rules = parse_into_ast(&mut input).unwrap();
        assert_eq!(rules.entries.len(), 3);

        assert_debug_snapshot!("complex_acl", rules);
    }

    #[test]
    fn parse_deny_templates() {
        let mut input = r#"
            policy deny_all {
                action deny                           explain-template="explain/global-deny.html"
            }
        "#;

        let rules = parse_into_ast(&mut input).unwrap();
        assert_eq!(rules.entries.len(), 1);

        assert_debug_snapshot!("deny_templates", rules);
    }

    #[test]
    fn parse_braces_over_multi_lines() {
        let mut input = r#"
            route main {
                when {
                    host =~ ".*.corp.example.com"
                    and protocol == "tls"
                }

                use ["exit1"]
            }


            policy corp {
                when { host =~ ".*.corp.example.com" and protocol == "tls" }
                require {
                    user_authed == true
                    and trust == "high"
                }

                action allow
            }

            policy deny_all {
                action {
                    deny explain-template="explain/global-deny.html"
                }
            }
        "#;

        let rules = parse_into_ast(&mut input).unwrap();
        assert_eq!(rules.entries.len(), 3);

        assert_debug_snapshot!("acl_with_braces", rules);
    }

    #[test]
    fn parse_valid_empty_policy_block() {
        let mut input = r#"
            policy main {
            }
        "#;

        let result = parse_into_ast(&mut input);

        assert_debug_snapshot!("empty_policy_block", result.unwrap());
    }

    #[test]
    fn parse_valid_with_lots_of_whitespace() {
        let mut input = r#"
            route     main      {
                
                use    [   "exit1"  ,  "exit2"   ]  
                
                when    src_ip    ==    "1.2.3.4"    
            }
        "#;

        let rules = parse_into_ast(&mut input).unwrap();

        assert_debug_snapshot!("route_with_lots_of_whitespace", rules);
    }

    #[test]
    fn parse_valid_with_semantically_wrong_rules() {
        // These are syntactically valid but semantically odd, e.g., using an undefined field
        let mut input = r#"
            policy weird_policy {
                require something_unknown == 42
                require user.undefined_field != "foo"
                action allow
                action deny
                action allow
                action deny
            }
        "#;

        // Should still parse, producing an AST; semantic correctness is checked elsewhere
        let rules = parse_into_ast(&mut input).unwrap();

        assert_debug_snapshot!("semantically_wrong_rules", rules);
    }

    #[test]
    fn parse_valid_duplicate_action_in_a_block() {
        let mut input = r#"
            policy main {
                action allow
                action deny
            }
        "#;
        let result = parse_into_ast(&mut input);

        assert_debug_snapshot!("dup_action", result.unwrap());
    }

    #[test]
    fn parse_valid_duplicate_when_in_a_block() {
        let mut input = r#"
            policy main {
                when host =~ ".*"
                when user.authenticated == true
                action allow
            }
        "#;
        let result = parse_into_ast(&mut input);

        assert_debug_snapshot!("dup_when", result.unwrap());
    }

    #[test]
    fn parse_valid_duplicate_require_in_a_block() {
        let mut input = r#"
            policy main {
                require host =~ ".*"
                require user.authenticated == true
                action allow
            }
        "#;
        let result = parse_into_ast(&mut input);

        assert_debug_snapshot!("dup_req", result.unwrap());
    }

    #[test]
    fn parse_valid_duplicate_policies() {
        let mut input = r#"
            policy main {
                action allow
            }

            policy main {
                action deny
            }
        "#;
        let result = parse_into_ast(&mut input);

        assert_debug_snapshot!("dup_policies", result.unwrap());
    }

    #[test]
    fn parse_valid_deny_with_template() {
        let mut input = r#"
            policy main {
                action deny explain-template="/tmp/my-explain.html"
            }
        "#;
        let result = parse_into_ast(&mut input);

        assert_debug_snapshot!("deny_with_template", result.unwrap());
    }

    #[test]
    fn parse_valid_deny_with_relative_template() {
        let mut input = r#"
            policy main {
                action deny explain-template="./my-explain.html"
            }
        "#;
        let result = parse_into_ast(&mut input);

        assert_debug_snapshot!("deny_with_relative_template", result.unwrap());
    }

    #[test]
    fn parse_valid_integers() {
        let mut input = r#"
            policy int {
                when {
                    a == -1
                    or b <= -50000
                    and c >= 10
                }

                action allow
            }
        "#;

        let result = parse_into_ast(&mut input);

        assert_debug_snapshot!("valid_integers", result.unwrap());
    }

    #[test]
    fn parse_valid_integer_limits() {
        let mut input = r#"
            policy int {
                when {
                    e == 9223372036854775806
                    and g == -9223372036854775807
                }

                action allow
            }
        "#;

        let result = parse_into_ast(&mut input);

        assert_debug_snapshot!("valid_integer_limits", result.unwrap());
    }

    #[test]
    fn parse_valid_expression_precedence() {
        let mut input = r#"
            policy complex_expr {
                when {
                    a == 1
                    or not b == 2
                    and c == 3
                    and not d == 4
                    or not e == 5
                    and f == 6
                }

                action allow
            }
        "#;

        let result = parse_into_ast(&mut input);

        assert_debug_snapshot!("valid_expression_precedence", result.unwrap());
    }

    #[test]
    fn parse_invalid_route_missing_opening_brace() {
        let mut input = r#"
            route main
                use ["exit1"]
        "#;

        let result = parse_into_ast(&mut input);
        assert!(result.is_err(), "Expected parsing error for missing braces");

        assert_snapshot!("invalid_route_missing_opening_brace", result.unwrap_err());
    }

    #[test]
    fn parse_invalid_route_missing_closing_brace() {
        let mut input = r#"
            route main {
                use ["exit1"]
        "#;

        let result = parse_into_ast(&mut input);
        assert!(result.is_err(), "Expected parsing error for missing braces");

        assert_snapshot!("invalid_route_missing_closing_brace", result.unwrap_err());
    }

    #[test]
    fn parse_invalid_policy_missing_brace() {
        let mut input = r#"
            policy no_action {
                require role == "user"
        "#; // missing closing brace

        let result = parse_into_ast(&mut input);
        assert!(
            result.is_err(),
            "Expected parsing error for missing closing brace in policy block"
        );
        assert_snapshot!("invalid_policy_missing_brace", result.unwrap_err());
    }

    #[test]
    fn parse_invalid_expression() {
        let mut input = r#"
            policy bad_expr {
                require role ==
            }
        "#;

        let result = parse_into_ast(&mut input);
        assert!(
            result.is_err(),
            "Expected parsing error for incomplete expression"
        );
        assert_snapshot!("invalid_expression", result.unwrap_err());
    }

    #[test]
    fn parse_invalid_regexp_operand() {
        let mut input = r#"
            policy bad_expr {
                require role =~ "*"
            }
        "#;

        let result = parse_into_ast(&mut input);
        assert!(result.is_err(), "Expected parsing error for invalid regexp");
        assert_snapshot!("invalid_regexp_in_operand", result.unwrap_err());
    }

    #[test]
    fn parse_invalid_integer_regexp_operand() {
        let mut input = r#"
            policy bad_expr {
                require role =~ 2350
            }
        "#;

        let result = parse_into_ast(&mut input);
        assert!(result.is_err(), "Expected parsing error for invalid regexp");
        assert_snapshot!("invalid_integer_in_regexp_operand", result.unwrap_err());
    }

    #[test]
    fn parse_invalid_lte_operand() {
        let mut input = r#"
            policy bad_expr {
                require role <= "abc"
            }
        "#;

        let result = parse_into_ast(&mut input);
        assert!(
            result.is_err(),
            "Expected parsing error for invalid lte operand"
        );
        assert_snapshot!("invalid_type_in_lte_operand", result.unwrap_err());
    }

    #[test]
    fn parse_invalid_in_operand() {
        let mut input = r#"
            policy bad_expr {
                require 5 in 6
            }
        "#;

        let result = parse_into_ast(&mut input);
        assert!(
            result.is_err(),
            "Expected parsing error for invalid in operand"
        );
        assert_snapshot!("invalid_type_in_in_operand", result.unwrap_err());
    }

    #[test]
    fn parse_invalid_stuck_together_commands_should_fail() {
        // Commands and operands without space: "actionallow" instead of "action allow"
        let mut input = r#"
            policy broken_policy {
                actionallow
            }
        "#;

        let result = parse_into_ast(&mut input);
        assert!(
            result.is_err(),
            "Expected parsing error for stuck-together commands"
        );

        assert_snapshot!("stuck_together_commands_error", result.unwrap_err());
    }

    #[test]
    fn parse_invalid_multiple_stuck_together_tokens() {
        let mut input = r#"
            policy broken_policy {
                requireuser.authenticated==true
                actiondeny
            }
        "#;

        let result = parse_into_ast(&mut input);
        assert!(
            result.is_err(),
            "Expected parsing error for stuck-together tokens"
        );

        assert_snapshot!("multiple_stuck_together_tokens_error", result.unwrap_err());
    }

    #[test]
    fn parse_invalid_policy_in_the_middle_of_valid() {
        let mut input = r#"
            policy good1 {
                action allow
            }

            policy good2 {
                action allow
            }

            policy broken {
                when host =~ ".*"
                requirebroken
                action allow
            }

            policy good3 {
                action allow
            }
        "#;

        let result = parse_into_ast(&mut input);
        assert!(
            result.is_err(),
            "Expected parsing error for one invalid policy block"
        );

        assert_snapshot!("invalid_policy_in_the_middle_of_valid", result.unwrap_err());
    }

    #[test]
    fn parse_invalid_uri_in_redirect() {
        let mut input = r#"
            policy goaway {
                action redirect "https:?"
            }
        "#;

        let result = parse_into_ast(&mut input);
        assert!(
            result.is_err(),
            "Expected parsing error for one invalid block"
        );

        assert_snapshot!("invalid_uri_in_redirect", result.unwrap_err());
    }

    #[test]
    fn parse_invalid_integer_upper_limit() {
        let mut input = r#"
            policy over {
                when {
                    e >= 9223372036854775808
                }

                action allow
            }
        "#;

        let result = parse_into_ast(&mut input);
        assert!(
            result.is_err(),
            "Expected parsing error for one invalid block"
        );

        assert_snapshot!("invalid_integer_upper_limit", result.unwrap_err());
    }

    #[test]
    fn parse_invalid_integer_lower_limit() {
        let mut input = r#"
            policy over {
                when {
                    g <= -9223372036854775808
                }

                action allow
            }
        "#;

        let result = parse_into_ast(&mut input);
        assert!(
            result.is_err(),
            "Expected parsing error for one invalid block"
        );

        assert_snapshot!("invalid_integer_lower_limit", result.unwrap_err());
    }
}
