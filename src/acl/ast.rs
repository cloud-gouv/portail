use std::{borrow::Borrow, collections::HashSet, net::IpAddr, ops::Deref, path::PathBuf};

use http::Uri;
use regex::Regex;
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct ACLAst<'s> {
    pub entries: Vec<ACLEntry<'s>>,
}

#[derive(Debug, Clone)]
pub enum ACLEntry<'s> {
    Route(RouteDefinition<'s>),
    Policy(PolicyBlock<'s>),
}

#[derive(Debug, Clone)]
pub struct RouteDefinition<'s> {
    pub name: &'s str,
    pub attributes: Vec<RouteAttribute<'s>>,
}

#[derive(Debug, Clone)]
pub enum RouteAttribute<'s> {
    When(Expression),
    Use(Vec<&'s str>),
}

#[derive(Debug, Clone)]
pub struct PolicyBlock<'s> {
    pub name: &'s str,
    pub attributes: Vec<PolicyAttribute>,
}

#[derive(Debug, Clone)]
pub enum PolicyAttribute {
    When(Expression),
    Require(Expression),
    Action(Action),
}

#[derive(Debug, Clone)]
pub enum Action {
    Allow,
    Deny(Option<PathBuf>),
    Redirect(Uri),
}

#[derive(Debug, Clone)]
pub enum Expression {
    Or(Box<Expression>, Box<Expression>),
    And(Box<Expression>, Box<Expression>),
    Not(Box<Expression>),
    Comparison(Operand, Comparator, Operand),
    Group(Box<Expression>),
}

#[derive(Debug, Clone)]
pub enum Operand {
    DottedIdentifier(Vec<String>),
    Identifier(String),
    String(String),
    Number(i64),
    Boolean(bool),
    Regex(Regex),
    Set(HashSet<String>),
}

#[derive(Debug, Clone)]
pub enum ConcreteOperand<'s> {
    String(&'s str),
    Number(i64),
    Boolean(bool),
    Regex(&'s Regex),
    Set(HashSet<&'s str>),
}

#[derive(Debug, Clone)]
pub enum OwnedConcreteOperand {
    String(String),
    Number(i64),
    Boolean(bool),
    Regex(Regex),
    Set(HashSet<String>),
}

impl OwnedConcreteOperand {
    pub fn as_ref<'s>(&'s self) -> ConcreteOperand<'s> {
        match self {
            Self::String(s) => ConcreteOperand::String(s.as_str()),
            Self::Regex(re) => ConcreteOperand::Regex(re),
            Self::Boolean(b) => ConcreteOperand::Boolean(*b),
            Self::Number(n) => ConcreteOperand::Number(*n),
            Self::Set(s) => ConcreteOperand::Set(s.iter().map(|s| s.as_ref()).collect()),
        }
    }
}

#[derive(Debug, Error)]
pub enum ComparisonError<'s> {
    #[error("Cannot compare value '{0:?}' of type '{1}' with value '{2:?}' of type '{3}'")]
    TypeMismatch(ConcreteOperand<'s>, &'s str, ConcreteOperand<'s>, &'s str),
    #[error("Regex comparison can only take place with strings, got '{0:?}' of type '{1}' and '{2:?}' of type '{3}'")]
    InvalidRegexOperands(ConcreteOperand<'s>, &'s str, ConcreteOperand<'s>, &'s str),
    #[error("Ordering comparison can only take place with numbers, got '{0:?}' of type '{1}' and '{2:?}' of type '{3}'")]
    InvalidOrderOperands(ConcreteOperand<'s>, &'s str, ConcreteOperand<'s>, &'s str),
}

impl<'s> ConcreteOperand<'s> {
    pub fn type_name(&self) -> &'static str {
        match self {
            Self::Boolean(_) => "boolean",
            Self::String(_) => "string",
            Self::Number(_) => "number",
            Self::Set(_) => "set of strings",
            Self::Regex(_) => "regular expression",
        }
    }

    pub fn compare(lhs: Self, comp: &Comparator, rhs: Self) -> Result<bool, ComparisonError<'s>> {
        use Comparator::*;
        use ConcreteOperand::*;

        match comp {
            Eq | Ne => {
                // Equality and inequality can compare only operands of the same type
                let result = match (lhs, rhs) {
                    (String(a), String(b)) => a == b,
                    (Number(a), Number(b)) => a == b,
                    (Boolean(a), Boolean(b)) => a == b,
                    (lhs, rhs) => {
                        let lhs_type = lhs.type_name();
                        let rhs_type = rhs.type_name();
                        return Err(ComparisonError::TypeMismatch(lhs, lhs_type, rhs, rhs_type));
                    }
                };
                Ok(if let Ne = comp { !result } else { result })
            }

            In => {
                // Inclusion checks can only work on set of strings.
                let result = match (lhs, rhs) {
                    (String(a), Set(bag)) => bag.contains(a),
                    (lhs, rhs) => {
                        let lhs_type = lhs.type_name();
                        let rhs_type = rhs.type_name();

                        return Err(ComparisonError::TypeMismatch(lhs, lhs_type, rhs, rhs_type));
                    }
                };

                Ok(result)
            }

            Comparator::Regex => {
                // Regex only applies to strings and regex operands on the right
                match (lhs, rhs) {
                    (String(value), ConcreteOperand::Regex(pattern)) => Ok(pattern.is_match(value)),
                    (lhs, rhs) => {
                        let lhs_type = lhs.type_name();
                        let rhs_type = rhs.type_name();

                        Err(ComparisonError::InvalidRegexOperands(
                            lhs, lhs_type, rhs, rhs_type,
                        ))
                    }
                }
            }

            Lt | Gt | Lte | Gte => {
                // Ordering only applies to numbers
                match (lhs, rhs) {
                    (Number(a), Number(b)) => {
                        let result = match comp {
                            Lt => a < b,
                            Gt => a > b,
                            Lte => a <= b,
                            Gte => a >= b,
                            _ => unreachable!(),
                        };
                        Ok(result)
                    }
                    (lhs, rhs) => {
                        let lhs_type = lhs.type_name();
                        let rhs_type = rhs.type_name();

                        Err(ComparisonError::InvalidOrderOperands(
                            lhs, lhs_type, rhs, rhs_type,
                        ))
                    }
                }
            }
        }
    }
}
#[derive(Debug, Clone, Copy)]
pub enum Comparator {
    Eq,
    Ne,
    Regex,
    Lt,
    Lte,
    Gt,
    Gte,
    In,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn make_set<'s>(items: &[&'s str]) -> HashSet<&'s str> {
        items.iter().copied().collect()
    }

    #[test]
    fn test_equality_and_inequality() {
        use Comparator::*;
        use ConcreteOperand::*;

        // String
        assert_eq!(
            ConcreteOperand::compare(String("a"), &Eq, String("a")).unwrap(),
            true
        );
        assert_eq!(
            ConcreteOperand::compare(String("a"), &Ne, String("b")).unwrap(),
            true
        );

        // Number
        assert_eq!(
            ConcreteOperand::compare(Number(5), &Eq, Number(5)).unwrap(),
            true
        );
        assert_eq!(
            ConcreteOperand::compare(Number(5), &Ne, Number(6)).unwrap(),
            true
        );

        // Boolean
        assert_eq!(
            ConcreteOperand::compare(Boolean(true), &Eq, Boolean(true)).unwrap(),
            true
        );
        assert_eq!(
            ConcreteOperand::compare(Boolean(true), &Ne, Boolean(false)).unwrap(),
            true
        );

        // Type mismatch
        let err = ConcreteOperand::compare(String("a"), &Eq, Number(5)).unwrap_err();
        matches!(err, ComparisonError::TypeMismatch(_, _, _, _));
    }

    #[test]
    fn test_in_operator() {
        use Comparator::*;
        use ConcreteOperand::*;

        let bag = make_set(&["apple", "banana"]);
        assert_eq!(
            ConcreteOperand::compare(String("apple"), &In, Set(bag.clone())).unwrap(),
            true
        );
        assert_eq!(
            ConcreteOperand::compare(String("pear"), &In, Set(bag.clone())).unwrap(),
            false
        );

        let err = ConcreteOperand::compare(Number(5), &In, Set(bag)).unwrap_err();
        matches!(err, ComparisonError::TypeMismatch(_, _, _, _));
    }

    #[test]
    fn test_regex_operator() {
        let re = regex::Regex::new(r"^\d+$").unwrap();
        // match
        assert_eq!(
            ConcreteOperand::compare(
                ConcreteOperand::String("123"),
                &Comparator::Regex,
                ConcreteOperand::Regex(&re)
            )
            .unwrap(),
            true
        );
        // no match
        assert_eq!(
            ConcreteOperand::compare(
                ConcreteOperand::String("abc"),
                &Comparator::Regex,
                ConcreteOperand::Regex(&re)
            )
            .unwrap(),
            false
        );

        // invalid operand types
        let err = ConcreteOperand::compare(
            ConcreteOperand::Number(5),
            &Comparator::Regex,
            ConcreteOperand::Regex(&re),
        )
        .unwrap_err();
        matches!(err, ComparisonError::InvalidRegexOperands(_, _, _, _));
    }

    #[test]
    fn test_ordering_operators() {
        use Comparator::*;
        use ConcreteOperand::*;

        assert_eq!(
            ConcreteOperand::compare(Number(3), &Lt, Number(5)).unwrap(),
            true
        );
        assert_eq!(
            ConcreteOperand::compare(Number(5), &Lt, Number(3)).unwrap(),
            false
        );

        assert_eq!(
            ConcreteOperand::compare(Number(3), &Lte, Number(3)).unwrap(),
            true
        );

        assert_eq!(
            ConcreteOperand::compare(Number(5), &Gt, Number(3)).unwrap(),
            true
        );
        assert_eq!(
            ConcreteOperand::compare(Number(2), &Gt, Number(3)).unwrap(),
            false
        );

        assert_eq!(
            ConcreteOperand::compare(Number(3), &Gte, Number(3)).unwrap(),
            true
        );

        // invalid types
        let err = ConcreteOperand::compare(String("a"), &Lt, Number(5)).unwrap_err();
        matches!(err, ComparisonError::InvalidOrderOperands(_, _, _, _));
    }
}
