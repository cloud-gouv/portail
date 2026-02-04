use std::collections::HashMap;

use regex::Regex;

use crate::acl::parser::{ACLRule, Hostname, Operator};

#[derive(Debug, Clone)]
pub struct EvalContext {
    tags: HashMap<String, String>,
    regex_cache: HashMap<String, Regex>, // Cache of compiled regex patterns
}

impl EvalContext {
    pub fn new() -> Self {
        EvalContext {
            tags: HashMap::new(),
            regex_cache: HashMap::new(),
        }
    }

    fn insert(&mut self, key: String, value: String) {
        self.tags.insert(key, value);
    }

    fn get(&self, key: &str) -> Option<&String> {
        self.tags.get(key)
    }

    pub fn get_regex(&mut self, pattern: &str) -> Option<&Regex> {
        if !self.regex_cache.contains_key(pattern) {
            // Compile the regex and cache it
            if let Ok(regex) = Regex::new(pattern) {
                self.regex_cache.insert(pattern.to_string(), regex);
            }
        }
        self.regex_cache.get(pattern)
    }
}

impl ACLRule {
    fn applies_to(&self, context: &mut EvalContext, target_hostname: &str) -> bool {
        match self.hostname {
            Hostname::Exact(ref expected) => expected == target_hostname,
            Hostname::Regex(ref pattern) => {
                if let Some(regex) = context.get_regex(pattern) {
                    regex.is_match(target_hostname)
                } else {
                    false
                }
            }
        }
    }

    fn evaluate_condition(&self, context: &EvalContext) -> bool {
        for condition in &self.conditions {
            let context_value = context.get(&condition.key);
            let condition_value = &condition.value;

            match (context_value, &condition.operator) {
                (Some(context_value), Operator::Equals) => {
                    if context_value != condition_value {
                        return false;
                    }
                }
                (Some(context_value), Operator::NotEquals) => {
                    if context_value == condition_value {
                        return false;
                    }
                }
                (Some(context_value), Operator::LessThan) => {
                    if context_value >= condition_value {
                        return false;
                    }
                }
                (Some(context_value), Operator::GreaterThan) => {
                    if context_value <= condition_value {
                        return false;
                    }
                }
                (Some(context_value), Operator::LessThanOrEqual) => {
                    if context_value > condition_value {
                        return false;
                    }
                }
                (Some(context_value), Operator::GreaterThanOrEqual) => {
                    if context_value < condition_value {
                        return false;
                    }
                }
                _ => return false,
            }
        }
        true
    }
}

pub fn evaluate_acl_rules(
    target_hostname: &str,
    rules: &[ACLRule],
    context: &mut EvalContext,
) -> Option<ACLRule> {
    for rule in rules {
        if rule.applies_to(context, target_hostname) && rule.evaluate_condition(context) {
            return Some(rule.clone());
        }
    }
    None
}

#[cfg(test)]
mod tests {
}
