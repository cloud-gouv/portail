use criterion::{Criterion, criterion_group, criterion_main};
use portail::{
    acl::{
        ACLRules, EvaluationContext, OwnedEvaluationContext, ast::ConcreteOperand, ast_to_hir,
        parser::parse_into_ast,
    },
    config::BackendSettings,
};
use rand::RngExt;
use std::{collections::HashMap, hint::black_box};

/// Configuration for generating random AST input
pub struct RandomAstConfig {
    pub num_policies: u64,
    pub num_routes: u64,
    pub max_expressions_per_policy: u64,
    pub max_backends_per_route: u64,
    pub allow_probability: f64, // probability for action=allow
    pub adversarial: bool,      // generate adversarial expressions for evaluation benchmarks, i.e.
                                // slowing down conditions.
}

pub fn generate_random_ast_input(cfg: &RandomAstConfig) -> String {
    let mut rng = rand::rng();
    let mut output = String::new();

    // Generate routes
    for i in 0..cfg.num_routes {
        let route_name = format!("route{}", i);
        let host_pattern = if cfg.adversarial {
            format!(".*(corp|dev|qa)\\.example\\.com") // repeated, regex-heavy
        } else {
            format!(r".*{}\.example\.com", i)
        };

        let num_backends = rng.random_range(1..=cfg.max_backends_per_route as usize);
        let all_backends = ["exit1", "exit2", "exit3", "exit4", "exit5"];
        let backends: Vec<_> = (0..num_backends)
            .map(|_| all_backends[rng.random_range(0..all_backends.len())])
            .collect();

        output.push_str(&format!(
            r#"
route {route_name} {{
    when host =~ "{host_pattern}"
    use ["{backends}"]
}}
"#,
            route_name = route_name,
            host_pattern = host_pattern,
            backends = backends.join("\", \"")
        ));
    }

    // Generate policies
    for i in 0..cfg.num_policies {
        let policy_name = format!("policy{}", i);
        let action = if rng.random_bool(cfg.allow_probability) {
            "allow"
        } else {
            "deny"
        };

        // Generate multiple require expressions
        let num_expr = rng.random_range(1..=cfg.max_expressions_per_policy as usize);
        let mut expressions = Vec::new();
        for _ in 0..num_expr {
            let expr = if cfg.adversarial {
                todo!();
            } else {
                let choices = [
                    "user_authed == true",
                    "a >= 3",
                    "b <= 5",
                    "c != 0",
                    "d < 10",
                ];
                choices[rng.random_range(0..choices.len())].to_string()
            };
            expressions.push(expr);
        }

        output.push_str(&format!(
            r#"
policy {policy_name} {{
    when host =~ ".*{i}.example.com"
    require {require_expr}
    action {action}
}}
"#,
            policy_name = policy_name,
            i = i,
            require_expr = expressions.join(" and "),
            action = action
        ));
    }

    output
}

pub fn generate_blocklist_policy(policy_name: &str, num_uris: usize) -> String {
    let uris: Vec<String> = (0..num_uris)
        .map(|i| format!("blocked{}.example.com", i))
        .collect();

    let mut policy_blocks = Vec::new();

    // Split into chunks of 1000
    for (idx, chunk) in uris.chunks(1000).enumerate() {
        let pattern = chunk.join("|");
        let chunk_policy_name = format!("{}_part{}", policy_name, idx + 1);

        let block = format!(
            r#"
policy {chunk_policy_name} {{
    require host =~ "{pattern}"
    action deny
}}
"#,
            chunk_policy_name = chunk_policy_name,
            pattern = pattern
        );

        policy_blocks.push(block);
    }

    // Add a default allow policy
    policy_blocks.push(
        r#"
policy default_allow {
    action allow
}
"#
        .to_string(),
    );

    policy_blocks.join("\n")
}
fn size_to_config(size: &str) -> RandomAstConfig {
    match size {
        "small" => RandomAstConfig {
            num_policies: 10,
            num_routes: 5,
            max_expressions_per_policy: 3,
            max_backends_per_route: 2,
            allow_probability: 0.7,
            adversarial: false,
        },
        "medium" => RandomAstConfig {
            num_policies: 100,
            num_routes: 50,
            max_expressions_per_policy: 5,
            max_backends_per_route: 3,
            allow_probability: 0.7,
            adversarial: false,
        },
        "large" => RandomAstConfig {
            num_policies: 1_000,
            num_routes: 100,
            max_expressions_per_policy: 10,
            max_backends_per_route: 3,
            allow_probability: 0.7,
            adversarial: false,
        },
        _ => panic!("Unknown size: {}", size),
    }
}

fn eval(host: &str, rules: ACLRules) {
    let eval_context = OwnedEvaluationContext::empty();
    let mut eval_context = eval_context.fork();

    eval_context.insert("host", ConcreteOperand::String(host));
    eval_context.insert("a", ConcreteOperand::Number(4));
    eval_context.insert("b", ConcreteOperand::Number(5));
    eval_context.insert("c", ConcreteOperand::Number(1));
    eval_context.insert("d", ConcreteOperand::Number(9));
    eval_context.insert("user_authed", ConcreteOperand::Boolean(true));

    eval_context.evaluate_request(&rules.hir).unwrap();
}

fn criterion_benchmark(c: &mut Criterion) {
    let sizes = ["small", "medium", "large"];
    let mut backends = HashMap::new();
    let backend_setting = BackendSettings {
        identity_aware: false,
        target_address: "1.1.1.1:443".parse().unwrap(),
    };

    for id in 1..=5 {
        backends.insert(format!("exit{}", id), backend_setting.clone());
    }

    for &size in &sizes {
        let cfg = size_to_config(size);
        let input = generate_random_ast_input(&cfg);
        let ast_label = format!("parse_into_ast({})", size);
        let hir_label = format!("ast_to_hir({})", size);

        c.bench_function(&ast_label, |b| {
            b.iter(|| parse_into_ast(black_box(&input)).unwrap())
        });

        let ast = parse_into_ast(&input).unwrap();
        c.bench_function(&hir_label, |b| {
            b.iter(|| ast_to_hir(black_box(ast.clone()), &backends).unwrap())
        });

        let rules = ACLRules {
            hir: ast_to_hir(ast, &backends).unwrap(),
        };
        let last_host = format!("{}.example.com", cfg.num_policies - 1);

        c.bench_function(&format!("eval_bestcase(1req, {})", size), |b| {
            b.iter_batched(
                || rules.clone(),
                |rules| eval(black_box("0.example.com"), black_box(rules)),
                criterion::BatchSize::SmallInput,
            )
        });
        c.bench_function(&format!("eval_worstcase(1req, {})", size), |b| {
            b.iter_batched(
                || rules.clone(),
                |rules| eval(black_box(&last_host), black_box(rules)),
                criterion::BatchSize::SmallInput,
            )
        });
    }

    for num_uris in &[1_000, 10_000, 100_000, 1_000_000] {
        let input = generate_blocklist_policy("blocked", *num_uris as usize);
        let ast = parse_into_ast(&input).unwrap();
        let hir = ast_to_hir(ast, &backends).unwrap();

        let rules = ACLRules { hir };

        c.bench_function(&format!("eval_blocklist_allow({})", num_uris), |b| {
            b.iter_batched(
                || rules.clone(),
                |rules| eval(black_box("allowed.example.com"), black_box(rules)),
                criterion::BatchSize::SmallInput,
            );
        });

        c.bench_function(&format!("eval_blocklist_deny({})", num_uris), |b| {
            let deny_host = format!("blocked{}.example.com", num_uris / 2);
            b.iter_batched(
                || rules.clone(),
                |rules| eval(black_box(&deny_host), black_box(rules)),
                criterion::BatchSize::SmallInput,
            );
        });
    }
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);

// TODO:
// - evaluation benchmarks
//  - evaluate large chain with regexps on the path
//  - evaluate adversarial comparisons cases
