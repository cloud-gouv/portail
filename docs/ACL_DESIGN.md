# ACL language design

## Objectives

Portail requires an access control language (ACL) to make decisions on:

* Allowing or denying proxy connections
* Modifying requests, e.g. redirection

The ACL language is central to Portail security and enables use cases such as:

* Compliance audits by third parties
* Explaining access denials to end users

Portail follows BeyondCorp principles:

* Enrich ACL evaluation with context from trust databases and side information (time, source IP geography, etc.)
* Provide trust-aware explanations for denied access while considering attacker risk

Portail also supports heterogeneous workloads across regions or clouds. ACL rules can include routing hints to recommend specific routes to reach a resource.

## Prior art

Portail's authors reviewed existing ACL and policy languages but opted to design a custom language for simplicity, performance, and user experience, avoiding the overhead of third-party integrations.

### Logic programming

Logic programming allows partial evaluation and variable reasoning but introduces unacceptable latency for ACL checks. While Portail does not require this capability, its ACL can be reinterpreted in logic languages for visualization or analysis, e.g. "which users have allow access to this host?"

* [Prolog](https://en.wikipedia.org/wiki/Prolog), a major logic programming language
* [LIFE](https://homepage.divms.uiowa.edu/~fleck/lifeIntro.pdf), a generalization of Prolog
* [Datalog](https://en.wikipedia.org/wiki/Datalog), a declarative restriction of Prolog

### Policy languages

Existing policy languages offer full-featured solutions but introduce dependencies or features beyond Portail's immediate needs. Portail may integrate such solutions in the future if requirements evolve.

* Open Policy Agent: integrates in the Golang ecosystem only or via an entire server runtime
* OpenFGA: requires a separate server runtime
* Cedar: efficient for large-scale policies

### General-purpose configuration languages

Using general-purpose configuration languages would require building a bespoke DSL, causing user friction and impedance mismatch.

## Design

Portail ACL processing uses a two-stage compilation pipeline:

1. String → AST
2. AST → HIR (higher intermediate representation)

HIR is maintained in memory for evaluation. Syntax and semantic errors are reported at load time (missing actions, invalid comparisons, unknown backends). Missing variables are reported at evaluation time.

Portail defaults to fail-close if no ACL is loaded, preventing open-proxy behavior. Disaster recovery must consider redeployment without using the affected instance.

Portail ACL serves two purposes: policy enforcement and routing. Evaluation occurs in two phases.

### Two-phased evaluation

Portail accumulates contextual information for each request (protocol, user, etc.).

#### Phase 1: policy enforcement

ACL evaluation produces:

* action: allow, deny, or redirect
* context of satisfied requirements
* list of failed requirements (for explanations and debugging)

#### Phase 2: routing

Authorized requests (allow or redirect) select an exit node: either Portail itself or a backend proxy. ACLs may include optional route blocks recommending regional proxies. Portail tries these routes first, then the default backend, and finally itself.

### "When, requirements, actions" logic

Policy blocks may include `when` and `require` clauses (both optional).

* `when` defines conditions for entering a policy block
* `require` defines conditions that must be satisfied to achieve the action

End-user explanations are based on `require`, not `when`. Idiomatic usage:

```
when host =~ "..."
require user.group in ["eng", "finance"]
```

This ensures explanations are actionable by users. Non-idiomatic usage is allowed but discouraged.

### Performance requirements

Policy compilation is not latency-sensitive. Portail targets:

* Load/reload time under 1 second for 100K–1M rules

Policy evaluation directly affects request latency. Targets:

* Internet proxy with large blocklists and default allow: <1ms added latency
* Internal proxy with small-to-medium allowlists and default block: <1ms added latency

Real-time collaboration and videoconferencing must remain unaffected.

Portail did not implement the full-range of language optimizations possible
yet, as the maturity of using Portail in production informs our needs, we will
consider some of these optimizations.
