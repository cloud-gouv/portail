# Cheatsheet: Syntax

Indentation has no effect in Portail files, you can format files as you want.

## Policy structure

```portail
policy policy_name {
  when condition    # optional: when the policy applies
  require condition # optional: prerequisite for the action
  action action_to_perform  # required
}
```

Policies are evaluated **top to bottom**. As soon as an action is executed, evaluation stops.
If the `when` and `require` blocks are omitted, the policy always executes (place these at the end).

## Route structure

```portail
route route_name {
  when condition
  use ["backend1", "backend2", ...]
}
```

Backends are tried in order. They must match names declared in `services.portail.settings.backends`.

## Comparison operators

| Operator | Meaning | Example |
|-----------|---------|---------|
| `==` | Equality | `proxy.cmd == "connect"` |
| `!=` | Not equal | `protocol != "http"` |
| `=~` | Regular expression | `host =~ ".*gouv.fr"` |
| `in` | Set membership | `host in ["github.com", "example.org"]` |

## Logical operators

| Operator | Meaning |
|-----------|---------|
| `and` | Logical *and* |
| `or` | Logical *or* |
| `not` | Logical negation |

Parentheses `( )` can be used to group expressions.

## Available actions

| Action | Effect |
|--------|--------|
| `allow` | Authorizes the request, stops evaluation |
| `deny` | Rejects the request, stops evaluation |
| `redirect <url>` | Redirects the request, stops evaluation |

## Context variables

| Variable | Type | Description | Context |
|----------|------|-------------|---------|
| `route.local` | `bool` | Standalone mode (`true`) or chaining (`false`) | Always |
| `proxy.protocol` | `string` | Proxy protocol: `socks5`, `http` | Always |
| `host` | `string` | Target hostname | Always |
| `port` | `u16` | Target port (0–65535) | Always |
| `proxy.cmd` | `string` | SOCKS5 command: `tcp_connect`, `udp_associate` | SOCKS5 |
