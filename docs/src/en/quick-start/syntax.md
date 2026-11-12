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
| `tunnel.protocol` | `string` | Outer tunnel protocol: `socks5`, `http` | Always |
| `tunnel.transport` | `string` | Outer transport: `tls`, `plaintext` | Always |
| `tunnel.host` | `string` | Canonical outer target host | Always |
| `tunnel.port` | `u16` | Outer target port | Always |
| `tunnel.client.auth` | `string` | Client authentication: `none`, `mtls` | Always |
| `tunnel.client.cert.subject_cn` | `string` | Client certificate subject CN | mTLS |
| `tunnel.client.cert.issuer_cn` | `string` | Client certificate issuer CN | mTLS |
| `tunnel.client.cert.serial` | `string` | Client certificate serial | mTLS |
| `tunnel.client.cert.san_dns` | `set` | Client certificate DNS SANs | mTLS |
| `tunnel.client.cert.san_uri` | `set` | Client certificate URI SANs | mTLS |
| `tunnel.client.cert.san_email` | `set` | Client certificate email SANs | mTLS |
| `tunnel.client.cert.san_ip` | `set` | Client certificate IP SANs | mTLS |
