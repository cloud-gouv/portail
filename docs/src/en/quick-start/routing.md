# Cheatsheet: Routing

## Operating modes

| Mode | `route.local` | Description | Recommendation |
|------|--------------|-------------|----------------|
| Standalone | `true` | Portail connects directly to the target. All filtering and traceability rests on the local instance. | Portail servers (remote proxies) |
| Chaining | `false` | Portail delegates to a remote proxy. Evaluation happens in two stages: local first, then remote. | Portail clients (workstations) |
| Failover | falls back to `true` | When all remote backends are unreachable, the request is re-evaluated in standalone mode. | Allow only for disaster recovery or to avoid compromising productivity |

## Backend resolution order

When a request needs to be routed:

1. **`route` blocks**: the first matching `route` block recommends a list
   of backends. They are tried one by one.
2. **Default backend**: configurable via `services.portail.settings.default-backend`
   or `portail rpc set-default-backend`.
3. **Standalone fallback**: if all backends fail, the request is re-evaluated
   in standalone mode (`route.local = true`).

```
┌────────── Incoming request ──────────┐
│                                      │
│  1. Route blocks                     │──> Try backend 1, 2, ... N
│                                      │
│  2. Default backend                  │──> Try
│                                      │
│  3. Standalone fallback              │──> Re-evaluate ACL
│     (route.local = true)             │
│                                      │
└──────────────────────────────────────┘
```

## Dynamic backends

A backend marked `dynamic = true` can be updated at runtime without restarting
Portail. Useful when the address changes in response to external events
(IP rotation, service announcements).

```nix
services.portail.settings.backends.my_secret_proxy = {
  dynamic = true;
};
```

Update via RPC:
```sh
portail rpc update-dynamic-backend --target-address 10.0.1.5:8080 my_secret_proxy
```

Until the first update is performed, all requests going through this backend
will fail.

## Backend types

| Type | Configuration | Usage |
|------|---------------|-------|
| Static | `target-address = "1.2.3.4:8080"` | Proxies with known, fixed addresses |
| Dynamic | `dynamic = true` | Proxies with changing addresses (rotation, announcements) |
| Default | `default-backend` | Fallback when no route matches |
