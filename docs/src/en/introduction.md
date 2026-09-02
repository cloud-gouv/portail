# Introduction

**Portail** is an identity-aware access proxy built for terminal workloads.
It draws inspiration from the [BeyondCorp research papers](https://research.google/pubs/beyondcorp-the-access-proxy/)
and is designed to work alongside [Sécurix](https://github.com/cloud-gouv/securix).

> **Status:** Portail is under active development. Features and APIs may change.
> Do not use in production yet unless you are familiar with the project.

## What Portail does

Portail acts as a **forward proxy** that sits between your command-line tools or browser and the network.
Every connection goes through an **ACL engine** that can allow, deny, redirect, or log the request
based on rich metadata: device identity, user attestation, geo-fencing,
risk assessments, and request-level details.

## Key capabilities

| Area | What's included |
|------|-----------------|
| Protocols | SOCKS5 (TCP CONNECT, UDP ASSOCIATE), HTTP CONNECT (1.1/2/3) |
| Routing | Standalone mode, proxy chaining, dynamic backends, failover |
| Access control | ACL language with `when`/`require`/`action`, regex, per-protocol conditions |
| Authentication | mTLS certificates (in progress) |
| Audit | Structured audit logs |
| Deployment | systemd socket activation, NixOS module |
| Observability | Prometheus metrics (in progress) |

## Where to go next

- [Quick start](./quick-start.md): learn the ACL language and routing by example
- [Configuration](./configuration.md): complete settings reference, NixOS and TOML, with copy-paste snippets
- [API reference](./api.md): RPC commands and CLI reference
- [Contributing](./contributing.md): development setup, testing, and PR process
- [Roadmap](./roadmap.md): implemented features and planned work

## Deployment scenarios

Portail can be deployed in several topologies, from a simple local proxy to a
fully distributed chain with mutual TLS.

### Scenario 1: Client-only (standalone)

Portail runs on the workstation and connects directly to the Internet.
All filtering and traceability rests on the local instance.

```
  Workstation
┌──────────────┐     Direct TCP      ┌──────────┐
│  curl / SSH  │────────────────────▶│ Internet │
│      │       │                     └──────────┘
│  ┌───┴───┐   │
│  │Portail│   │  ACL evaluation: route.local = true
│  └───────┘   │  No remote proxy involved
└──────────────┘
```

### Scenario 2: Client + standard upstream proxy

Portail on the workstation chains to a standard SOCKS5 or HTTP CONNECT proxy
running on a server. ACLs are evaluated locally, then the upstream proxy forwards
the request to Internet or Intranet targets. If the upstream is unreachable,
the client Portail falls back to autonomous mode and exits directly (dashed line).

```
  Workstation                              Server
┌──────────────┐  SOCKS5 / HTTP CONNECT  ┌──────────────┐     ┌──────────┐
│  curl / SSH  │────────────────────────▶│ SOCKS5/HTTP  │────▶│ Internet │
│      │       │                         │    proxy     │     └──────────┘
│  ┌──┴────┐   │                         └──────┬───────┘     ┌──────────┐
│  │Portail│   │  ACL: local evaluation         └────────────▶│ Intranet │
│  └──┬────┘   │  route.local = false                         └──────────┘
│     │        │
│     │ fallback (autonomous, route.local = true)
│     └────────────────────────────────────────▶ ┌──────────┐
└──────────────────────────────────────────────┘ │ Internet │
                                                 └──────────┘
```

### Scenario 3: Client + Portail server (dual ACL)

Portail runs on both the workstation and the server. The workstation evaluates
local policies first, then delegates to the server-side Portail which evaluates
its own policies. Both layers can independently allow or deny the request.
The server Portail can reach both Internet and Intranet targets. If the server
Portail is unreachable, the client falls back to autonomous mode (dashed line).

```
  Workstation                              Server
┌──────────────┐  SOCKS5 / HTTP CONNECT  ┌──────────────┐     ┌──────────┐
│  curl / SSH  │───────┬────────────────▶│   Portail    │────▶│ Internet │
│      │       │       │                 │   (server)   │     └──────────┘
│  ┌───┴────┐  │       │                 └──────┬───────┘     ┌──────────┐
│  │Portail │  │  ACL layer 1                   └────────────▶│ Intranet │
│  │(client)│  │  route.local = false                         └──────────┘
│  └───┬────┘  │
│      │    fallback (autonomous, route.local = true)
│      └────────────────────────────────────────▶ ┌──────────┐
└───────────────────────────────────────────────┘ │ Internet │
                                                  └──────────┘
```

### Scenario 4: Full chain with mTLS backends

Portail on the workstation chains to a server-side Portail which routes to
application backends behind mTLS. Each backend requires a client certificate
issued by a trusted CA (`identity-aware = true`). End-to-end identity is
preserved across the entire chain. Backends serve applications exposed on both
Internet and Intranet. If the server or all backends fail, the client falls
back to autonomous mode (dashed line).

```
  Workstation                              Server
┌──────────────┐  mTLS                   ┌──────────────┐
│  curl / SSH  │────────────────────────▶│   Portail    │
│      │       │  client cert            │   (server)   │
│  ┌───┴────┐  │                         └──────┬───────┘
│  │Portail │  │                                │
│  │(client)│  │                   ┌────────────┼────────────┐
│  └───┬────┘  │                   │ mTLS       │ mTLS       │ mTLS
│      │       │                   ▼            ▼            ▼
│      │       │              ┌─────────┐ ┌─────────┐ ┌─────────┐
│      │       │              │ Backend │ │ Backend │ │ Backend │
│      │       │              │   A     │ │   B     │ │   C     │
│      │       │              └────┬────┘ └────┬────┘ └────┬────┘
│      │       │              ┌────┴───────────┴───────────┴────┐
│      │       │              │    identity-aware backends      │
│      │       │              └──────────────┬──────────────────┘
│      │       │                             │
│      │       │         ┌───────────────────┼───────────────────┐
│      │       │         ▼                   ▼                   ▼
│      │       │   ┌──────────┐       ┌──────────┐       ┌──────────┐
│      │       │   │ Internet │       │ Intranet │       │  Custom  │
│      │       │   │  access  │       │  access  │       │   apps   │
│      │       │   └──────────┘       └──────────┘       └──────────┘
│      │       │
│      │    fallback (autonomous, route.local = true)
│      └────────────────────────────────────────▶ ┌──────────┐
└───────────────────────────────────────────────┘ │ Internet │
                                                  └──────────┘
```
