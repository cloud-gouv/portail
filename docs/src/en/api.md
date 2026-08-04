# API reference

Portail exposes a control API via [Varlink](https://varlink.org/) over a Unix socket
(`/run/fr.gouv.portail.Control`).

## Available RPC commands

| Command | Description |
|----------|-------------|
| `portail rpc print-current-backend` | Show the current default backend |
| `portail rpc list-backends` | List all backends and their status |
| `portail rpc set-default-backend <name>` | Set the default backend |
| `portail rpc unset-default-backend` | Clear the default backend |
| `portail rpc update-dynamic-backend --target-address <address> <name>` | Update a dynamic backend's address |

## RPC permissions

| Command | Required group | Effect |
|---------|---------------|--------|
| `print-current-backend` | (any) | Read current default backend |
| `list-backends` | (any) | List all backends |
| `set-default-backend` | `trusted-groups` | Change default routing target |
| `unset-default-backend` | `trusted-groups` | Clear the default backend |
| `update-dynamic-backend` | `admin-groups` | Redirect traffic to a new backend address |

Groups are configured via `[rpc]` in the TOML settings or
`services.portail.settings.rpc` in the NixOS module. See
[Configuration](./configuration.md) for details.

> The full Varlink API reference is still being developed and should be considered unstable.

## Varlink interface

The interface definition is at `src/rpc/fr.gouv.portail.control.varlink`.

## Socket activation

Portail uses systemd socket activation for:
- **Proxy socket**: `portail-proxy.socket`
- **RPC socket**: `portail-rpc.socket`

## CLI reference

```sh
portail --help
```

| Option | Description |
|--------|-------------|
| `--config <PATH>` | Path to configuration file |
| `--version` | Print version and exit |
| `daemon` | Start the Portail daemon |
| `check-acl-syntax` | Validate an ACL file's syntax |
| `rpc` | Call an RPC command on a running instance |

> The CLI is still being developed and should be considered unstable.
