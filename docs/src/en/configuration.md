# Configuration

## Quick starters

### Minimal (NixOS module)

```nix
{ config, lib, pkgs, ... }:
{
  # Reference to the Portail module.
  imports = [ ./nix/module.nix ];

  services.portail = {
    enable = true;
    proxyListenStream = "127.0.0.1:8080";
    settings = {
      connect-timeout = 30;
      backends = { };
    };
  };
}
```

### Full-featured (NixOS module)

```nix
{ config, lib, pkgs, ... }:
{
  imports = [ ./nix/module.nix ];

  services.portail = {
    enable = true;
    enableAtBoot = true;
    proxyListenStream = "127.0.0.1:8080";

    settings = {
      connect-timeout = 30;
      tcp-nodelay = true;
      public-address = "203.0.113.5";
      default-backend = "my-remote-proxy";
      filter-acl-rules-path = "/etc/portail/filter-acl.rules";

      listener = {
        cacert_file = "/etc/portail/ca.crt";
        tls_privkey = "/etc/portail/server.key";
        tls_chain = "/etc/portail/server.crt";
      };

      escaper = {
        cacert_file = "/etc/portail/ca.crt";
        tls_privkey = "/etc/portail/client.key";
        tls_certificate = "/etc/portail/client.crt";
      };

      rpc = {
        admin_groups = ["portail-admins"];
        trusted_groups = ["portail-users"];
      };

      backends = {
        my-remote-proxy = {
          target-address = "10.0.0.1:8080";
          identity-aware = false;
        };
        my-secret-proxy = {
          target-address = "10.0.0.2:8080";
          identity-aware = true;
          tls-server-name = "secret.corp.example.com";
        };
        yet-another-proxy = {
          dynamic = true;
        };
      };
    };

    acl.filter.rules = {
      "10-allow-github" = ''
        policy allow_github {
          when host == "github.com"
          action allow
        }
      '';
      "99-default-deny" = ''
        policy default_deny {
          action deny
        }
      '';
    };
  };
}
```

---

## Settings reference

All keys in the TOML config use `kebab-case`. NixOS uses the same names nested under `services.portail.settings`.

### Top-level

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `connect-timeout` | `u64` (seconds) | **required** | Maximum time for a proxied request before it is killed |
| `handshake-timeout` | `u64` (seconds) | **required** | Maximum time for the initialization of a request before it is killed |
| `tcp-nodelay` | `bool` | `false` | Disable Nagle's algorithm on proxy-side TCP connections |
| `public-address` | `IpAddr` | none | IP address advertised for UDP ASSOCIATE responses |
| `default-backend` | `string` | none | Backend name to use when no `route` block matches |
| `filter-acl-rules-path` | `path` | none | Path to the ACL rules file for filtering connections |
| `explain-acl-rules-path` | `path` | none | Path to the ACL rules file for redacting deny explanations |
| `max-connections` | `u64` on modern systems | approx. half of the open files limit | Maximum concurrent connections to Portail |

### `[listener]` (Inbound TLS)

Settings for TLS on the socket that clients connect to (browsers, curl, other Portail instances).
Omit the entire section for plain-text local connections.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `cacert-file` | `path` | none | CA certificate used to validate client certificates (mTLS) |
| `tls-privkey` | `path` | none | Server private key for TLS |
| `tls-chain` | `path` | none | Server certificate chain presented to connecting clients |

When all three are set, Portail requires and validates client certificates via mTLS.

### `[escaper]` (Outbound TLS)

Settings for TLS when Portail connects to upstream backends or target websites.
Omit the entire section for plain-text outbound connections.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `cacert-file` | `path` | none | CA certificate used to validate the backend's server certificate |
| `tls-privkey` | `path` | none | Client private key for mTLS |
| `tls-certificate` | `path` | none | Client certificate presented to backends |

### `[dns]` (Domain name resolution)

DNS settings when Portail perform domain name resolution autonomously.
Omit the entire section to use the system-wide resolver.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `resolvers` | list of `IpAddr` | empty (system resolution) | List of remote DNS resolvers |
| `timeout` | `u64` (seconds) | 5 seconds | Maximum time for a DNS resolution before it is killed |


### `[rpc]` (RPC authorization)

Controls who can call privileged RPC commands on the Unix socket.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `admin-groups` | `[string]` | `[]` | Unix groups allowed to call **admin** RPCs: `UpdateDynamicBackend`. These users can redirect traffic: treat as root-equivalent. |
| `trusted-groups` | `[string]` | `[]` | Unix groups allowed to call `SetDefaultBackend` and `UnsetDefaultBackend`. Cannot redirect traffic but can change the default routing target. |

### `[backends]` (Backend definitions)

Each backend is a named entry under `[backends]`. The name is referenced by `route` blocks and `default-backend`.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `target-address` | `SocketAddr` | required (unless `dynamic`) | `IP:port` of the upstream proxy |
| `dynamic` | `bool` | `false` | If `true`, `target-address` can be omitted and supplied later via `portail rpc update-dynamic-backend` |
| `identity-aware` | `bool` | `false` | Whether to use the escaper's mTLS certificate when connecting to this backend |
| `tls-server-name` | `string` | IP of `target-address` | TLS SNI hostname for the backend connection |

Backends are not used in a specific global order: the order depends on `route` blocks and the backend resolution logic (see [Routing](./quick-start/routing.md)).

---

## Copy-paste snippets

### Local-only proxy (no TLS, single static backend)

```toml
connect-timeout = 30
handshake-timeout = 15

[backends.my-upstream]
target-address = "10.0.0.1:8080"
```

### mTLS listener + mTLS escaper (full mutual TLS)

```toml
connect-timeout = 30
handshake-timeout = 15

[listener]
cacert-file = "/etc/portail/ca.crt"
tls-privkey = "/etc/portail/server.key"
tls-chain = "/etc/portail/server.crt"

[escaper]
cacert-file = "/etc/portail/ca.crt"
tls-privkey = "/etc/portail/client.key"
tls-certificate = "/etc/portail/client.crt"

[backends.secure-upstream]
target-address = "10.0.0.1:8080"
identity-aware = true
tls-server-name = "upstream.corp.example.com"
```

### Dynamic backend with admin group (TOML)

```toml
connect-timeout = 30
handshake-timeout = 15

[rpc]
admin_groups = ["portail-admins"]

[backends.secret-proxy]
dynamic = true
```

### NixOS with listener, escaper, ACL, and admin groups

```nix
services.portail = {
  enable = true;
  proxyListenStream = "127.0.0.1:8080";

  settings = {
    connect-timeout = 30;
    handshake-timeout = 15;
    default-backend = "secure-upstream";

    listener = {
      cacert_file = "/run/secrets/portail/ca.crt";
      tls_privkey = "/run/secrets/portail/server.key";
      tls_chain = "/run/secrets/portail/server.crt";
    };

    escaper = {
      cacert_file = "/run/secrets/portail/ca.crt";
      tls_privkey = "/run/secrets/portail/client.key";
      tls_certificate = "/run/secrets/portail/client.crt";
    };

    rpc.admin_groups = ["portail-admins"];

    backends = {
      secure-upstream.target-address = "10.0.0.1:8080";
      secret-proxy.dynamic = true;
    };
  };

  acl.filter.rules = {
    "10-routes" = ''
      route secret_services {
        when host =~ ".*.internal.corp.example.com"
        use ["secret-proxy"]
      }
    '';
    "99-default-deny" = ''
      policy default_deny { action deny }
    '';
  };
};
```
