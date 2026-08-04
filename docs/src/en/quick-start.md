# Quick Start

This chapter walks you through setting up Portail on NixOS, from writing your
first ACL rules to deploying a dynamic backend.

The following pages serve as quick reference once you're familiar with the concepts:

| Page | Content |
|------|---------|
| [Cheatsheet: Syntax](./quick-start/syntax.md) | Operators, context variables, actions |
| [Best Practices](./quick-start/best-practices.md) | Policy ordering, *default deny*, naming |
| [Cheatsheet: Routing](./quick-start/routing.md) | Standalone/chaining modes, dynamic backends |
| [Cheatsheet: Use Cases](./quick-start/use-cases.md) | The 6 classic patterns |

---

## Step-by-step setup

We'll configure Portail to use a **secret proxy** whose address changes regularly
and cannot be hardcoded in the configuration.
This is [use case 5](./quick-start/use-cases.md#5-secret-proxy-dynamic-backend).

### 1. Enable Portail on NixOS

Add the Portail module to your NixOS configuration:

```nix
{
  imports = [
    # You can use either Flakes or any dependency management (e.g. npins, lon, etc.) to get Portail inputs.
    /path/to/portail/nix/module.nix
  ];

  services.portail = {
    enable = true;
    proxyListenStream = "127.0.0.1:8080";
  };
}
```

After `nixos-rebuild switch`, the systemd sockets are active:

```sh
systemctl status portail-proxy.socket
systemctl status portail-rpc.socket
```

### 2. Declare the dynamic backend

The secret proxy must be declared with `dynamic = true`. Until an address
is provided via RPC, requests through this backend will fail.

```nix
services.portail.settings.backends = {
  my_secret_proxy = {
    dynamic = true;
  };
};
```

### 3. Configure the admin group

To allow backend updates via RPC, declare an admin group. Users in this group
will be able to call `portail rpc` on admin-level RPCs such as dynamic updates of backends.

```nix
services.portail.settings = {
  rpc.admin-groups = ["portail-admins"];
};
```

Declare the group and users in your NixOS configuration:

```nix
users.groups.portail-admins = {};

users.users.alice = {
  isNormalUser = true;
  extraGroups = ["portail-admins"];
};
```

### 4. Write the ACL rules

Create a rules file that:
- Routes all traffic to the secret proxy by default
- Allows a few sites in standalone mode (fallback if the proxy is unreachable)
- Applies an explicit *default deny*

```nix
services.portail.acl.filter.rules = {
  "10-failover" = ''
    policy failover_sites {
      when host in ["github.com", "google.com"] and route.local == true
      action allow
    }
  '';

  "50-delegate" = ''
    policy delegate_to_remote_proxy {
      when route.local == false
      action allow
    }
  '';

  "99-default-deny" = ''
    policy default_deny {
      action deny
    }
  '';
};
```

### 5. Set the default backend

To route traffic to the secret proxy, set it as the default backend.
Any request that doesn't match a route will be sent to `my_secret_proxy`.

```nix
services.portail.settings.default-backend = "my_secret_proxy";
```

Or dynamically via RPC (you need to be in the `trusted-groups` for this RPC):

```sh
portail rpc set-default-backend my_secret_proxy
```

### 6. Deploy and update the backend

After `nixos-rebuild switch`, the backend is waiting for its first update.
A user in the `portail-admins` group can then provide the real address:

```sh
portail rpc update-dynamic-backend --target-address 10.0.1.5:8080 my_secret_proxy
```

From that moment, traffic is routed to `10.0.1.5:8080`. If the secret proxy
changes address, just run the command again, no Portail restart required.

### 7. Verify it works

Test with curl through the local SOCKS5 proxy or the local HTTP proxy:

```sh
# SOCKS5 proxy
curl --socks5 127.0.0.1:8080 https://github.com
# HTTP CONNECT
curl -x http://127.0.0.1:8080 https://github.com
```

Check the backend status:

```sh
portail rpc print-current-backend
```

### Complete configuration summary

```nix
{
  imports = [ /path/to/portail/nix/module.nix ];

  services.portail = {
    enable = true;
    proxyListenStream = "127.0.0.1:8080";

    settings = {
      admin-groups = ["portail-admins"];
      default-backend = "my_secret_proxy";

      backends = {
        my_secret_proxy = {
          dynamic = true;
        };
      };
    };

    acl.filter.rules = {
      "10-failover" = ''
        policy failover_sites {
          when host in ["github.com", "google.com"] and route.local == true
          action allow
        }
      '';
      "50-delegate" = ''
        policy delegate_to_remote_proxy {
          when route.local == false
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

To dive deeper into each aspect, condition syntax, best practices,
routing modes, or other use cases, see the cheatsheet pages above.
