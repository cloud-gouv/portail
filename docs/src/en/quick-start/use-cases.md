# Cheatsheet: Use Cases

## 1. Allow-list based access

Allow only a known list of sites.

```portail
policy allowed_sites {
  when host in ["google.com", "github.com"]
  action allow
}
```

## 2. Deny-list based access

Block specific sites, allow everything else.

```portail
policy disallowed_sites {
  when host in ["chatgpt.com", "deepseek.com", "anthropic.com"]
  action deny
}
```

## 3. Exceptions in standalone mode

Allow certain sites only when the local proxy operates without a remote proxy.

```portail
policy allowed_for_autonomous_operations {
  when host in ["github.com", "numerique.gouv.fr"] and route.local == true
  action allow
}
```

## 4. Multi-backend intranet routing

Route different subdomains to different exit proxies.

```portail
route cloud_region_a {
  when host =~ "*.region-a.cloud.example.com"
  use ["region_a_exit_a", "region_a_exit_b"]
}

route cloud_region_b {
  when host =~ "*.region-b.cloud.example.com"
  use ["region_b_exit_a", "region_b_exit_b"]
}

policy allowed_admin_interfaces {
  when host =~ "(horizon|auth).cloud.example.com"
  action allow
}
```

Associated NixOS configuration:

```nix
services.portail.settings.backends = {
  region_a_exit_a.target-address = "1.2.3.4:8080";
  region_a_exit_b.target-address = "1.2.3.5:8080";
  region_b_exit_a.target-address = "2.3.4.5:8080";
};
```

## 5. Secret proxy (dynamic backend)

Backend whose address is kept secret or changes dynamically.

```nix
services.portail.settings.backends.my_secret_proxy = {
  dynamic = true;
};
```

Update by a user in the admin group:
```sh
portail rpc update-dynamic-backend --target-address 10.0.1.5:8080 mon_secret_proxy
```

## 6. Failover with standalone mode

Allow restricted traffic in standalone mode while requiring the remote proxy
in normal mode. Useful while deploying the proxy infrastructure.

```portail
policy allowed_sites_in_failover {
  when host in ["google.com", "github.com"] and route.local == true
  action allow
}

policy delegate_to_remote_proxy {
  when route.local == false
  action allow
}

policy default_deny {
  action deny
}
```
