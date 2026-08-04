# Aide-mémoire : cas d'usage

## 1. Liste d'autorisation

Autoriser uniquement une liste de sites connus.

```portail
policy allowed_sites {
  when host in ["google.com", "github.com"]
  action allow
}
```

## 2. Liste d'interdiction

Bloquer des sites spécifiques, laisser passer le reste.

```portail
policy disallowed_sites {
  when host in ["chatgpt.com", "deepseek.com", "anthropic.com"]
  action deny
}
```

## 3. Exceptions en mode autonome

Autoriser certains sites uniquement quand le proxy local fonctionne sans proxy distant.

```portail
policy allowed_for_autonomous_operations {
  when host in ["github.com", "numerique.gouv.fr"] and route.local == true
  action allow
}
```

## 4. Routage intranet multi-backend

Router différents sous-domaines vers différents proxies de sortie.

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

Configuration NixOS associée :

```nix
services.portail.settings.backends = {
  region_a_exit_a.target-address = "1.2.3.4:8080";
  region_a_exit_b.target-address = "1.2.3.5:8080";
  region_b_exit_a.target-address = "2.3.4.5:8080";
};
```

## 5. Proxy secret (backend dynamique)

Backend dont l'adresse est maintenue secrète ou change dynamiquement.

```nix
services.portail.settings.backends.mon_proxy_secret = {
  dynamic = true;
};
```

Mise à jour par un utilisateur du groupe admin :
```sh
portail rpc update-dynamic-backend --target-address 10.0.1.5:8080 mon_proxy_secret
```

## 6. Failover avec mode autonome

Permettre un trafic restreint en mode autonome tout en exigeant le proxy distant
en mode normal. Utile pendant le déploiement de l'infrastructure.

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
