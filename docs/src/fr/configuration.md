# Configuration

## Démarrages rapides

### Minimal (module NixOS)

```nix
{ config, lib, pkgs, ... }:
{
  # Référence au module Portail.
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

### Complet (module NixOS)

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
      default-backend = "mon-proxy-distant";
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
        mon-proxy-distant = {
          target-address = "10.0.0.1:8080";
          identity-aware = false;
        };
        mon-proxy-secret = {
          target-address = "10.0.0.2:8080";
          identity-aware = true;
          tls-server-name = "secret.corp.example.com";
        };
        encore-un-autre = {
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

## Référence des paramètres

Toutes les clés de la configuration TOML utilisent le `kebab-case`. En NixOS, les mêmes noms sont utilisés sous `services.portail.settings`.

### Niveau racine

| Clé | Type | Défaut | Description |
|-----|------|--------|-------------|
| `connect-timeout` | `u64` (secondes) | **requis** | Temps maximum pour une requête proxifiée avant d'être tuée |
| `handshake-timeout` | `u64` (secondes) | **requis** | Temps maximum pour l'initialisation d'une requête avant d'être tuée |
| `tcp-nodelay` | `bool` | `false` | Désactive l'algorithme de Nagle sur les connexions TCP côté proxy |
| `public-address` | `IpAddr` | aucun | Adresse IP annoncée pour les réponses UDP ASSOCIATE |
| `default-backend` | `string` | aucun | Nom du backend à utiliser quand aucun bloc `route` ne correspond |
| `filter-acl-rules-path` | `path` | aucun | Chemin vers le fichier de politiques ACL pour le filtrage des connexions |
| `explain-acl-rules-path` | `path` | aucun | Chemin vers le fichier de politiques ACL pour le masquage des explications de refus |
| `max-connections` | `u64` sur systèmes modernes | approx. moitié du nombre de fichiers ouverts permis | Nombre de connexions concurrent maximum à Portail |

### `[listener]` (TLS entrant)

Paramètres TLS pour la socket sur laquelle les clients se connectent (navigateurs, curl, autres instances Portail).
Omettre la section entière pour des connexions locales en clair.

| Clé | Type | Défaut | Description |
|-----|------|--------|-------------|
| `cacert-file` | `path` | aucun | Certificat CA utilisé pour valider les certificats clients (mTLS) |
| `tls-privkey` | `path` | aucun | Clé privée du serveur pour TLS |
| `tls-chain` | `path` | aucun | Chaîne de certificats du serveur présentée aux clients |

Quand les trois sont définis, Portail exige et valide les certificats clients via mTLS.

### `[escaper]` (TLS sortant)

Paramètres TLS lorsque Portail se connecte aux backends amont ou aux sites cibles.
Omettre la section entière pour des connexions sortantes en clair.

| Clé | Type | Défaut | Description |
|-----|------|--------|-------------|
| `cacert-file` | `path` | aucun | Certificat CA utilisé pour valider le certificat serveur du backend |
| `tls-privkey` | `path` | aucun | Clé privée du client pour mTLS |
| `tls-certificate` | `path` | aucun | Certificat client présenté aux backends |

### `[dns]` (Résolution des noms de domaine)

Paramètres DNS lorsque Portail effectue de la résolution des noms autonome.
Omettre la section entière pour utiliser la résolution des noms systèmes.

| Clé | Type | Défaut | Description |
|-----|------|--------|-------------|
| `resolvers` | liste de `IpAddr` | vide (résolution système) | Liste des résolveurs DNS distants |
| `timeout` | `u64` (seconds) | 5 secondes | Temps maximum pour une résolution de nom avant d'être tuée |


### `[rpc]` (Autorisation RPC)

Contrôle qui peut appeler les commandes RPC privilégiées sur la socket Unix.

| Clé | Type | Défaut | Description |
|-----|------|--------|-------------|
| `admin-groups` | `[string]` | `[]` | Groupes Unix autorisés à appeler les RPC **admin** : `UpdateDynamicBackend`. Ces utilisateurs peuvent rediriger le trafic : à traiter comme équivalent root. |
| `trusted-groups` | `[string]` | `[]` | Groupes Unix autorisés à appeler `SetDefaultBackend` et `UnsetDefaultBackend`. Ne peuvent pas rediriger le trafic mais peuvent changer la cible de routage par défaut. |

### `[backends]` (Définitions des backends)

Chaque backend est une entrée nommée sous `[backends]`. Le nom est référencé par les blocs `route` et `default-backend`.

| Clé | Type | Défaut | Description |
|-----|------|--------|-------------|
| `target-address` | `SocketAddr` | requis (sauf si `dynamic`) | `IP:port` du proxy amont |
| `dynamic` | `bool` | `false` | Si `true`, `target-address` peut être omis et devra être fourni ultérieurement via `portail rpc update-dynamic-backend` |
| `identity-aware` | `bool` | `false` | Si le certificat mTLS de l'escaper doit être utilisé pour la connexion à ce backend |
| `tls-server-name` | `string` | IP de `target-address` | Nom d'hôte TLS SNI pour la connexion au backend |

Les backends ne sont pas utilisés dans un ordre global spécifique : l'ordre dépend des blocs `route` et de la logique de résolution des backends (voir [Routage](./demarrage-rapide/routage.md)).

---

## Extraits prêts à copier

### Proxy local uniquement, sans TLS, un seul backend statique

```toml
connect-timeout = 30
handshake-timeout = 15

[backends.mon-upstream]
target-address = "10.0.0.1:8080"
```

### Listener mTLS + escaper mTLS (TLS mutuel complet)

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

### Backend dynamique avec groupe admin (TOML)

```toml
connect-timeout = 30
handshake-timeout = 15

[rpc]
admin_groups = ["portail-admins"]

[backends.proxy-secret]
dynamic = true
```

### NixOS avec listener, escaper, ACL et groupes admin

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
      proxy-secret.dynamic = true;
    };
  };

  acl.filter.rules = {
    "10-routes" = ''
      route services_secrets {
        when host =~ ".*.internal.corp.example.com"
        use ["proxy-secret"]
      }
    '';
    "99-default-deny" = ''
      policy default_deny { action deny }
    '';
  };
};
```
