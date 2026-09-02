# Démarrage rapide

Ce chapitre vous guide à travers la mise en place de Portail sur NixOS, de l'écriture
des premières politiques ACL jusqu'au déploiement d'un backend dynamique.

Les pages suivantes servent de référence rapide une fois que vous serez familier
avec les concepts :

| Page | Contenu |
|------|---------|
| [Aide-mémoire : syntaxe](./demarrage-rapide/syntaxe.md) | Opérateurs, variables de contexte, actions |
| [Bonnes pratiques](./demarrage-rapide/bonnes-pratiques.md) | Ordre des politiques, *default deny*, nommage |
| [Aide-mémoire : routage](./demarrage-rapide/routage.md) | Modes autonome/chaînage, backends dynamiques |
| [Aide-mémoire : cas d'usage](./demarrage-rapide/cas-usage.md) | Les 6 motifs classiques |

---

## Mise en place pas à pas

Nous allons configurer Portail pour utiliser un **proxy secret** dont l'adresse
change régulièrement et ne peut pas être écrite en dur dans la configuration.
C'est le [cas d'usage 5](./demarrage-rapide/cas-usage.md#5-proxy-secret-backend-dynamique).

### 1. Activer Portail sur NixOS

Ajoutez le module Portail à votre configuration NixOS :

```nix
{
  imports = [
    # Vous pouvez utiliser Flakes ou n'importe quel gestionnaire de dépendances (ex. npins, lon, etc.) pour obtenir les entrées de Portail.
    /chemin/vers/portail/nix/module.nix
  ];

  services.portail = {
    enable = true;
    proxyListenStream = "127.0.0.1:8080";
  };
}
```

Après `nixos-rebuild switch`, les sockets systemd sont actives :

```sh
systemctl status portail-proxy.socket
systemctl status portail-rpc.socket
```

### 2. Déclarer le backend dynamique

Le proxy secret doit être déclaré avec `dynamic = true`. Tant qu'aucune adresse
n'a été fournie via RPC, les requêtes vers ce backend échoueront.

```nix
services.portail.settings.backends = {
  mon_proxy_secret = {
    # Vous n'avez pas besoin de mettre de target-address.
    # target-address = "";
    # Elle sera renseignée dynamiquement.
    dynamic = true;
  };
};
```

### 3. Configurer le groupe admin

Pour permettre la mise à jour du backend via RPC, déclarez un groupe d'administration.
Les utilisateurs membres de ce groupe pourront appeler `portail rpc`.

```nix
services.portail.settings = {
  rpc.admin-groups = ["portail-admins"];
};
```

Déclarez le groupe et les utilisateurs dans votre configuration NixOS :

```nix
users.groups.portail-admins = {};

users.users.alice = {
  isNormalUser = true;
  extraGroups = ["portail-admins"];
};
```

### 4. Écrire les politiques ACL

Créez un fichier de politiques qui :
- Route tout le trafic vers le proxy secret par défaut
- Autorise quelques sites en mode autonome (fallback si le proxy est injoignable)
- Applique un *default deny* explicite

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

### 5. Définir le backend par défaut

Pour que le trafic soit routé vers le proxy secret, définissez-le comme backend
par défaut. Ainsi, toute requête qui ne correspond à aucune route sera envoyée
vers `mon_proxy_secret`.

```nix
services.portail.settings.default-backend = "mon_proxy_secret";
```

Ou dynamiquement via RPC (vous devez être dans le groupe `trusted-groups` pour cette RPC) :

```sh
portail rpc set-default-backend mon_proxy_secret
```

### 6. Déployer et mettre à jour le backend

Après `nixos-rebuild switch`, le backend est en attente de sa première mise à jour.
Un utilisateur du groupe `portail-admins` peut alors fournir l'adresse réelle :

```sh
portail rpc update-dynamic-backend --target-address 10.0.1.5:8080 mon_proxy_secret
```

À partir de cet instant, le trafic est routé vers `10.0.1.5:8080`. Si le proxy
secret change d'adresse, il suffit de relancer la commande, aucun redémarrage
de Portail n'est nécessaire.

### 7. Vérifier le bon fonctionnement

Testez avec curl en passant par le proxy SOCKS5 local ou le proxy HTTP local :

```sh
# Proxy SOCKS5
curl --socks5 127.0.0.1:8080 https://github.com
# HTTP CONNECT
curl -x http://127.0.0.1:8080 https://github.com
```

Vérifiez l'état du backend :

```sh
portail rpc print-current-backend
```

### Résumé de la configuration complète

```nix
{
  imports = [ /chemin/vers/portail/nix/module.nix ];

  services.portail = {
    enable = true;
    proxyListenStream = "127.0.0.1:8080";

    settings = {
      admin-groups = ["portail-admins"];
      default-backend = "mon_proxy_secret";

      backends = {
        mon_proxy_secret = {
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

Pour approfondir chaque aspect, syntaxe des conditions, bonnes pratiques,
modes de routage, ou autres cas d'usage : consultez les pages d'aide-mémoire
ci-dessus.
