# Référence API

Portail expose une API de contrôle via [Varlink](https://varlink.org/) sur un socket Unix
(`/run/fr.gouv.portail.Control`).

## Commandes RPC disponibles

| Commande | Description |
|----------|-------------|
| `portail rpc print-current-backend` | Affiche le backend par défaut actuel |
| `portail rpc list-backends` | Liste tous les backends et leur état |
| `portail rpc set-default-backend <nom>` | Définit le backend par défaut |
| `portail rpc unset-default-backend` | Efface le backend par défaut |
| `portail rpc update-dynamic-backend --target-address <adresse> <nom>` | Met à jour l'adresse d'un backend dynamique |

## Permissions RPC

| Commande | Groupe requis | Effet |
|---------|---------------|--------|
| `print-current-backend` | (tous) | Lire le backend par défaut actuel |
| `list-backends` | (tous) | Lister tous les backends |
| `set-default-backend` | `trusted-groups` | Changer la cible de routage par défaut |
| `unset-default-backend` | `trusted-groups` | Effacer le backend par défaut |
| `update-dynamic-backend` | `admin-groups` | Rediriger le trafic vers une nouvelle adresse de backend |

Les groupes sont configurés via `[rpc]` dans les paramètres TOML ou
`services.portail.settings.rpc` dans le module NixOS. Voir
[Configuration](./configuration.md) pour les détails.

> La référence complète de l'API Varlink est toujours en cours de développement et doit être considérée comme instable.

## Interface Varlink

La définition de l'interface est dans `src/rpc/fr.gouv.portail.control.varlink`.

## Activation par socket

Portail utilise l'activation par socket systemd pour :
- **Socket proxy**: `portail-proxy.socket`
- **Socket RPC**: `portail-rpc.socket`

## Référence CLI

```sh
portail --help
```

| Option | Description |
|--------|-------------|
| `--config <CHEMIN>` | Chemin vers le fichier de configuration |
| `--version` | Affiche la version et quitte |
| `daemon` | Lance le démon Portail |
| `check-acl-syntax` | Vérifie la syntaxe d'un fichier ACL |
| `rpc` | Appelle une commande RPC sur une instance en cours |

> La CLI est toujours en cours de développement et doit être considérée comme instable.
