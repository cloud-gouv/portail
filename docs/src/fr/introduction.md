# Introduction

**Portail** est un proxy d'accès orienté identité conçu pour les cas d'usages terminal.
Il s'inspire des [articles de recherche BeyondCorp](https://research.google/pubs/beyondcorp-the-access-proxy/)
et est conçu pour fonctionner avec [Sécurix](https://github.com/cloud-gouv/securix).

> **Statut :** Portail est en développement actif. Les fonctionnalités et API peuvent changer.
> Ne pas utiliser en production pour le moment, sauf si vous êtes familier avec le projet.

## Ce que fait Portail

Portail agit comme un **proxy direct** (*forward proxy*) placé entre vos outils en ligne de commande ou votre navigateur et le réseau.
Chaque connexion passe par un **moteur ACL** qui peut autoriser, bloquer, rediriger ou journaliser la requête
en s'appuyant sur des métadonnées riches : identité de l'appareil, attestation utilisateur, géo-filtrage,
évaluations de risque et détails au niveau de la requête.

## Capacités principales

| Domaine | Inclus |
|---------|--------|
| Protocoles | SOCKS5 (TCP CONNECT, UDP ASSOCIATE), HTTP CONNECT (1.1/2/3) |
| Routage | Mode autonome, chaînage de proxies, backends dynamiques, failover |
| Contrôle d'accès | Langage ACL avec `when`/`require`/`action`, regex, conditions par protocole |
| Authentification | Certificats mTLS (en cours) |
| Audit | Journaux d'audit structurés |
| Déploiement | Activation socket systemd, module NixOS |
| Observabilité | Métriques Prometheus (en cours) |

## Par où commencer

- [Démarrage rapide](./demarrage-rapide.md): apprenez le langage ACL et le routage par l'exemple
- [Configuration](./configuration.md): référence complète des paramètres, NixOS et TOML, avec extraits prêts à copier
- [Référence API](./api.md): commandes RPC et référence CLI
- [Contribuer](./contributing.md): environnement de développement, tests et processus de PR
- [Feuille de route](./roadmap.md): fonctionnalités implémentées et travaux prévus

## Scénarios de déploiement

Portail peut être déployé selon plusieurs topologies, du simple proxy local
jusqu'à une chaîne complète avec TLS mutuel.

### Scénario 1 : Client seul (autonome)

Portail s'exécute sur le poste de travail et se connecte directement à Internet.
Tout le filtrage et la traçabilité reposent sur l'instance locale.

```
  Poste de travail
┌──────────────┐     TCP direct        ┌──────────┐
│  curl / SSH  │──────────────────────▶│ Internet │
│      │       │                       └──────────┘
│  ┌──┴────┐   │
│  │Portail│   │  Évaluation ACL : route.local = true
│  └───────┘   │  Aucun proxy distant impliqué
└──────────────┘
```

### Scénario 2 : Client + proxy amont standard

Portail sur le poste de travail chaîne vers un proxy SOCKS5 ou HTTP CONNECT
standard exécuté sur un serveur. Les ACL sont évaluées localement, puis le
proxy amont relaie la requête vers des cibles Internet ou Intranet. Si l'amont
est injoignable, le Portail client bascule en mode autonome (ligne pointillée).

```
  Poste de travail                        Serveur
┌──────────────┐  SOCKS5 / HTTP CONNECT  ┌──────────────┐     ┌──────────┐
│  curl / SSH  │────────────────────────▶│ SOCKS5/HTTP  │────▶│ Internet │
│      │       │                         │    proxy     │     └──────────┘
│  ┌──┴────┐   │                         └──────┬───────┘     ┌──────────┐
│  │Portail│   │  ACL : évaluation locale         └────────────▶│ Intranet │
│  └──┬────┘   │  route.local = false                          └──────────┘
│     │        │
│     │ fallback (autonome, route.local = true)
│     └────────────────────────────────────────▶ ┌──────────┐
└──────────────────────────────────────────────┘ │ Internet │
                                                 └──────────┘
```

### Scénario 3 : Client + serveur Portail (double ACL)

Portail s'exécute à la fois sur le poste de travail et sur le serveur.
Le poste évalue ses politiques locales en premier, puis délègue au Portail
serveur qui évalue ses propres politiques. Les deux couches peuvent
indépendamment autoriser ou refuser la requête. Le serveur Portail peut
atteindre à la fois des cibles Internet et Intranet. Si le serveur Portail
est injoignable, le client bascule en mode autonome (ligne pointillée).

```
  Poste de travail                        Serveur
┌──────────────┐  SOCKS5 / HTTP CONNECT  ┌──────────────┐     ┌──────────┐
│  curl / SSH  │───────┬────────────────▶│   Portail    │────▶│ Internet │
│      │       │       │                │  (serveur)   │     └──────────┘
│  ┌──┴────┐   │       │                └──────┬───────┘     ┌──────────┐
│  │Portail│   │  Couche ACL 1                  └────────────▶│ Intranet │
│  │(client)   │  route.local = false                         └──────────┘
│  └──┬────┘   │
│     │        │  fallback (autonome, route.local = true)
│     └────────────────────────────────────────▶ ┌──────────┐
└──────────────────────────────────────────────┘ │ Internet │
                                                 └──────────┘
```

### Scénario 4 : Chaîne complète avec backends applicatifs en mTLS

Portail sur le poste de travail chaîne vers un Portail serveur qui route vers
des backends applicatifs derrière mTLS. Chaque backend exige un certificat
client émis par une CA de confiance (`identity-aware = true`). L'identité
est préservée de bout en bout sur toute la chaîne. Les backends servent des
applications exposées à la fois sur Internet et Intranet. Si le serveur ou
tous les backends échouent, le client bascule en mode autonome (ligne pointillée).

```
  Poste de travail                        Serveur
┌──────────────┐  mTLS                   ┌──────────────┐
│  curl / SSH  │────────────────────────▶│   Portail    │
│      │       │  certificat client      │  (serveur)   │
│  ┌──┴────┐   │                         └──────┬───────┘
│  │Portail│   │                                │
│  │(client)   │                   ┌────────────┼────────────┐
│  └──┬────┘   │                   │ mTLS       │ mTLS       │ mTLS
│     │        │                   ▼            ▼            ▼
│     │        │              ┌─────────┐ ┌─────────┐ ┌─────────┐
│     │        │              │ Backend │ │ Backend │ │ Backend │
│     │        │              │    A    │ │    B    │ │    C    │
│     │        │              └────┬────┘ └────┬────┘ └────┬────┘
│     │        │              ┌────┴──────────┴──────────┴────┐
│     │        │              │    backends identity-aware    │
│     │        │              └──────────────┬───────────────┘
│     │        │                             │
│     │        │         ┌───────────────────┼───────────────────┐
│     │        │         ▼                   ▼                   ▼
│     │        │   ┌──────────┐       ┌──────────┐       ┌──────────┐
│     │        │   │ Internet │       │ Intranet │       │   Apps   │
│     │        │   │  accès   │       │  accès   │       │  métier  │
│     │        │   └──────────┘       └──────────┘       └──────────┘
│     │        │
│     │ fallback (autonome, route.local = true)
│     └────────────────────────────────────────▶ ┌──────────┐
└──────────────────────────────────────────────┘ │ Internet │
                                                 └──────────┘
```
