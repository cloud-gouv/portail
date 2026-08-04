# Aide-mémoire : routage

## Modes de fonctionnement

| Mode | `route.local` | Description | Recommandation |
|------|--------------|-------------|----------------|
| Autonome | `true` | Portail établit lui-même la connexion directe vers la cible. Tout le filtrage et la traçabilité reposent sur l'instance locale. | Serveurs Portail (proxies distants) |
| Chaînage | `false` | Portail délègue à un proxy distant. L'évaluation se fait en deux temps : locale d'abord, distante ensuite. | Clients Portail (postes de travail) |
| Fallback | bascule vers `true` | Quand tous les backends distants sont injoignables, la requête est ré-évaluée en mode autonome. | À n'utiliser que pour la reprise après sinistre ou pour éviter de compromettre la productivité |

## Ordre de résolution des backends

Lorsqu'une requête doit être routée :

1. **Blocs `route`**: le premier bloc `route` dont les conditions correspondent
   recommande une liste de backends. Ils sont essayés un par un.
2. **Backend par défaut**: configurable via `services.portail.settings.default-backend`
   ou `portail rpc set-default-backend`.
3. **Fallback autonome**: si tous les backends échouent, la requête est
   ré-évaluée en mode autonome (`route.local = true`).

```
┌────────── Requête entrante ──────────┐
│                                      │
│  1. Blocs route                      │──> Essai backend 1, 2, ... N
│                                      │
│  2. Backend par défaut               │──> Essai
│                                      │
│  3. Fallback autonome                │──> Ré-évaluation ACL
│     (route.local = true)             │
│                                      │
└──────────────────────────────────────┘
```

## Backends dynamiques

Un backend marqué `dynamic = true` peut être mis à jour à chaud sans redémarrer
Portail. Utile quand l'adresse change en réponse à des événements externes
(rotation d'IP, annonces de service).

```nix
services.portail.settings.backends.mon_proxy_secret = {
  dynamic = true;
};
```

Mise à jour via RPC :
```sh
portail rpc update-dynamic-backend --target-address 10.0.1.5:8080 mon_proxy_secret
```

Tant que la première mise à jour n'a pas été faite, les requêtes passant par
ce backend échoueront.

## Types de backends

| Type | Configuration | Usage |
|------|---------------|-------|
| Statique | `target-address = "1.2.3.4:8080"` | Proxies dont l'adresse est connue et fixe |
| Dynamique | `dynamic = true` | Proxies dont l'adresse change (rotation, annonces) |
| Défaut | `default-backend` | Fallback quand aucune route ne correspond |
