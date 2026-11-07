# Aide-mémoire : syntaxe

L'indentation dans les fichiers Portail n'a aucun effet. Vous pouvez formatter le fichier comme bon vous semble.

## Structure d'une politique

```portail
policy nom_de_la_politique {
  when condition    # optionnel : quand la politique s'applique
  require condition # optionnel : pré-requis pour l'action
  action action_a_effectuer  # obligatoire
}
```

Les politiques sont évaluées **de haut en bas**. Dès qu'une action est exécutée, l'évaluation s'arrête.
Si les blocs `when` et `require` sont omis, la politique s'exécute systématiquement (à placer en fin de fichier).

## Structure d'une route

```portail
route nom_de_la_route {
  when condition
  use ["backend1", "backend2", ...]
}
```

Les backends sont essayés dans l'ordre. Ils doivent correspondre à des noms déclarés dans `services.portail.settings.backends`.

## Opérateurs de comparaison

| Opérateur | Signification | Exemple |
|-----------|---------------|---------|
| `==` | Égalité | `proxy.cmd == "connect"` |
| `!=` | Différent de | `protocol != "http"` |
| `=~` | Expression régulière | `host =~ ".*gouv.fr"` |
| `in` | Appartenance à un ensemble | `host in ["github.com", "example.org"]` |

## Opérateurs logiques

| Opérateur | Signification |
|-----------|---------------|
| `and` | *et* logique |
| `or` | *ou* logique |
| `not` | négation logique |

Les parenthèses `( )` permettent de regrouper les expressions.

## Actions disponibles

| Action | Effet |
|--------|-------|
| `allow` | Autorise la requête, interrompt l'évaluation |
| `deny` | Refuse la requête, interrompt l'évaluation |
| `redirect <url>` | Redirige la requête, interrompt l'évaluation |

## Variables de contexte

| Variable | Type | Description | Contexte |
|----------|------|-------------|----------|
| `route.local` | `bool` | Mode autonome (`true`) ou chaînage (`false`) | Toujours |
| `proxy.protocol` | `string` | Protocole proxy : `socks5`, `http` | Toujours |
| `host` | `string` | Nom d'hôte cible | Toujours |
| `port` | `u16` | Port cible (0–65535) | Toujours |
| `proxy.cmd` | `string` | Commande SOCKS5 : `tcp_connect`, `udp_associate` | SOCKS5 |
| `tunnel.protocol` | `string` | Protocole du tunnel externe : `socks5`, `http` | Toujours |
| `tunnel.transport` | `string` | Transport externe : `tls`, `plaintext` | Toujours |
| `tunnel.host` | `string` | Hôte cible externe canonique | Toujours |
| `tunnel.port` | `u16` | Port cible externe | Toujours |
| `tunnel.client.auth` | `string` | Authentification client : `none`, `mtls` | Toujours |
| `tunnel.client.cert.subject_cn` | `string` | CN du sujet du certificat client | mTLS |
| `tunnel.client.cert.issuer_cn` | `string` | CN de l'émetteur du certificat client | mTLS |
| `tunnel.client.cert.serial` | `string` | Numéro de série du certificat client | mTLS |
| `tunnel.client.cert.san_dns` | `set` | SAN DNS du certificat client | mTLS |
| `tunnel.client.cert.san_uri` | `set` | SAN URI du certificat client | mTLS |
| `tunnel.client.cert.san_email` | `set` | SAN email du certificat client | mTLS |
| `tunnel.client.cert.san_ip` | `set` | SAN IP du certificat client | mTLS |
