# Bonnes pratiques

## Ordre des politiques

Les politiques sont évaluées **dans l'ordre de déclaration**, de haut en bas. La première
dont les conditions sont satisfaites voit son action exécutée, et l'évaluation s'arrête.

Placez toujours les cas **spécifiques avant** les cas généraux.

```portail
# Correct : les politiques spécifiques d'abord
policy admin_access {
  when host =~ "(horizon|auth).cloud.example.com"
  action allow
}

policy allowed_sites {
  when host in ["github.com", "google.com"]
  action allow
}

policy default_deny {
  action deny
}
```

```portail
# Incorrect : la règle générale capture tout avant les spécifiques
policy allow_all {
  action allow
}

policy block_unapproved_llm_usage {
  when host in ["chatgpt.com", "deepseek.com", "anthropic.com"]
  action deny  # jamais atteinte !
}
```

## Politique par défaut explicite

Portail applique un *default deny* implicite si aucune politique ne produit de `allow`.
Pour rendre vos fichiers lisibles et prévisibles, **ajoutez toujours un `default deny` explicite**
en dernière position.

```portail
policy default_deny {
  action deny
}
```

## Utiliser `route.local` pour le failover

Sur un poste de travail, vous pouvez autoriser un trafic restreint en mode autonome
(fallback) tout en exigeant le proxy distant en mode normal :

```portail
# En mode autonome : accès limité à quelques sites
policy failover_sites {
  when host in ["github.com", "google.com"] and route.local == true
  action allow
}

# En mode chaînage : on fait confiance au proxy distant
policy delegate_to_remote {
  when route.local == false
  action allow
}

policy default_deny {
  action deny
}
```

Cette technique est utile lorsque l'infrastructure proxy distante est en cours de déploiement
et que vous voulez un filet de sécurité sans compromettre la productivité.

## Nommage des politiques

Utilisez des noms descriptifs en `snake_case`. Préfixez avec des numéros si vous voulez contrôler
l'ordre dans des fichiers séparés.

Avec le module NixOS, les politiques ACL sont déclarées comme un ensemble d'attributs sous
`services.portail.acl.filter.rules`. Les clés sont triées par ordre lexicographique,
les préfixes numériques permettent donc de contrôler l'ordre d'évaluation :

```nix
services.portail.acl.filter.rules = {
  "10-admin" = ''policy admin_access { ... }'';
  "20-intranet" = ''route cloud_console { ... }'';
  "50-failover" = ''policy failover_sites { ... }'';
  "99-default-deny" = ''policy default_deny { action deny }'';
};
```

Si vous gérez les ACL sous forme de fichiers plats, utilisez `filter-acl-rules-path`
dans vos paramètres. Le fichier est lu de haut en bas sans tri lexicographique.
