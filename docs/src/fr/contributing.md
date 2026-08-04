# Contribuer

Portail est développé ouvertement. Les contributions sont les bienvenues dans
tous les domaines : code, documentation, tests et conception.

## Environnement de développement

### Prérequis

Ce projet cible Nix/NixOS en priorité et repose donc sur Nix dans l'environnement
de développement.

### Compilation

```sh
$ nix-shell -p cargo rustc
$ cargo build
$ cargo build --release
```

### Tests

```sh
$ cargo test

# Tests d'intégration (avec snapshots insta)
$ cargo test --test '*'

# Accepter les nouveaux snapshots après un changement délibéré
$ cargo insta review

# Benchmarks ACL
$ cargo bench
```

### Linting

```sh
$ nix-shell -p rustfmt clippy
$ cargo fmt --all --check
$ cargo clippy --locked --all-features -- -D warnings
```

### Tests d'intégration NixOS

```sh
$ nix-build ./nix/release.nix -A checks.integration
```

Tests individuels :

```sh
$ nix-build ./nix/release.nix -A checks.integration.exit-node
$ nix-build ./nix/release.nix -A checks.integration.portail-upstream
```

### Construire la documentation

```sh
$ nix-shell -p mdbook
$ cd docs
$ mdbook build book-fr --dest-dir book/fr
$ mdbook build book-en --dest-dir book/en
$ mdbook serve book-fr --open
```

Ou via Nix :

```sh
$ nix-build ./nix/release.nix -A packages.portail.docs.all
```

## Processus de pull request

1. Ouvrir une issue d'abord, surtout pour les nouvelles fonctionnalités ou les refactorings importants.
2. Forker le dépôt et créer une branche depuis `main`.
3. Appliquer vos changements en suivant le style de code ci-dessous.
4. Ajouter des tests pour les nouvelles fonctionnalités. Utiliser `insta` pour les snapshots.
5. Lancer `cargo fmt`, `cargo clippy` et `cargo test` avant de soumettre.
6. Mettre à jour la documentation si le changement affecte le comportement utilisateur (FR et EN).
7. Soumettre une PR contre `main`. Référencer l'issue de l'étape 1.

## Style de code

- Édition : Rust 2024
- Formatage : `rustfmt` (paramètres par défaut)
- Linting : Clippy avec `-D warnings` (voir `Cargo.toml` pour les exceptions)
- Nommage : snake_case pour les fonctions/variables, CamelCase pour les types
- Commentaires : Expliquer *pourquoi*, pas *quoi*. `//` pour les commentaires, `///` pour la documentation.
- Gestion d'erreurs : `thiserror` pour les erreurs de bibliothèque, `anyhow` pour les erreurs applicatives.

## Conventions de test

- Tests unitaires : Dans le module avec `#[cfg(test)] mod tests { ... }`.
- Tests de snapshot : Utiliser `insta` pour la sortie du parseur, les résultats ACL, etc.
- Tests NixOS : Pour les scénarios de bout en bout (chaînage, protocoles, TLS).

## Conventions de commit

Utiliser des messages clairs et descriptifs. Préfixer avec le domaine du changement :

```
proxy: ajout du support HTTP/2 CONNECT
acl: correction de la priorité des opérateurs
docs: ajout de la référence de routage en français
nix: mise à jour du module pour les backends dynamiques
```

<https://scopedcommits.com/>

## Documentation

La documentation de Portail est un mdbook bilingue. Lors de l'ajout ou de la
modification de fonctionnalités, mettre à jour les deux langues :

- `docs/src/fr/` : documentation en français
- `docs/src/en/` : documentation en anglais
- La coloration syntaxique des blocs ACL Portail est configurée dans `docs/theme/head.hbs`
