# Contributing

Portail is developed openly. Contributions are welcome in all areas: code,
documentation, testing, and design.

## Development environment

### Prerequisites

This project targets Nix/NixOS first and relies on Nix for the development
environment.

### Building

```sh
$ nix-shell -p cargo rustc
$ cargo build
$ cargo build --release
```

### Running tests

```sh
$ cargo test

# Integration tests (with snapshot testing via insta)
$ cargo test --test '*'

# Accept new snapshots after a deliberate change
$ cargo insta review

# ACL benchmarks
$ cargo bench
```

### Linting

```sh
$ nix-shell -p rustfmt clippy
$ cargo fmt --all --check
$ cargo clippy --locked --all-features -- -D warnings
```

### NixOS integration tests

```sh
$ nix-build ./nix/release.nix -A checks.integration
```

Individual tests:

```sh
$ nix-build ./nix/release.nix -A checks.integration.exit-node
$ nix-build ./nix/release.nix -A checks.integration.portail-upstream
```

### Building the documentation

```sh
$ nix-shell -p mdbook
$ cd docs
$ mdbook build book-fr --dest-dir book/fr
$ mdbook build book-en --dest-dir book/en
$ mdbook serve book-fr --open
```

Or via Nix:

```sh
$ nix-build ./nix/release.nix -A packages.portail.docs.all
```

## Pull request process

1. Open an issue first, especially for new features or significant refactors.
2. Fork the repository and create a feature branch from `main`.
3. Make your changes, following the code style below.
4. Add tests for new functionality. Use `insta` for snapshot tests where appropriate.
5. Run `cargo fmt`, `cargo clippy`, and `cargo test` before submitting.
6. Update documentation if your change affects user-facing behavior (both EN and FR).
7. Submit a PR against `main`. Link the issue from step 1.

## Code style

- Edition: Rust 2024
- Formatting: `rustfmt` (default settings)
- Linting: Clippy with `-D warnings` (see `Cargo.toml` for allowed exceptions)
- Naming: snake_case for functions/variables, CamelCase for types
- Comments: Explain *why*, not *what*. Use `//` for regular comments, `///` for doc comments.
- Error handling: `thiserror` for library errors, `anyhow` for application errors.

## Testing guidelines

- Unit tests: Place inline with `#[cfg(test)] mod tests { ... }`.
- Snapshot tests: Use `insta` for testing parser output, ACL evaluation results, etc.
- NixOS tests: For end-to-end proxy scenarios (chaining, protocol handling, TLS).

## Commit conventions

Use clear, descriptive commit messages. Prefix with the area of change:

```
proxy: add HTTP/2 CONNECT support
acl: fix operator precedence in parser
docs: add French routing reference
nix: update module for dynamic backends
```

<https://scopedcommits.com/>

## Documentation

Portail's documentation is a bilingual mdbook. When adding or changing features,
update both languages:

- `docs/src/fr/`: French documentation
- `docs/src/en/`: English documentation
- Syntax highlighting for Portail ACL blocks is configured in `docs/theme/head.hbs`
