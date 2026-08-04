# Contributing to Portail

Portail is developed openly. Contributions are welcome in all areas — code, documentation, testing, and design.

## Project structure

```
src/
├── main.rs          # Entry point, CLI argument parsing (clap)
├── lib.rs           # Library root
├── config.rs        # TOML configuration parsing
├── state.rs         # Global proxy state management
├── systemd.rs       # systemd integration (FDStore, socket activation)
├── acl/             # ACL engine: parser (winnow), AST, HIR, evaluator
├── proxy/           # SOCKS5 (fast-socks5), HTTP CONNECT (Hyper), TLS
├── rpc/             # varlink RPC interface (zlink)
└── logging/         # Structured logging (tracing)
nix/                 # Nix build infrastructure and NixOS module
docs/                # mdbook documentation (EN + FR)
benches/             # Criterion benchmarks
```

## Development environment

### Prerequisites

- Rust 2024 edition ([rustup](https://rustup.rs/))
- OpenSSL development headers
- Nix (optional, for NixOS module and integration tests)

### Building

```sh
cargo build
cargo build --release
```

### Running tests

```sh
# Unit tests
cargo test

# Integration tests (with snapshot testing via insta)
cargo test --test '*'

# Accept new snapshots after a deliberate change
cargo insta review

# ACL benchmarks
cargo bench
```

### Linting

```sh
cargo fmt --all --check
cargo clippy --locked --all-features -- -D warnings
```

### NixOS integration tests

```sh
nix-build ./nix/release.nix -A checks.integration
```

Individual tests can be run with:

```sh
nix-build ./nix/release.nix -A checks.integration.exit-node
nix-build ./nix/release.nix -A checks.integration.portail-upstream
# etc.
```

### Building the documentation

```sh
cd docs
mdbook build book-fr --dest-dir book/fr
mdbook build book-en --dest-dir book/en
mdbook serve book-fr --open   # Live preview at localhost:3000
```

Or via Nix:

```sh
nix-build ./nix/release.nix -A packages.portail.docs.all
```

## Pull request process

1. **Open an issue first** to discuss the change — especially for new features or significant refactors.
2. Fork the repository and create a feature branch from `main`.
3. Make your changes, following the code style below.
4. Add tests for new functionality. Use `insta` for snapshot tests where appropriate.
5. Run `cargo fmt`, `cargo clippy`, and `cargo test` before submitting.
6. Update documentation if your change affects user-facing behavior (both EN and FR where applicable).
7. Submit a PR against `main`. Link the issue you opened in step 1.

## Code style

- **Edition**: Rust 2024
- **Formatting**: `rustfmt` (default settings)
- **Linting**: Clippy with `-D warnings` — see `Cargo.toml` for allowed exceptions
- **Naming**: snake_case for functions/variables, CamelCase for types, descriptive names
- **Comments**: Explain *why*, not *what*. Use `//` for regular comments, `///` for doc comments.
- **Error handling**: Use `thiserror` for library errors, `anyhow` for application-level errors.

## Testing guidelines

- **Unit tests**: Place inline with `#[cfg(test)] mod tests { ... }`.
- **Integration tests**: Place in the `tests/` directory at the crate root.
- **Snapshot tests**: Use `insta` for testing parser output, ACL evaluation results, etc.
- **NixOS tests**: For end-to-end proxy scenarios (chaining, protocol handling, TLS).

## Commit conventions

Use clear, descriptive commit messages. Prefix with the area of change:

```
proxy: add HTTP/2 CONNECT support
acl: fix operator precedence in parser
docs: add French routing reference
nix: update module for dynamic backends
```

## Documentation

Portail's documentation is a bilingual mdbook (French and English).
When adding or changing features, update both languages.

- `docs/src/fr/` — French documentation
- `docs/src/en/` — English documentation
- Syntax highlighting for Portail ACL code blocks is configured in `docs/theme/head.hbs`

## Getting help

Open a GitHub issue for questions, or reach out to the maintainers.
