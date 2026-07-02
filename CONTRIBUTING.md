# Contributing to CloakPipe

Thanks for your interest in contributing to CloakPipe! This document covers the basics you need to get started.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/<your-username>/cloakpipe.git`
3. Create a branch: `git checkout -b my-feature`
4. Make your changes
5. Run tests: `cargo test`
6. Push and open a pull request

## Development Setup

```bash
# Build
cargo build

# Run tests
cargo test

# Run with debug logging
RUST_LOG=debug cargo run -- start

# Run detection test (no API key needed)
cargo run -- test --text "Send $1.2M to alice@acme.com"
```

## Project Structure

CloakPipe is a Cargo workspace with these crates:

| Crate | Purpose |
|-------|---------|
| `cloakpipe-core` | Detection engine, pseudonymization, vault, rehydration |
| `cloakpipe-proxy` | Axum HTTP proxy server |
| `cloakpipe-cli` | CLI binary |
| `cloakpipe-audit` | JSONL audit logging |
| `cloakpipe-tree` | Vectorless retrieval (planned) |
| `cloakpipe-vector` | Vector encryption (planned) |
| `cloakpipe-local` | Local-only RAG mode (planned) |

## What to Contribute

- **Bug fixes** -- Always welcome. Please include a test that reproduces the bug.
- **New detection patterns** -- Add regex patterns to `cloakpipe-core/src/detector/patterns.rs` or financial patterns to `financial.rs`.
- **Documentation** -- Improvements to README, inline docs, or usage examples.
- **Tests** -- More coverage is always good. Integration tests live in `cloakpipe-core/tests/`.

For larger changes (new features, architectural changes), please open an issue first to discuss the approach.

## Code Guidelines

- Run `cargo test` before submitting. All tests must pass.
- Run `cargo clippy` and address any warnings.
- Follow existing code style -- no need to reformat files you didn't change.
- Keep PRs focused. One feature or fix per PR.
- Write tests for new functionality.

## Security

If you discover a security vulnerability, **do not open a public issue**. Instead, report it privately via [GitHub Security Advisories](https://github.com/rohansx/cloakpipe/security/advisories/new).

## License

By contributing, you agree that your contributions will be licensed under the same license as the project: MIT.
