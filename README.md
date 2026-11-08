# crates

Shared Rust crates by [ryuzcorp](https://github.com/ryuzcorp), licensed under
Apache-2.0 (each crate carries its own `NOTICE` for derived sources).

| Crate | What |
| --- | --- |
| [`ryuz_workflow`](ryuz_workflow/) | GitHub-Actions-style CI workflows executed in containers: strict YAML parser, matrix/parallel runner, structured events and failure outcomes. |
| [`ryuz_git`](ryuz_git/) | S3-backed WAL git: immutable tip bundles plus one `MANIFEST.json` flip, bare-mirror sync, push policy and an axum smart-HTTP server. |

```bash
cargo fmt --all --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
```
