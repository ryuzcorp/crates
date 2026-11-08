# s3-wal-git

S3-backed WAL git for Rust/axum applications. A repository is a write-ahead log
in an object store: immutable objects first, then one **conditional** manifest
write as the linearization point. A local bare mirror is a cache rebuilt from
the manifest, and smart HTTP v0/v2 serves stock `git clone`/`fetch`/`push`.

Derived from [Noite](https://github.com/ryuzcorp/noite)'s runner and
[Outer](https://github.com/ryuzcorp/outer)'s git module (Apache-2.0).

## What it does

| Area | Features |
| --- | --- |
| Durability | CAS manifest, immutable log segments, checkpoints, ambiguous-write reconciliation, rollback on failure |
| Storage | Bundle mode (full tip bundles) and pack mode (incoming packs + live pack set), connectivity checks, safe GC |
| Git protocol | v0 and v2 advertising, `ls-refs`/`fetch` via stock git, shallow/filter, report-status-v2, push options, atomic pushes |
| Concurrency | Per-slug locks, cross-instance CAS retries, single-flight group commit, TTL leases |
| Policy | Per-repo rule language: protected refs, groups, fast-forward, deletes, size/history ceilings |
| Auth | Pluggable `GitHooks`; token/Basic helpers; anonymous read opt-in |
| LFS | Batch + basic transfer, signed URLs, locks, quotas |
| Events | WAL-derived ref events, durable cursor, HMAC webhooks, dedup/gap metrics |
| Ops | fsck, compaction, retention, import/export, CLI, Prometheus metrics, structured tracing |
| Stores | Memory, filesystem, S3/R2/MinIO (feature `s3`), GCS (feature `gcs`) |

## Layout

```
git/{repo}/MANIFEST.json          CAS commit point: refs, HEAD, packs, log, checkpoint, settings
git/{repo}/{refname}/{sha}.bundle bundle mode
git/{repo}/wal/{checksum}.pack    pack mode (+ .idx, .rev)
git/{repo}/log/{seq}.json         immutable publish log
git/{repo}/checkpoints/{seq}/     folded refs + pack inventory
git/{repo}/leases/{name}.json     CAS lease with TTL
git/{repo}/policy.json            per-repo push rules
git/{repo}/events/cursor.json     durable event cursor
git/{repo}/lfs/objects/…          LFS objects
```

A publish:

1. takes the per-slug lock;
2. loads `(manifest, version)` and syncs the mirror;
3. CAS-updates the mirror refs and uploads immutable bundles/packs;
4. writes one immutable log segment;
5. **CAS-writes the manifest** (`Update(version)` / `Create`);
6. retires packs after the flip; superseded bundles are left for `gc`, which
   honors `retention_grace` so readers holding the previous manifest still win.

On 412 it re-reads, revalidates every expected old OID, re-sequences and
retries with jitter. On an ambiguous error it re-reads and adopts only a
manifest that names its exact tips and seq.

## Usage

Implement `ObjectStore` for your bucket client (`get`, `head`, `put`, `delete`,
`list`, `list_prefixes`, optional signed URLs). Implementations for memory,
filesystem, S3 and GCS ship in the crate.

```rust
use std::sync::Arc;
use s3_wal_git::{Layout, ObjectStore, RefsCodec, Wal, WalConfig};

let config = WalConfig::new("/data/git", Layout::new("git"));
let wal = Wal::new(store, Arc::new(config), Arc::new(RefsCodec));

wal.init_repo("acme/app").await?;
wal.publish(
    "acme/app",
    &[s3_wal_git::RefUpdate::set(
        "refs/heads/main",
        None::<String>,
        &new_commit_sha,
    )],
)
.await?;
```

### S3/R2/MinIO store

```rust
use std::sync::Arc;
#[cfg(feature = "s3")]
use s3_wal_git::{S3Config, S3Store};

#[cfg(feature = "s3")]
let store = Arc::new(
    S3Store::new(
        S3Config::new("my-bucket")
            .with_region("auto")
            .with_endpoint("https://<account>.r2.cloudflarestorage.com")
            .with_path_style(true)
            .with_credentials(access_key, secret_key, None),
    )
    .await?,
);
```

Omit `with_credentials` to use the AWS provider chain. GCS uses
`GcsStore::new(GcsConfig::new("bucket"))`. Both implement `ObjectStore` and can
be wrapped in `Prefixed::new(store, "tenant/")`.

## Axum

```rust
use std::sync::Arc;

let state = Arc::new(s3_wal_git::http::GitHttp::new(
    store,
    Arc::new(config),
    Arc::new(RefsCodec),
    my_hooks,
));
let app = axum::Router::new()
    .nest("/v1/git", s3_wal_git::http::router(state));
```

Routes:

- `GET  /{repo}/info/refs?service=git-{upload,receive}-pack`
- `POST /{repo}/git-upload-pack`
- `POST /{repo}/git-receive-pack`
- `POST /{repo}/info/lfs/objects/batch`
- `PUT|GET /{repo}/info/lfs/objects/{oid}`

`{repo}` accepts `demo` and `acme/demo`. `GitHooks` owns authorization, extra
push rules, the first-push note and post-push notification. Limits, timeouts,
per-repo concurrency and panic containment are applied by the router.

## Existing manifest formats

If your application already writes a different manifest JSON, implement
`ManifestCodec` for that type. The WAL needs `seq`, a normalized
`refname -> {sha, bundle}` view and a builder for the next manifest; packs,
log, HEAD and settings are optional extensions. This keeps an existing bucket
format readable while sharing the WAL mechanics.

## CLI

```bash
cargo run --features cli --bin walgit -- --config walgit.toml ls acme/app
cargo run --features cli --bin walgit -- compact acme/app
cargo run --features cli --bin walgit -- fsck acme/app
```

```toml
[store]
kind = "s3"                     # memory | fs | s3
bucket = "my-bucket"
region = "auto"
endpoint = "http://127.0.0.1:9000"
access_key = "..."
secret_key = "..."

[wal]
prefix = "git"
storage = "pack"                # bundle | pack
repos_dir = "/data/walgit-repos"
```

Build the S3 CLI with `--features cli,s3`.

## Guarantees

- A missing object or unreachable store never reads as “no manifest”.
- Two writers cannot both win a manifest CAS; stale writers revalidate and retry.
- A push is acknowledged only after the manifest write.
- `applied_seq` never moves backward; purges forget the generation.
- `delete_prefix` refuses empty or non-scoped prefixes.
- Git runs with a cleared environment, its own process group and a timeout.
- Issued pack/bundle bytes are never deleted while a live or retired manifest names them.
- Unreferenced bundles are collected only after the retention grace; a publish
  never deletes a bundle another host may be about to commit.

## Tests

```bash
cargo fmt --all --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
cargo check --features cli,webhook-client,s3,gcs
```

The suite covers store contracts, CAS/fault injection, two-writer races,
bundle/pack rehydrate, policy, LFS, events, real `git push`/`clone` through the
axum router, and v0/v2 interop.
