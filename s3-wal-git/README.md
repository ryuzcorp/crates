# s3-wal-git

S3-backed WAL git for Rust/axum applications. One repository is a
write-ahead log in an object store: immutable tip bundles first, then a single
`MANIFEST.json` write (`seq + 1`) as the linearization point. A local bare
mirror is a cache rebuilt from the manifest, and `git clone`/`push` are served
over stock smart HTTP.

Derived from [Noite](https://github.com/ryuzcorp/noite)'s runner and
[Outer](https://github.com/ryuzcorp/outer)'s git module (both Apache-2.0).

## Layout

```
git/{slug}/MANIFEST.json   {version, seq, refs: {refname: {sha, bundle}}}
git/{slug}/{refname}/{sha}.bundle
```

Every publish:

1. takes the per-slug lock;
2. CAS-updates the bare mirror and creates a bundle per changed ref;
3. uploads the bundles (invisible to readers);
4. **writes the manifest with `seq + 1`** — the commit point;
5. prunes superseded bundles only after the flip.

A failure before step 4 restores the mirror and removes orphan bundles. A
reader that sees a newer `seq` rehydrates from the manifest's bundles. A
half-written publish is never visible.

## Usage

Implement [`ObjectStore`] for your bucket client (`get`, `put`, `put_file`,
`get_to_file`, `delete`, `list`, `delete_prefix`). [`MemoryStore`] is included
for tests.

```rust
use std::path::PathBuf;
use s3_wal_git::{GitSync, Layout, RefUpdate, Wal, WalConfig};

let config = WalConfig::new(PathBuf::from("/data/git"), Layout::new("git"));
let sync = GitSync::default();
let wal = Wal::new(&store, &config, &s3_wal_git::RefsCodec, &sync);

wal.init_repo("my-app").await?;
wal.apply(
    "my-app",
    &[RefUpdate::new(
        "refs/heads/main",
        None::<String>,
        &new_commit_sha,
    )],
    &[],
)
.await?;
```

`ensure_synced` returns a ready bare mirror and refreshes it when the manifest
moved. `publish`/`apply` is for commits built by the application (no worktree
required); `record_push` persists refs a git process already moved.

## Axum smart HTTP

```rust
use std::sync::Arc;

let state = Arc::new(s3_wal_git::http::GitHttp::new(
    store,
    config,
    s3_wal_git::RefsCodec,
    my_hooks,
));
let app = axum::Router::new().nest("/v1/git", s3_wal_git::http::router(state));
```

Routes:

- `GET  /{slug}/info/refs?service=git-{upload,receive}-pack`
- `POST /{slug}/git-upload-pack`
- `POST /{slug}/git-receive-pack`

[`GitHooks`] owns authorization (`authorize`), optional extra push rules, the
first-push `remote:` note, and the post-push `refs_moved` notification.
Structural policy is built in: `push` may create and fast-forward, `admin` may
force-push/delete, `view` may not push; git itself also gets
`receive.denyNonFastForwards` and `receive.denyDeletes` for non-admin pushes.

## Existing manifest formats

If your application already writes a different manifest JSON, implement
[`ManifestCodec`] for that type instead of adopting [`RefsManifest`]. The WAL
only needs `seq`, a normalized `refname -> {sha, bundle}` view, and a builder
for the next manifest. This keeps an existing bucket format readable while
sharing the WAL mechanics.

## Guarantees

- Missing bundle keys surface as errors; an unreachable store never reads as
  "no manifest" (which would restart `seq` and drop refs).
- `applied_seq` only moves forward, so a stale read cannot roll a mirror back.
- Two concurrent publishes over the same pair of slugs serialize in lexical
  order (no lock inversion).
- `delete_prefix` refuses empty prefixes and prefixes without a trailing `/`.
- Commands run with a cleared environment, their own process group, and a
  timeout (a timed-out git's grandchildren die with it).

## Tests

```bash
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo test --locked
```

The suite covers publish/prune, CAS conflicts, multi-ref deletes, cold
rehydrate, rollback on a failed manifest read, lock ordering, policy parsing,
and a real `git push` + `git clone` through the axum router.
