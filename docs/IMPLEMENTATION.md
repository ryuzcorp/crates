# s3-wal-git 0.2 implementation contract

Status: foundation (`store` types, `manifest` v2, `config`, `git` core, errors)
is in place and compiles. Everything below is the target for this branch.

## Invariants (non-negotiable)

1. The manifest is the only commit point. A push is acknowledged only after the
   manifest write succeeds.
2. Manifest writes are conditional (`PutMode::Update(version)` / `Create`). On
   `PreconditionFailed`, re-read, revalidate every expected old OID, re-seq and
   retry with jitter. Never overwrite blindly.
3. An ambiguous write (non-412 error) is resolved by re-reading: adopt only if
   the manifest names our exact tips and seq, otherwise roll back the mirror.
4. Immutable objects are written before the manifest; they are content-addressed
   or sequence-addressed and may be orphaned safely.
5. A missing object/store failure never reads as "no manifest".
6. Local state is a cache. Every path must recover from an empty `repos_dir`.
7. No unsafe except the existing process-group kill. No `todo!`,
   `unimplemented!`, placeholders or silent fallbacks in final code.
8. Never delete bytes that a live or retired manifest names.

## Module ownership (do not edit outside your files)

| Owner | Files |
| --- | --- |
| WAL core | `src/wal/mod.rs`, `publish.rs`, `log.rs`, `sync.rs` |
| WAL maintenance | `src/wal/checkpoint.rs`, `lease.rs`, `maintenance.rs` |
| Git protocol/ingest | `src/git/ingest.rs`, `receive.rs`, `protocol.rs`, `local.rs` |
| Store backends | `src/store/s3.rs`, `gcs.rs`, `contract.rs`, `fs.rs`, `memory.rs`, `fault.rs` |
| Policy | `src/policy.rs` |
| HTTP | `src/http/*` |
| Events/LFS/metrics | `src/events.rs`, `webhook.rs`, `lfs.rs`, `metrics.rs` |
| Import/CLI | `src/import.rs`, `src/bin/walgit.rs`, `src/export.rs` |
| Integration owner | parent: `src/lib.rs`, `Cargo.toml`, cross-module fixes |

If an interface must change, implement against the contract and report the
exact missing method in the final message. Do not edit another owner's file.

## Core types

`Wal<C: ManifestCodec>` (`src/wal/mod.rs`) is cloneable, owns
`DynStore`, `Arc<WalConfig>`, `Arc<C>`, `GitSync`. Required methods:

```rust
load_manifest(slug) -> Result<Option<(C::Manifest, Version)>, WalError>
read_manifest(slug) -> Result<Option<C::Manifest>, WalError>
write_manifest(slug, &manifest, PutMode) -> Result<ObjectMeta, WalError>
pending_manifest(slug) -> Result<Option<(C::Manifest, Version)>, WalError>
init_repo(slug) -> Result<(), WalError>
ensure_synced(slug) -> Result<PathBuf, WalError>
ensure_synced_locked(slug) -> Result<PathBuf, WalError>
rehydrate(slug) -> Result<BTreeMap<String, String>, WalError>
publish(slug, &[RefUpdate]) -> Result<RecordOutcome, WalError>
publish_locked(slug, &[RefUpdate]) -> Result<RecordOutcome, WalError>
record_push(slug, &RefSnapshot, Option<IngestedPack>) -> Result<RecordOutcome, WalError>
record_push_locked(slug, &RefSnapshot, Option<IngestedPack>) -> Result<RecordOutcome, WalError>
publish_settings(slug, RepoSetting) -> Result<RecordOutcome, WalError>
purge(slug) -> Result<(), WalError>
head_of(slug, refname) -> Result<Option<String>, WalError>
is_fast_forward(slug, old, new) -> Result<bool, WalError>
read_log(slug, from, to) -> Result<Vec<LogEntry>, WalError>
checkpoint(slug) -> Result<Option<CheckpointRef>, WalError>
compact(slug, CompactOptions) -> Result<Option<PackRef>, WalError>
fsck(slug) -> Result<FsckReport, WalError>
lease(slug, LeaseRequest) -> Result<Option<LeaseGuard>, WalError>
read_policy(slug) -> Result<Policy, WalError>
write_policy(slug, &Policy) -> Result<(), WalError>
```

`RefUpdate` is in `wal/mod.rs`; `RefSnapshot` in `git/mod.rs`.

Manifest state is read/written through `ManifestCodec::state/from_state`.

## Storage modes

- `StorageMode::Bundle`: one bundle per changed ref under the layout bundle key;
  manifest refs carry `bundle: Some(key)`.
- `StorageMode::Pack`: incoming HTTP pack is ingested with
  `git::ingest::ingest_pack`, uploaded as `wal/<checksum>.{pack,idx,rev}`,
  appended to `manifest.packs`; refs carry `bundle: None`. Programmatic
  `publish` creates a full pack with `git pack-objects --all` and retires older
  packs into `retired_packs`.
- Rehydrate installs every live pack before setting refs; bundle mode fetches
  each manifest ref bundle.

## Log / checkpoint / lease

- `LogEntry { seq, kind, txns, pack, supersedes, checkpoint, created_at, writer, meta }`.
- One segment object per publish batch at `layout.log_key(slug, first_seq)`,
  written with `PutMode::Create`; JSON array or framed JSON, immutable.
- Manifest appends the segment ref. On 412, burn the seq and retry (strictly
  increasing, not dense).
- Checkpoint at `layout.checkpoint_key` + refs snapshot at
  `layout.checkpoint_refs_key`; CAS manifest `checkpoint` and trim folded log.
- Lease at `layout.lease_key`: CAS JSON `{holder, purpose, expires_at}`; TTL
  heartbeat; release deletes conditionally.
- Maintenance: compaction, fsck (connectivity), gc (only packs not named live or
  retired, older than `retention_grace`), repair report.

## Policy

Port the rule language: groups + ordered rules; `match` keys `refs`,
`principals`, `paths` (AND of keys, OR of values), one glob dialect (`*`, `?`,
`**`, `^` exclusion); effects `protect` (create/update/delete/force-push,
bypass), `history`, `size`. Named denial text. Unknown keys inside a rule are
errors; unknown envelope keys ignored. Missing file = allow-all. `group:`
references must resolve at validation. The receive path enforces `push_bytes`
and history limits; a `blob_bytes` rule is rejected until changed-path
inspection is wired rather than silently ignored.

## HTTP

- Routes accept both `demo` and `acme/demo` via a catch-all repo segment.
- `info/refs` honors `Git-Protocol: version=2` and runs
  `git upload-pack --stateless-rpc --advertise-refs` with `GIT_PROTOCOL=version=2`;
  no `# service` wrapper in v2. v0 keeps the wrapper.
- `POST /git-upload-pack` and `POST /git-receive-pack` pass
  `GIT_PROTOCOL=version=2` when negotiated.
- receive: parse with `git::receive::parse_receive`, authorize, evaluate policy,
  hold the slug lock, ensure synced, run `git receive-pack --stateless-rpc`
  (deny non-FF/deletes for non-admin), then `record_push` with the ingested pack
  when storage is pack mode.
- LFS: batch + basic transfer routes.
- Layers: body limit, timeout, concurrency, catch-panic, request id.
- Auth hook trait stays `GitHooks`; `authorize_request` receives the request
  headers (the default delegates to `authorize`), plus static-token/Basic
  helpers.

## Testing rules

- Deterministic, no wall-clock sleeps in tests; use barriers/notify/injected
  clocks.
- Real git interop tests are preferred for protocol paths.
- FaultStore for 412/5xx/lost-response tests.
- Unit tests live in the module; cross-module tests in `tests/`.
- Run `cargo fmt --all`, `cargo clippy --all-targets -- -D warnings`,
  `cargo test` before reporting. Full-workspace failures caused by another
  owner's unfinished file are expected; report them, do not patch them.

## Definition of done for this wave

The module compiles when the rest of the branch is complete, has real tests,
and contains no placeholders.
