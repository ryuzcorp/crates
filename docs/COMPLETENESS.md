# Completeness matrix

Target: an embeddable production WAL git library. Status values: **shipped**
(tested in this crate), **partial** (implemented with a documented gap), **host**
(belongs to the consuming application, not this crate).

| Area | Feature | Module | Status |
| --- | --- | --- | --- |
| Store | versioned/conditional reads+writes, typed errors | `store` | shipped |
| Store | in-memory + filesystem + fault injection + contract suite | `store::{memory,fs,fault,contract}` | shipped |
| Store | S3/R2/MinIO backend (feature `s3`) | `store::s3` | shipped |
| Store | GCS backend (feature `gcs`) | `store::gcs` | shipped |
| Store | range reads, streaming/multipart bodies, signed URLs | `store` | shipped |
| Store | paginated listing + prefix listing | `store` | shipped |
| Store | retry policy (retryable only, jitter) | `store::RetryPolicy` | shipped |
| Manifest | v2 format, v1 dual-read, codec seam | `manifest` | shipped |
| Manifest | CAS publish + 412 revalidate/retry | `wal::publish` | shipped |
| Manifest | ambiguous-write reconciliation | `wal::publish` | shipped |
| Manifest | ref transactions, deletes, no-op detection | `wal` | shipped |
| Manifest | symbolic HEAD + peeled tags | `manifest`, `git` | shipped |
| Manifest | logical seq/revision/writer diagnostics | `manifest` | shipped |
| Manifest | per-repo settings with history | `wal` | shipped |
| Log | immutable log entries, segments, replay | `wal::log` | shipped |
| Log | orphan segment handling, strictly increasing seq | `wal::publish` | shipped |
| Log | checkpoints + log folding | `wal::checkpoint` | shipped |
| Storage | bundle mode (full tip bundles) | `wal` | shipped |
| Storage | pack mode (incoming packs, pack set) | `wal` | shipped |
| Storage | pack ingestion (`index-pack --fix-thin`) + connectivity | `git::ingest` | shipped |
| Storage | side-files (idx/rev) and pack retention | `wal`, `git::local` | shipped |
| Storage | safe GC of unreachable objects | `wal::maintenance` | shipped |
| Storage | large-repo remote reader / history pack | — | host/later |
| Concurrency | per-slug + rename locks | `wal::GitSync` | shipped |
| Concurrency | cross-instance CAS conflict handling | `wal::publish` | shipped |
| Concurrency | single-flight publisher / group commit | `wal::publish` | shipped |
| Concurrency | CAS leases with TTL/heartbeat | `wal::lease` | shipped |
| Concurrency | push broker/forwarding | — | host |
| Protocol | v0 smart HTTP | `http` | shipped |
| Protocol | v2 advertisement + ls-refs/fetch via stock git | `http`, `git::protocol` | shipped |
| Protocol | receive caps: report-status-v2, push-options, atomic, shallow | `git::receive` | shipped |
| Protocol | per-ref ok/ng framing + sideband errors | `git::receive` | shipped |
| Protocol | HTTP/2, gzip bodies | `http` | shipped |
| Protocol | body limits, timeouts, concurrency, catch-panic | `http::limits` | shipped |
| Policy | rule language: groups, refs/principals/paths, protect/history/size | `policy` | shipped |
| Policy | branch protection / FF / deletes / bypass | `policy`, `http` | shipped |
| Policy | push options exposed to hooks | `git::receive`, `http` | shipped |
| Auth | hooks; token/Basic helpers; anonymous read | `http::auth` | shipped |
| Auth | OIDC provider | — | host |
| LFS | batch API + basic transfer | `lfs`, `http::lfs` | shipped |
| LFS | signed/direct transfer, quotas, upstream read-through | `lfs` | partial |
| LFS | locking API | `lfs` | shipped |
| Events | ref events derived from WAL | `events` | shipped |
| Events | durable cursor, HMAC, dedup, batching, gaps | `events`, `webhook` | shipped |
| Events | notification wakeups + sweep | `events` | shipped |
| Events | push-driven app hook | `http::GitHooks` | shipped |
| Observe | metrics (pushes, bytes, CAS, store, events, LFS) | `metrics` | shipped |
| Observe | tracing spans + request ids + structured logs | `http`, `metrics` | shipped |
| Observe | health/readiness, config validation | `config`, `http` | shipped |
| Ops | checkpoints, compaction, fsck, repair seam, retention | `wal::maintenance` | shipped |
| Ops | quotas, rate limits, audit log | `policy`, `http`, `wal` | partial |
| Ops | backup/restore, resumable import/export | `import`, `export` | shipped |
| Ops | CLI | `bin/walgit` | shipped |
| Compat | `owner/repo` namespacing | `git::RepoId` | shipped |
| Compat | sha256 repositories | `config::ObjectFormat`, `git` | shipped |
| Compat | hidden/advertised refs | `config`, `git` | shipped |
| Compat | shallow/partial clone | stock git via v2 | shipped |
| Tests | backend contract, fault injection, multi-writer race | `store::contract`, `tests/` | shipped |
| Tests | real git interop (push/clone, v0/v2, sha1/sha256, LFS) | `tests/` | shipped |
| Docs | invariants, cost model, policy, events, migration | `docs/`, README | shipped |

Host-only (explicit non-goals): web UI, SDK, billing, multi-host placement,
OIDC, remote pack serving/history packs, service-side compose.
