# Cost model

The bucket is the durable authority; local disk is a cache. Every protocol is
judged on both correctness and sequential round trips.

## Budgets (healthy path)

| Operation | Sequential depth | Requests | Notes |
| --- | --- | --- | --- |
| Fresh manifest read | 1 | 1 GET (or 0 inside `freshness_ttl`) | `If-None-Match` returns 304 cheaply |
| Bundle push | 3 | manifest GET + bundle PUT + log PUT + manifest CAS | Bundle is O(repo) |
| Pack push | 4 | manifest GET + pack/idx PUT (parallel) + log PUT + manifest CAS | Pack is O(push) |
| Ref-only update | 3 | manifest GET + log PUT + manifest CAS | No objects |
| Settings publish | 3 | manifest GET + log PUT + manifest CAS | Settings ride the manifest |
| Checkpoint | 3 | refs PUT + checkpoint PUT (parallel) + manifest CAS | 4 requests |
| Lease acquire | 2 | GET + CAS PUT (or Create) | The only cross-instance mutex |
| Cold mirror (bundle) | 1 + refs | manifest GET + each bundle GET | Fetches only live tips |
| Cold mirror (pack) | 1 + packs | manifest GET + each live pack/idx/rev GET | Parallel downloads |

## Rules

- Depth before count: independent uploads use `tokio::join!`.
- Let the conditional write be the read: `Create`/`Update` 412s carry the
  answer. Do not GET first.
- Verification belongs on the failure path (ambiguous write, missing object).
- Never LIST on a hot path. Probe keys; use `list_prefixes` only for admin.
- The manifest is the one GET every request makes; carry pack set, checkpoint
  pointer, log window, HEAD and settings in it.
- Reuse versions: after a CAS success the returned version is current; after a
  412 the store may report the current version.
- Jitter every retry against a shared CAS object.
- Immutable objects are cacheable forever with a strong ETag.

## Bytes budgets

- Bundle mode: one full-history bundle per changed ref. Switch to pack mode
  when p95 upload per update exceeds `pack_threshold_bytes` (default 1 MiB).
- Pack mode: incoming packs are uploaded as received (fix-thin resolved
  locally); compaction rewrites only when configured.
- `max_push_bytes`, `max_body_bytes`, `max_bundle_bytes`, `max_repo_bytes` are
  enforced before upload.
