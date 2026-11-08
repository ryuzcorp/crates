# Migration

## Manifest v1 → v2

- Readers accept v1 (`refs` only) and v2. Writers always emit v2.
- v1 manifests are read as `bundle: Some(key)` refs, no packs/log/head.
- No rewrite is required: the first publish writes a v2 manifest from the
  state it read, preserving every ref.
- Unknown future versions are refused rather than guessed.

## Bundle → pack mode

Per repository, behind `StorageMode::Pack`:

1. Keep the current manifest and bundles live.
2. First pack publish builds a full pack from the mirror, uploads pack/idx/rev
   and CASes the manifest with `packs` plus the same refs (`bundle: null`).
3. Old bundles become unreferenced; they are removed only after the CAS, and
   only if not named by a live or retired manifest.
4. A failure before the CAS leaves the bundle-mode manifest untouched; the
   mirror still serves.
5. Rollback: a manifest that names bundles is still readable; the code never
   requires packs for a bundle-mode repo.

## Local mirror

`repos_dir` is a cache. Deleting it is always safe; the next read rehydrates
from the manifest (bundles or packs). A mirror whose refs match the manifest
is served without a rebuild.

## Store changes

Changing the store endpoint or bucket changes object identity. Keep the old
bucket readable until every live repository has been re-published, or copy the
prefixes; the manifest CAS cannot protect a repository split across stores.
