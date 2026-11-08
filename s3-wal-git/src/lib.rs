//! S3-backed WAL git for axum applications.
//!
//! One repository is a write-ahead log in an object store: every tip is
//! written as an immutable bundle first, then a single `MANIFEST.json` write
//! (with `seq + 1`) is the linearization point. Readers resolve refs from the
//! manifest, so a half-written publish is never visible. The local bare mirror
//! is a cache rebuilt from the manifest whenever its refs are stale.
//!
//! The crate is storage- and format-neutral:
//!
//! - [`ObjectStore`] is the bucket seam; [`MemoryStore`] is provided for tests.
//! - [`ManifestCodec`] owns the on-disk manifest shape, so an application can
//!   keep its existing format while sharing the WAL mechanics
//!   ([`RefsManifest`] is the generic multi-ref format).
//! - [`WalConfig`]/[`Layout`] own the key layout (manifest key and the
//!   per-ref bundle prefix).
//!
//! With the default `http` feature, [`http::router`] serves stock
//! `git clone`/`push` over smart HTTP. Authentication, authorization and
//! post-push hooks are supplied by the application through
//! [`http::GitHooks`].

pub mod config;
pub mod git;
pub mod manifest;
pub mod policy;
pub mod store;
pub mod wal;

#[cfg(feature = "http")]
pub mod http;

pub use config::{Layout, WalConfig};
pub use git::{
    cas_update, head_of_ref, init_bare, is_ancestor, is_full_sha, list_refs, run_git, run_git_raw,
    run_git_stdin, set_ref, validate_slug,
};
pub use manifest::{ManifestCodec, ManifestRef, RefsCodec, RefsManifest, MANIFEST_VERSION};
pub use store::{check_delete_prefix, MemoryStore, ObjectStore};
pub use wal::{GitSync, PublishedRef, RecordOutcome, RefUpdate, Wal};
