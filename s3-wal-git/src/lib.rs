//! S3-backed WAL git for axum applications.
//!
//! The repository is a write-ahead log in an object store: immutable objects
//! (bundles, packs, log entries, checkpoints) first, then a single conditional
//! write of `MANIFEST.json` as the linearization point. A local bare mirror is
//! a cache rebuilt from the manifest. Smart HTTP v0/v2 serves stock git.
//!
//! Layers:
//! - [`store`] — versioned, conditional object-store contract and backends.
//! - [`manifest`] — the on-disk manifest and the application codec seam.
//! - [`wal`] — CAS publish, immutable log, checkpoints, leases, maintenance.
//! - [`git`] — plumbing, pack ingestion, pkt-line parsing and receive framing.
//! - [`policy`] — the per-repository push rule language.
//! - [`http`] — smart HTTP, LFS, limits and auth helpers (feature `http`).
//! - [`events`] — durable WAL-to-webhook bridge.
//! - [`metrics`] — optional `metrics` facade instrumentation.

pub mod config;
pub mod error;
pub mod events;
pub mod export;
pub mod git;
pub mod import;
pub mod lfs;
pub mod manifest;
pub mod metrics;
pub mod policy;
pub mod store;
pub mod wal;
pub mod webhook;

#[cfg(feature = "http")]
pub mod http;

pub use config::{Layout, Limits, ObjectFormat, StorageMode, WalConfig};
pub use error::{ConfigError, GitError, PolicyError, RefError, StoreError, WalError};
pub use git::{local::LocalRepo, validate_refname, validate_slug, RepoId};
pub use manifest::{
    CheckpointRef, LogSegmentRef, ManifestCodec, ManifestRef, ManifestState, PackKind, PackRef,
    RefsCodec, RefsManifest, RepoSetting, RetiredPack, MANIFEST_VERSION,
};
pub use policy::{evaluate_push, Policy, PushContext, Update as PolicyUpdate};
#[cfg(feature = "gcs")]
pub use store::gcs::{GcsConfig, GcsStore};
#[cfg(feature = "s3")]
pub use store::s3::{S3Config, S3Store};
pub use store::{
    BoxStream, ByteStream, DynStore, FsStore, GetOptions, GetResult, MemoryStore, ObjectMeta,
    ObjectStore, ObjectStoreExt, Prefixed, PutBody, PutMode, PutOptions, RetryPolicy, Version,
};
pub use wal::checkpoint::Checkpoint;
pub use wal::lease::{Lease, LeaseGuard, LeaseRequest};
pub use wal::log::{LogEntry, LogKind, LogTxn, TxnKind};
pub use wal::maintenance::{CompactOptions, FsckReport, GcReport};
pub use wal::{GitSync, PublishedRef, RecordOutcome, RefUpdate, RefUpdate as WalRefUpdate, Wal};
