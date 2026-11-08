//! The WAL: manifest CAS, immutable log, checkpoints, leases and mirrors.
//!
//! The manifest is the only commit point. Immutable objects (bundles, packs,
//! log segments) are written first; the manifest is then replaced with a
//! conditional write. A loser re-reads, revalidates and retries; a local mirror
//! is a cache that any path can rebuild from the manifest.
//!
//! Lock order (outermost first): HTTP/application locks, then the per-slug lock
//! in [`GitSync`], then store operations. [`Wal::publish_locked`] and
//! [`Wal::record_push_locked`] exist for callers that already hold the slug
//! lock across a longer operation (for example `git receive-pack`).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Mutex;

use crate::config::WalConfig;
use crate::error::{StoreError, WalError};
use crate::git;
use crate::manifest::{ManifestCodec, ManifestState};
use crate::store::{
    DynStore, GetOptions, GetResult, ObjectMeta, ObjectStoreExt, PutBody, PutMode, PutOptions,
    Version,
};

pub mod checkpoint;
pub mod lease;
pub mod log;
pub mod maintenance;
pub mod publish;
pub mod sync;

#[cfg(test)]
mod tests;

pub use log::{LogEntry, LogKind, LogPack, LogTxn, TxnKind};
pub use publish::BatchFailure;

/// Current time as RFC 3339 UTC, second precision.
pub(crate) fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// Diagnostic id of this writer (backend plus pid).
pub(crate) fn writer_name() -> String {
    format!("{}:{}", "wal", std::process::id())
}

/// One ref tip that moved in a publish.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishedRef {
    pub refname: String,
    pub sha: String,
    /// Bundle key in bundle mode.
    pub bundle: Option<String>,
    /// Pack checksum in pack mode.
    pub pack: Option<String>,
}

/// What one publish persisted.
#[derive(Debug, Clone, Default)]
pub struct RecordOutcome {
    pub moved: Vec<PublishedRef>,
    pub deleted: Vec<String>,
    /// Manifest sequence of the batch that committed this change (the current
    /// sequence for a no-op).
    pub seq: u64,
}

/// A ref the caller wants moved before the publish.
///
/// `expected_old` is the compare-and-swap precondition: `None` means the ref
/// must not exist, `Some(sha)` means it must currently be `sha`. `new_sha`
/// `None` deletes the ref. A no-op (`expected_old == new_sha`) writes nothing.
#[derive(Debug, Clone)]
pub struct RefUpdate {
    pub refname: String,
    pub expected_old: Option<String>,
    pub new_sha: Option<String>,
}

impl RefUpdate {
    pub fn set(
        refname: impl Into<String>,
        expected_old: Option<impl Into<String>>,
        new_sha: impl Into<String>,
    ) -> Self {
        Self {
            refname: refname.into(),
            expected_old: expected_old.map(Into::into),
            new_sha: Some(new_sha.into()),
        }
    }

    pub fn delete(refname: impl Into<String>, expected_old: Option<impl Into<String>>) -> Self {
        Self {
            refname: refname.into(),
            expected_old: expected_old.map(Into::into),
            new_sha: None,
        }
    }
}

/// Single-writer coordination: per-slug mutex plus the last applied seq.
#[derive(Clone, Default)]
pub struct GitSync {
    locks: Arc<Mutex<BTreeMap<String, Arc<Mutex<()>>>>>,
    applied: Arc<Mutex<BTreeMap<String, u64>>>,
}

impl GitSync {
    /// Hold across a whole publish (mirror CAS, uploads, manifest flip).
    pub async fn lock(&self, slug: &str) -> tokio::sync::OwnedMutexGuard<()> {
        let lock = {
            let mut locks = self.locks.lock().await;
            locks
                .entry(slug.to_string())
                .or_insert_with(|| Arc::new(Mutex::new(())))
                .clone()
        };
        lock.lock_owned().await
    }

    /// Both slug locks for a slug-changing operation, taken in lexical order
    /// so two renames over the same pair serialize instead of deadlocking.
    pub async fn lock_pair(
        &self,
        old_slug: &str,
        new_slug: &str,
    ) -> (
        tokio::sync::OwnedMutexGuard<()>,
        Option<tokio::sync::OwnedMutexGuard<()>>,
    ) {
        let (first, second) = if new_slug < old_slug {
            (new_slug, old_slug)
        } else {
            (old_slug, new_slug)
        };
        let first_guard = self.lock(first).await;
        if first == second {
            return (first_guard, None);
        }
        (first_guard, Some(self.lock(second).await))
    }

    pub async fn applied_seq(&self, slug: &str) -> Option<u64> {
        self.applied.lock().await.get(slug).copied()
    }

    /// Record an applied manifest seq, only moving forward.
    pub async fn set_applied_seq(&self, slug: &str, seq: u64) {
        let mut applied = self.applied.lock().await;
        if applied.get(slug).is_none_or(|current| seq > *current) {
            applied.insert(slug.to_string(), seq);
        }
    }

    /// Unconditional seq record for a rebuilt mirror.
    pub async fn reset_applied_seq(&self, slug: &str, seq: u64) {
        self.applied.lock().await.insert(slug.to_string(), seq);
    }

    /// Drop a slug's marker (purge). Call under the slug's lock.
    pub async fn forget(&self, slug: &str) {
        self.applied.lock().await.remove(slug);
    }
}

/// A cloneable handle over one store/config/codec.
#[derive(Clone)]
pub struct Wal<C: ManifestCodec> {
    pub(crate) store: DynStore,
    pub(crate) config: Arc<WalConfig>,
    pub(crate) codec: Arc<C>,
    pub(crate) sync: GitSync,
    pub(crate) batch: publish::Batcher,
}

impl<C: ManifestCodec> Wal<C> {
    pub fn new(store: DynStore, config: Arc<WalConfig>, codec: Arc<C>) -> Self {
        Self {
            store,
            config,
            codec,
            sync: GitSync::default(),
            batch: publish::Batcher::default(),
        }
    }

    pub fn with_sync(mut self, sync: GitSync) -> Self {
        self.sync = sync;
        self
    }

    pub fn store(&self) -> &DynStore {
        &self.store
    }

    pub fn config(&self) -> &WalConfig {
        &self.config
    }

    pub fn codec(&self) -> &C {
        &self.codec
    }

    pub fn sync(&self) -> &GitSync {
        &self.sync
    }

    pub fn manifest_key(&self, slug: &str) -> String {
        self.config.layout.manifest_key(slug)
    }

    pub fn mirror_path(&self, slug: &str) -> PathBuf {
        self.config.mirror_path(slug)
    }

    /// The per-slug publish guard. Callers that also hold an app-level lock
    /// take this one last.
    pub async fn lock(&self, slug: &str) -> tokio::sync::OwnedMutexGuard<()> {
        self.sync.lock(slug).await
    }

    /// The manifest with its object version. `Ok(None)` is a missing manifest;
    /// any other store failure is an error, never "no manifest".
    pub async fn load_manifest(
        &self,
        slug: &str,
    ) -> Result<Option<(C::Manifest, Version)>, WalError> {
        let key = self.manifest_key(slug);
        let Some((meta, bytes)) = self.store.get_bytes(&key).await? else {
            return Ok(None);
        };
        let manifest = self
            .codec
            .decode(&bytes)
            .map_err(|error| WalError::Corrupt(format!("manifest {key}: {error}")))?;
        Ok(Some((manifest, meta.version)))
    }

    /// The manifest without its version.
    pub async fn read_manifest(&self, slug: &str) -> Result<Option<C::Manifest>, WalError> {
        Ok(self
            .load_manifest(slug)
            .await?
            .map(|(manifest, _)| manifest))
    }

    /// Conditional manifest write. A lost condition surfaces as
    /// [`StoreError::PreconditionFailed`] inside [`WalError::Store`].
    pub async fn write_manifest(
        &self,
        slug: &str,
        manifest: &C::Manifest,
        mode: PutMode,
    ) -> Result<ObjectMeta, WalError> {
        let key = self.manifest_key(slug);
        let bytes = self
            .codec
            .encode(manifest)
            .map_err(|error| WalError::Corrupt(format!("encode manifest {key}: {error}")))?;
        let options = PutOptions {
            mode,
            content_type: Some("application/json"),
            immutable: false,
        };
        Ok(self.store.put(&key, bytes.into(), options).await?)
    }

    /// The manifest when the local mirror still needs it: `None` when none
    /// exists or the applied sequence already covers it.
    pub async fn pending_manifest(
        &self,
        slug: &str,
    ) -> Result<Option<(C::Manifest, Version)>, WalError> {
        let Some((manifest, version)) = self.load_manifest(slug).await? else {
            return Ok(None);
        };
        if self
            .sync
            .applied_seq(slug)
            .await
            .is_some_and(|applied| applied >= self.codec.seq(&manifest))
        {
            return Ok(None);
        }
        Ok(Some((manifest, version)))
    }

    /// Full manifest state plus its object version.
    pub(crate) async fn load_state(
        &self,
        slug: &str,
    ) -> Result<Option<(ManifestState, Version)>, WalError> {
        Ok(self
            .load_manifest(slug)
            .await?
            .map(|(manifest, version)| (self.codec.state(&manifest), version)))
    }

    /// Write a full manifest state.
    pub(crate) async fn write_state(
        &self,
        slug: &str,
        state: ManifestState,
        mode: PutMode,
    ) -> Result<ObjectMeta, WalError> {
        let manifest = self
            .codec
            .from_state(state)
            .map_err(|error| WalError::Corrupt(format!("build manifest: {error}")))?;
        self.write_manifest(slug, &manifest, mode).await
    }

    /// Whether two states encode identically.
    pub(crate) fn same_state(
        &self,
        a: &ManifestState,
        b: &ManifestState,
    ) -> Result<bool, WalError> {
        let left = self
            .codec
            .from_state(a.clone())
            .map_err(|error| WalError::Corrupt(format!("compare manifest state: {error}")))?;
        let right = self
            .codec
            .from_state(b.clone())
            .map_err(|error| WalError::Corrupt(format!("compare manifest state: {error}")))?;
        Ok(self.codec.encode(&left)? == self.codec.encode(&right)?)
    }

    /// Exponential backoff with full jitter, bounded by the configured cap.
    /// A zero base or cap disables the sleep (tests use zero).
    pub(crate) async fn backoff(&self, attempt: u32) {
        let delay = retry_delay(&self.config, attempt);
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
    }

    /// Create the empty mirror and the empty manifest (seq 0) with `Create`.
    pub async fn init_repo(&self, slug: &str) -> Result<(), WalError> {
        git::validate_slug(slug)?;
        let _guard = self.lock(slug).await;
        if self.load_manifest(slug).await?.is_some() {
            return Err(WalError::AlreadyExists(slug.to_string()));
        }
        let bare = self.mirror_path(slug);
        if !bare.join("HEAD").exists() {
            if bare.exists() {
                tokio::fs::remove_dir_all(&bare).await?;
            }
            git::init_bare(&self.config, &bare).await?;
        }
        let manifest = self
            .codec
            .build(0, Vec::new())
            .map_err(|error| WalError::Corrupt(format!("build empty manifest: {error}")))?;
        match self.write_manifest(slug, &manifest, PutMode::Create).await {
            Ok(_) => {
                self.sync.reset_applied_seq(slug, 0).await;
                Ok(())
            }
            Err(WalError::Store(error)) if error.is_precondition_failed() => {
                Err(WalError::AlreadyExists(slug.to_string()))
            }
            Err(error) => Err(error),
        }
    }

    /// Entries with `from < seq <= to`, read from the immutable segments the
    /// manifest names, in sequence order. `None` means every entry after
    /// `from`.
    pub async fn read_log(
        &self,
        slug: &str,
        from: u64,
        to: Option<u64>,
    ) -> Result<Vec<LogEntry>, WalError> {
        let to = to.unwrap_or(u64::MAX);
        if to <= from {
            return Ok(Vec::new());
        }
        let Some((state, _)) = self.load_state(slug).await? else {
            return Ok(Vec::new());
        };
        log::read_range(&self.store, &state.log, from, to).await
    }

    /// The tip of `refname` in the local mirror (syncing first).
    pub async fn head_of(&self, slug: &str, refname: &str) -> Result<Option<String>, WalError> {
        let bare = self.ensure_synced(slug).await?;
        Ok(git::head_of_ref(&bare, refname).await?)
    }

    /// Whether `old` is an ancestor of `new` (both must be present locally).
    pub async fn is_fast_forward(
        &self,
        slug: &str,
        old: &str,
        new: &str,
    ) -> Result<bool, WalError> {
        if old == new {
            return Ok(true);
        }
        let bare = self.ensure_synced(slug).await?;
        Ok(git::is_ancestor(&bare, old, new).await)
    }

    /// Delete the mirror and the repository prefix, and forget the applied seq.
    pub async fn purge(&self, slug: &str) -> Result<(), WalError> {
        git::validate_slug(slug)?;
        let _guard = self.lock(slug).await;
        let bare = self.mirror_path(slug);
        match tokio::fs::remove_dir_all(&bare).await {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let prefix = self.config.layout.repo_prefix(slug);
        for key in self.list_keys(&prefix).await? {
            self.store.delete(&key, None).await?;
        }
        self.sync.forget(slug).await;
        Ok(())
    }

    /// Every key under `prefix`, in lexical order.
    pub(crate) async fn list_keys(&self, prefix: &str) -> Result<Vec<String>, WalError> {
        use futures::TryStreamExt as _;
        let keys: Vec<String> = self
            .store
            .list(prefix, None)
            .map_ok(|meta: ObjectMeta| meta.key)
            .try_collect()
            .await?;
        Ok(keys)
    }

    /// The repository policy. A missing policy object is allow-all; a store
    /// failure is an error, never allow-all.
    pub async fn read_policy(&self, slug: &str) -> Result<crate::policy::Policy, WalError> {
        let key = self.config.layout.policy_key(slug);
        let bytes = self.store.get_bytes(&key).await?;
        let policy = match bytes {
            Some((_, bytes)) => crate::policy::Policy::parse(&bytes),
            None => Ok(crate::policy::Policy::default()),
        };
        policy.map_err(|error| WalError::Other(anyhow::anyhow!("policy {key}: {error}")))
    }

    /// Replace the repository policy (validated before the write).
    pub async fn write_policy(
        &self,
        slug: &str,
        policy: &crate::policy::Policy,
    ) -> Result<(), WalError> {
        let key = self.config.layout.policy_key(slug);
        let bytes = policy
            .to_json()
            .map_err(|error| WalError::Other(anyhow::anyhow!("policy {key}: {error}")))?;
        self.store
            .put(
                &key,
                bytes.into(),
                PutOptions {
                    mode: PutMode::Overwrite,
                    content_type: Some("application/json"),
                    immutable: false,
                },
            )
            .await?;
        Ok(())
    }

    /// Store the repository settings and append a `SETTINGS` log entry in one
    /// manifest CAS.
    /// Fold the log up to the current sequence into a checkpoint.
    pub async fn checkpoint(
        &self,
        slug: &str,
    ) -> Result<Option<crate::manifest::CheckpointRef>, WalError> {
        checkpoint::write_checkpoint(self, slug).await
    }

    /// Repack reachable objects into one live pack.
    pub async fn compact(
        &self,
        slug: &str,
        opts: maintenance::CompactOptions,
    ) -> Result<Option<crate::manifest::PackRef>, WalError> {
        maintenance::compact(self, slug, opts).await
    }

    /// Verify every live object is present and reachable.
    pub async fn fsck(&self, slug: &str) -> Result<maintenance::FsckReport, WalError> {
        maintenance::fsck(self, slug).await
    }

    /// Acquire the repository maintenance lease.
    pub async fn lease(
        &self,
        slug: &str,
        request: lease::LeaseRequest,
    ) -> Result<Option<lease::LeaseGuard>, WalError> {
        lease::acquire(self, slug, &request)
            .await
            .map_err(|error| WalError::Other(anyhow::anyhow!("lease: {error}")))
    }
}

/// A temp path unique to this call, with the slug flattened so namespaced
/// slugs (`owner/name`) never create directories under the temp root.
pub(crate) fn tmp_for(prefix: &str, slug: &str, suffix: &str) -> PathBuf {
    let slug: String = slug
        .chars()
        .map(|c| if c == '/' || c == '\\' { '-' } else { c })
        .collect();
    crate::config::tmp_path(&format!("{prefix}-{slug}-{suffix}"))
}

/// Upload a local file under `key`.
pub(crate) async fn put_file(
    store: &DynStore,
    key: &str,
    path: &Path,
    mode: PutMode,
) -> Result<ObjectMeta, WalError> {
    let options = PutOptions {
        mode,
        content_type: None,
        immutable: true,
    };
    let body = PutBody::File(path.to_path_buf());
    Ok(store.put(key, body, options).await?)
}

/// Download `key` to `dest` atomically. `Ok(false)` means the object is absent.
pub(crate) async fn get_to_file(
    store: &DynStore,
    key: &str,
    dest: &Path,
) -> Result<bool, WalError> {
    match store.get(key, GetOptions::default()).await {
        Ok(GetResult::Object { body, .. }) => {
            crate::store::write_stream_atomic(body, dest).await?;
            Ok(true)
        }
        Ok(GetResult::NotModified { .. }) => Ok(false),
        Err(StoreError::NotFound { .. }) => Ok(false),
        Err(error) => Err(error.into()),
    }
}

/// Restore every ref that differs between `current` and `previous` (the mirror
/// cache is best-effort: a ref that cannot be restored is rebuilt later).
pub(crate) async fn restore_refs(
    bare: &Path,
    previous: &BTreeMap<String, String>,
    current: &BTreeMap<String, String>,
) {
    let mut names: Vec<String> = previous.keys().cloned().collect();
    names.extend(current.keys().cloned());
    names.sort();
    names.dedup();
    for refname in names {
        let wanted = previous.get(&refname).map(String::as_str);
        if current.get(&refname).map(String::as_str) == wanted {
            continue;
        }
        let _ = git::set_ref(bare, &refname, wanted).await;
    }
}

/// Exponential backoff with full jitter, bounded by `publish_retry_max`.
pub(crate) fn retry_delay(config: &WalConfig, attempt: u32) -> Duration {
    let base = config.publish_retry_base;
    if base.is_zero() {
        return Duration::ZERO;
    }
    let cap = config
        .publish_retry_max
        .max(base)
        .min(base.saturating_mul(1u32 << attempt.min(10)));
    let millis = cap.as_millis().max(1) as u64;
    let jitter = rand::random::<u64>() % millis.max(1);
    Duration::from_millis(jitter)
}
