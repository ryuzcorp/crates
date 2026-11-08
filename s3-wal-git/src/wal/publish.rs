//! Publish: coalesce concurrent requests, CAS the mirror refs, cut immutable
//! objects, append one log segment, then flip the manifest.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::Path;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use tokio::sync::{oneshot, Mutex};

use crate::config::StorageMode;
use crate::error::{StoreError, WalError};
use crate::git::{self, IngestedPack, RefSnapshot};
use crate::manifest::{
    LogSegmentRef, ManifestCodec, ManifestRef, ManifestState, PackKind, PackRef, RepoSetting,
    RetiredPack,
};
use crate::store::{PutMode, Version};
use crate::wal::log::{self, LogEntry, LogKind, LogPack, LogTxn};
use crate::wal::{now_rfc3339, put_file, restore_refs, tmp_for, writer_name};

use super::{PublishedRef, RecordOutcome, RefUpdate, Wal};

/// A publish outcome copied across the group-commit channel.
///
/// [`WalError`] is not `Clone`, so a batch leader that fails wholesale keeps the
/// typed data and rebuilds one error per waiter.
#[derive(Debug, Clone)]
pub enum BatchFailure {
    NotFound(String),
    AlreadyExists(String),
    RefConflict {
        name: String,
        expected: Option<String>,
        actual: Option<String>,
    },
    Corrupt(String),
    UnsupportedVersion(u8),
    RetryExhausted {
        slug: String,
        attempts: u32,
    },
    Ambiguous(String),
    Store(String),
    Git(String),
    Io {
        kind: std::io::ErrorKind,
        message: String,
    },
    Json(String),
    Other(String),
}

impl BatchFailure {
    pub fn from_error(error: &WalError) -> Self {
        match error {
            WalError::NotFound(message) => Self::NotFound(message.clone()),
            WalError::AlreadyExists(message) => Self::AlreadyExists(message.clone()),
            WalError::RefConflict {
                name,
                expected,
                actual,
            } => Self::RefConflict {
                name: name.clone(),
                expected: expected.clone(),
                actual: actual.clone(),
            },
            WalError::Corrupt(message) => Self::Corrupt(message.clone()),
            WalError::UnsupportedVersion(version) => Self::UnsupportedVersion(*version),
            WalError::RetryExhausted { slug, attempts } => Self::RetryExhausted {
                slug: slug.clone(),
                attempts: *attempts,
            },
            WalError::Ambiguous(message) => Self::Ambiguous(message.clone()),
            WalError::Store(error) => Self::Store(error.to_string()),
            WalError::Git(error) => Self::Git(error.to_string()),
            WalError::Io(error) => Self::Io {
                kind: error.kind(),
                message: error.to_string(),
            },
            WalError::Json(error) => Self::Json(error.to_string()),
            WalError::Other(error) => Self::Other(format!("{error:#}")),
        }
    }

    pub fn into_error(self) -> WalError {
        match self {
            Self::NotFound(message) => WalError::NotFound(message),
            Self::AlreadyExists(message) => WalError::AlreadyExists(message),
            Self::RefConflict {
                name,
                expected,
                actual,
            } => WalError::RefConflict {
                name,
                expected,
                actual,
            },
            Self::Corrupt(message) => WalError::Corrupt(message),
            Self::UnsupportedVersion(version) => WalError::UnsupportedVersion(version),
            Self::RetryExhausted { slug, attempts } => WalError::RetryExhausted { slug, attempts },
            Self::Ambiguous(message) => WalError::Ambiguous(message),
            Self::Store(message) => WalError::Store(StoreError::Other(anyhow::anyhow!(message))),
            Self::Git(message) => {
                WalError::Git(crate::error::GitError::Other(anyhow::anyhow!(message)))
            }
            Self::Io { kind, message } => WalError::Io(std::io::Error::new(kind, message)),
            Self::Json(message) => WalError::Other(anyhow::anyhow!("json: {message}")),
            Self::Other(message) => WalError::Other(anyhow::anyhow!(message)),
        }
    }
}

/// Per-slug single-flight publisher. Concurrent [`Wal::publish`] calls queue
/// their requests; the first caller that acquires the flush lock drains up to
/// `max_batch` requests after `batch_window` and commits them with one CAS.
#[derive(Clone, Default)]
pub(crate) struct Batcher {
    cells: Arc<Mutex<BTreeMap<String, Arc<BatchCell>>>>,
}

struct BatchCell {
    flush: Mutex<()>,
    queue: StdMutex<VecDeque<BatchRequest>>,
}

struct BatchRequest {
    updates: Vec<RefUpdate>,
    reply: oneshot::Sender<Result<RecordOutcome, BatchFailure>>,
}

fn queue(cell: &BatchCell) -> std::sync::MutexGuard<'_, VecDeque<BatchRequest>> {
    cell.queue.lock().unwrap_or_else(|error| error.into_inner())
}

impl Batcher {
    async fn cell(&self, slug: &str) -> Arc<BatchCell> {
        let mut cells = self.cells.lock().await;
        cells
            .entry(slug.to_string())
            .or_insert_with(|| {
                Arc::new(BatchCell {
                    flush: Mutex::new(()),
                    queue: StdMutex::new(VecDeque::new()),
                })
            })
            .clone()
    }
}

impl<C: ManifestCodec> Wal<C> {
    /// Apply ref updates and publish them in one manifest CAS.
    ///
    /// Concurrent calls for the same slug are coalesced into one batch (one
    /// manifest write) when they arrive within `batch_window`.
    pub async fn publish(
        &self,
        slug: &str,
        updates: &[RefUpdate],
    ) -> Result<RecordOutcome, WalError> {
        git::validate_slug(slug)?;
        let cell = self.batch.cell(slug).await;
        let (reply, mut wait) = oneshot::channel();
        queue(&cell).push_back(BatchRequest {
            updates: updates.to_vec(),
            reply,
        });
        tokio::select! {
            biased;
            result = &mut wait => {
                result
                    .map_err(|_| WalError::Other(anyhow::anyhow!("publish batch was cancelled")))?
                    .map_err(BatchFailure::into_error)
            }
            guard = cell.flush.lock() => {
                self.flush_batches(slug, &cell).await;
                drop(guard);
                wait.await
                    .map_err(|_| WalError::Other(anyhow::anyhow!("publish batch was cancelled")))?
                    .map_err(BatchFailure::into_error)
            }
        }
    }

    /// [`Self::publish`] for a caller already holding the slug lock.
    pub async fn publish_locked(
        &self,
        slug: &str,
        updates: &[RefUpdate],
    ) -> Result<RecordOutcome, WalError> {
        let mut results = self
            .publish_batch_locked(slug, vec![updates.to_vec()])
            .await;
        results.pop().unwrap_or_else(|| {
            Err(WalError::Other(anyhow::anyhow!(
                "publish produced no outcome"
            )))
        })
    }

    /// Drain queued requests until the queue is empty, one manifest CAS per
    /// batch.
    async fn flush_batches(&self, slug: &str, cell: &BatchCell) {
        let window = self.config.batch_window;
        if !window.is_zero() {
            tokio::time::sleep(window).await;
        }
        let max_batch = self.config.max_batch.max(1);
        loop {
            let batch: Vec<BatchRequest> = {
                let mut queue = queue(cell);
                let take = queue.len().min(max_batch);
                queue.drain(..take).collect()
            };
            if batch.is_empty() {
                break;
            }
            let full = batch.len() >= max_batch;
            let requests: Vec<Vec<RefUpdate>> = batch
                .iter()
                .map(|request| request.updates.clone())
                .collect();
            let results = {
                let _guard = self.sync.lock(slug).await;
                self.publish_batch_locked(slug, requests).await
            };
            for (request, result) in batch.into_iter().zip(results) {
                let result = result.map_err(|error| BatchFailure::from_error(&error));
                let _ = request.reply.send(result);
            }
            if !full {
                break;
            }
        }
    }

    /// Commit a whole batch under the slug lock.
    ///
    /// Each request's expected OIDs are validated against the batch's base
    /// manifest (and against earlier requests in the same batch, so chained
    /// updates share one flip). A conflict fails only its own request.
    async fn publish_batch_locked(
        &self,
        slug: &str,
        requests: Vec<Vec<RefUpdate>>,
    ) -> Vec<Result<RecordOutcome, WalError>> {
        let mut results: Vec<Option<Result<RecordOutcome, WalError>>> =
            (0..requests.len()).map(|_| None).collect();
        let mut pending: Vec<usize> = Vec::new();
        for (index, updates) in requests.iter().enumerate() {
            match self.validate_updates(updates) {
                Ok(()) => pending.push(index),
                Err(error) => results[index] = Some(Err(error)),
            }
        }
        let mut attempts = 0u32;
        while !pending.is_empty() {
            if let Err(error) = self.ensure_repo_locked(slug).await {
                fail_all(&mut results, &pending, &error);
                pending.clear();
                break;
            }
            let prepared = async {
                let bare = self.ensure_synced_locked(slug).await?;
                let state = self.load_state(slug).await?;
                Ok::<_, WalError>((bare, state))
            }
            .await;
            let (bare, loaded) = match prepared {
                Ok(value) => value,
                Err(error) => {
                    fail_all(&mut results, &pending, &error);
                    pending.clear();
                    break;
                }
            };
            let (base_state, version) = match loaded {
                Some((state, version)) => (state, Some(version)),
                None => (ManifestState::default(), None),
            };
            let before = match self.snapshot(&bare).await {
                Ok(snapshot) => snapshot.refs,
                Err(error) => {
                    fail_all(&mut results, &pending, &error);
                    pending.clear();
                    break;
                }
            };
            // A stale cache must never leak refs into the new manifest.
            let manifest_refs: BTreeMap<String, String> = base_state
                .refs
                .iter()
                .map(|(name, entry)| (name.clone(), entry.sha.clone()))
                .collect();
            let before = if before != manifest_refs {
                match self.rehydrate_locked(slug).await {
                    Ok(refs) => refs,
                    Err(error) => {
                        fail_all(&mut results, &pending, &error);
                        pending.clear();
                        break;
                    }
                }
            } else {
                before
            };

            let mut working = before.clone();
            let mut plans: Vec<(usize, Plan)> = Vec::new();
            for &index in &pending {
                match plan_request(&working, &requests[index]) {
                    Ok(plan) => {
                        working = plan.after.clone();
                        plans.push((index, plan));
                    }
                    Err(error) => results[index] = Some(Err(error)),
                }
            }
            pending = plans.iter().map(|(index, _)| *index).collect();
            if plans.is_empty() {
                break;
            }
            if working == before {
                let seq = base_state.seq;
                for &index in &pending {
                    results[index] = Some(Ok(RecordOutcome {
                        seq,
                        ..RecordOutcome::default()
                    }));
                }
                pending.clear();
                break;
            }

            // Move the mirror first: bundles and packs are cut from it. One
            // transaction covers every request, so chained expected values are
            // applied in order.
            let updates = diff_updates(&before, &working);
            if let Err(error) = git::apply_ref_transaction(&bare, &updates).await {
                restore_refs(&bare, &before, &working).await;
                let error: WalError = error.into();
                fail_all(&mut results, &pending, &error);
                pending.clear();
                break;
            }
            let after = match self.snapshot(&bare).await {
                Ok(snapshot) => snapshot,
                Err(error) => {
                    restore_refs(&bare, &before, &working).await;
                    fail_all(&mut results, &pending, &error);
                    pending.clear();
                    break;
                }
            };

            match self
                .commit_batch(
                    slug,
                    &bare,
                    &base_state,
                    version,
                    &before,
                    &after,
                    &plans,
                    None,
                )
                .await
            {
                Ok(outcomes) => {
                    for (index, outcome) in outcomes {
                        results[index] = Some(Ok(outcome));
                    }
                    pending.clear();
                    break;
                }
                Err(failure) => match failure.kind {
                    FailureKind::Precondition => {
                        restore_refs(&bare, &before, &after.refs).await;
                        self.cleanup_orphans(slug, &failure.objects).await;
                        attempts += 1;
                        if attempts >= self.config.publish_retries.max(1) {
                            let error = WalError::RetryExhausted {
                                slug: slug.to_string(),
                                attempts,
                            };
                            fail_all(&mut results, &pending, &error);
                            pending.clear();
                            break;
                        }
                        self.backoff(attempts).await;
                    }
                    FailureKind::Failed(error) => {
                        if let Some(commit) = failure.commit.as_deref() {
                            if self.adopt_if_landed(slug, commit).await {
                                self.sync.set_applied_seq(slug, commit.state.seq).await;
                                self.prune(slug, &commit.state, &base_state).await;
                                for (index, outcome) in &commit.outcomes {
                                    results[*index] = Some(Ok(outcome.clone()));
                                }
                                pending.clear();
                                break;
                            }
                        }
                        restore_refs(&bare, &before, &after.refs).await;
                        self.cleanup_orphans(slug, &failure.objects).await;
                        fail_all(&mut results, &pending, &error);
                        pending.clear();
                        break;
                    }
                },
            }
        }
        results
            .into_iter()
            .map(|result| {
                result.unwrap_or_else(|| {
                    Err(WalError::Other(anyhow::anyhow!(
                        "publish produced no outcome"
                    )))
                })
            })
            .collect()
    }

    /// Persist a push git already accepted. `before` is the snapshot taken
    /// before receive-pack ran; `pack` is the incoming pack in pack mode.
    pub async fn record_push(
        &self,
        slug: &str,
        before: &RefSnapshot,
        pack: Option<IngestedPack>,
    ) -> Result<RecordOutcome, WalError> {
        let _guard = self.lock(slug).await;
        self.record_push_locked(slug, before, pack).await
    }

    /// [`Self::record_push`] for a caller holding the slug lock (the HTTP
    /// server holds it across `git receive-pack`).
    pub async fn record_push_locked(
        &self,
        slug: &str,
        before: &RefSnapshot,
        pack: Option<IngestedPack>,
    ) -> Result<RecordOutcome, WalError> {
        git::validate_slug(slug)?;
        let bare = self.mirror_path(slug);
        if !bare.join("HEAD").exists() {
            return Err(WalError::Corrupt(format!(
                "receive-pack ran without a synced mirror for {slug}"
            )));
        }
        let accepted = self.snapshot(&bare).await?;
        let txns = log::classify_txns(&before.refs, &accepted.refs);
        self.ensure_repo_locked(slug).await?;
        if txns.is_empty() && pack.is_none() {
            let seq = self
                .read_manifest(slug)
                .await?
                .map_or(0, |manifest| self.codec.seq(&manifest));
            return Ok(RecordOutcome {
                seq,
                ..RecordOutcome::default()
            });
        }
        let moved = moved_refs(&before.refs, &accepted.refs);
        let deleted = deleted_refs(&before.refs, &accepted.refs);
        let mut attempts = 0u32;
        loop {
            let (base_state, version) = match self.load_state(slug).await? {
                Some((state, version)) => (state, Some(version)),
                None => (ManifestState::default(), None),
            };
            if let Some(conflict) = revalidate(&base_state, &txns) {
                // Another writer moved a ref this push touches. Rebuild the
                // mirror from the manifest and refuse: the push is not lost
                // silently, the client sees the conflict.
                let _ = self.rehydrate_locked(slug).await;
                return Err(conflict);
            }
            let base_refs: BTreeMap<String, String> = base_state
                .refs
                .iter()
                .map(|(name, entry)| (name.clone(), entry.sha.clone()))
                .collect();
            let mut target = base_refs.clone();
            for txn in &txns {
                match &txn.new {
                    Some(new) => {
                        target.insert(txn.refname.clone(), new.clone());
                    }
                    None => {
                        target.remove(&txn.refname);
                    }
                }
            }
            let current = self.snapshot(&bare).await?;
            if current.refs != target {
                let updates = diff_updates(&current.refs, &target);
                if let Err(error) = git::apply_ref_transaction(&bare, &updates).await {
                    restore_refs(&bare, &base_refs, &current.refs).await;
                    return Err(error.into());
                }
            }
            let after = self.snapshot(&bare).await?;
            let plan = Plan {
                after: target,
                txns: txns.clone(),
                moved: moved.clone(),
                deleted: deleted.clone(),
            };
            match self
                .commit_batch(
                    slug,
                    &bare,
                    &base_state,
                    version,
                    &base_refs,
                    &after,
                    &[(0, plan)],
                    pack.as_ref(),
                )
                .await
            {
                Ok(mut outcomes) => {
                    return Ok(outcomes
                        .pop()
                        .map(|(_, outcome)| outcome)
                        .unwrap_or_else(|| RecordOutcome {
                            seq: base_state.seq,
                            ..RecordOutcome::default()
                        }));
                }
                Err(failure) => match failure.kind {
                    FailureKind::Precondition => {
                        restore_refs(&bare, &base_refs, &after.refs).await;
                        self.cleanup_orphans(slug, &failure.objects).await;
                        attempts += 1;
                        if attempts >= self.config.publish_retries.max(1) {
                            let _ = self.rehydrate_locked(slug).await;
                            return Err(WalError::RetryExhausted {
                                slug: slug.to_string(),
                                attempts,
                            });
                        }
                        self.backoff(attempts).await;
                        // Pull in the winner's manifest without dropping the
                        // objects receive-pack just indexed into this mirror.
                        self.ensure_synced_locked(slug).await?;
                    }
                    FailureKind::Failed(error) => {
                        if let Some(commit) = failure.commit.as_deref() {
                            if self.adopt_if_landed(slug, commit).await {
                                self.sync.set_applied_seq(slug, commit.state.seq).await;
                                self.prune(slug, &commit.state, &base_state).await;
                                return Ok(commit
                                    .outcomes
                                    .iter()
                                    .find(|(index, _)| *index == 0)
                                    .map(|(_, outcome)| outcome.clone())
                                    .unwrap_or_else(|| RecordOutcome {
                                        seq: commit.state.seq,
                                        ..RecordOutcome::default()
                                    }));
                            }
                        }
                        restore_refs(&bare, &base_refs, &after.refs).await;
                        self.cleanup_orphans(slug, &failure.objects).await;
                        return Err(error);
                    }
                },
            }
        }
    }

    /// Publish per-repository settings as one CAS bump.
    pub async fn publish_settings(
        &self,
        slug: &str,
        setting: RepoSetting,
    ) -> Result<RecordOutcome, WalError> {
        git::validate_slug(slug)?;
        let _guard = self.lock(slug).await;
        let mut attempts = 0u32;
        loop {
            self.ensure_repo_locked(slug).await?;
            let (base, version) = match self.load_state(slug).await? {
                Some((state, version)) => (state, Some(version)),
                None => (ManifestState::default(), None),
            };
            let first_seq = base.seq + 1;
            let entry = LogEntry {
                seq: 0,
                kind: LogKind::Settings,
                txns: Vec::new(),
                pack: None,
                supersedes: Vec::new(),
                checkpoint: None,
                created_at: now_rfc3339(),
                writer: Some(writer_name()),
                meta: BTreeMap::new(),
            };
            let (segment, entries) = self.write_log_segment(slug, first_seq, vec![entry]).await?;
            let now = now_rfc3339();
            let mut state = base.clone();
            state.seq = segment.last_seq;
            state.revision = base.revision + 1;
            state.writer = Some(writer_name());
            state.updated_at = Some(now.clone());
            state.settings = Some(RepoSetting {
                revision: base.settings.as_ref().map_or(1, |old| old.revision + 1),
                updated_at: now,
                ..setting.clone()
            });
            state.log.push(segment.clone());
            let mode = match version {
                Some(version) => PutMode::Update(version),
                None => PutMode::Create,
            };
            match self.write_state(slug, state.clone(), mode).await {
                Ok(_) => {
                    self.sync.set_applied_seq(slug, segment.last_seq).await;
                    return Ok(RecordOutcome {
                        seq: entries[0].seq,
                        ..RecordOutcome::default()
                    });
                }
                Err(WalError::Store(error)) if error.is_precondition_failed() => {
                    self.cleanup_orphans(slug, std::slice::from_ref(&segment.key))
                        .await;
                    attempts += 1;
                    if attempts >= self.config.publish_retries.max(1) {
                        return Err(WalError::RetryExhausted {
                            slug: slug.to_string(),
                            attempts,
                        });
                    }
                    self.backoff(attempts).await;
                }
                Err(error) => {
                    if let Ok(Some((current, _))) = self.load_state(slug).await {
                        if self.same_state(&current, &state).unwrap_or(false) {
                            self.sync.set_applied_seq(slug, segment.last_seq).await;
                            return Ok(RecordOutcome {
                                seq: entries[0].seq,
                                ..RecordOutcome::default()
                            });
                        }
                    }
                    self.cleanup_orphans(slug, std::slice::from_ref(&segment.key))
                        .await;
                    return Err(error);
                }
            }
        }
    }

    fn validate_updates(&self, updates: &[RefUpdate]) -> Result<(), WalError> {
        for update in updates {
            git::validate_refname(&update.refname)?;
            for sha in [update.expected_old.as_deref(), update.new_sha.as_deref()]
                .into_iter()
                .flatten()
            {
                if !git::is_full_sha(sha, self.config.object_format) {
                    return Err(WalError::Other(anyhow::anyhow!(
                        "{} needs a full {} object id, got {sha:?}",
                        update.refname,
                        self.config.object_format
                    )));
                }
            }
        }
        Ok(())
    }

    /// Create the mirror and the empty manifest when missing.
    async fn ensure_repo_locked(&self, slug: &str) -> Result<(), WalError> {
        let bare = self.mirror_path(slug);
        if !bare.join("HEAD").exists() {
            if bare.exists() {
                tokio::fs::remove_dir_all(&bare).await?;
            }
            git::init_bare(&self.config, &bare).await?;
        }
        if self.load_manifest(slug).await?.is_none() {
            let manifest = self
                .codec
                .from_state(ManifestState::default())
                .map_err(|error| WalError::Corrupt(format!("build empty manifest: {error}")))?;
            match self.write_manifest(slug, &manifest, PutMode::Create).await {
                Ok(_) => self.sync.reset_applied_seq(slug, 0).await,
                Err(WalError::Store(error)) if error.is_precondition_failed() => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    async fn snapshot(&self, bare: &Path) -> Result<RefSnapshot, WalError> {
        let mut snapshot = git::snapshot_refs(bare, &self.config.extra_ref_prefixes).await?;
        snapshot.refs = self.config.filter_refs(snapshot.refs);
        Ok(snapshot)
    }

    /// Cut bundles, packs, the log segment and the manifest for one batch.
    #[allow(clippy::too_many_arguments)]
    async fn commit_batch(
        &self,
        slug: &str,
        bare: &Path,
        base_state: &ManifestState,
        version: Option<Version>,
        before: &BTreeMap<String, String>,
        after: &RefSnapshot,
        plans: &[(usize, Plan)],
        incoming: Option<&IngestedPack>,
    ) -> Result<Vec<(usize, RecordOutcome)>, CommitFailure> {
        let mut objects: Vec<String> = Vec::new();
        let changed = diff_updates(before, &after.refs);
        let mut bundle_map: BTreeMap<String, String> = BTreeMap::new();
        let mut packs = base_state.packs.clone();
        let mut retired = base_state.retired_packs.clone();
        let mut pack_log: Option<LogPack> = None;
        let mut pack_checksum: Option<String> = None;

        match self.config.storage {
            StorageMode::Bundle => {
                for update in &changed {
                    let Some(new) = &update.new_sha else {
                        continue;
                    };
                    match self.ensure_bundle(slug, bare, &update.refname, new).await {
                        Ok((key, created)) => {
                            if created {
                                objects.push(key.clone());
                            }
                            bundle_map.insert(update.refname.clone(), key);
                        }
                        Err(error) => return Err(CommitFailure::failed(error, objects)),
                    }
                }
            }
            StorageMode::Pack => match incoming {
                Some(pack) => {
                    let pack_ref = pack_ref(pack, base_state.seq + 1);
                    if let Err(error) = self.upload_ingested_pack(slug, pack, &mut objects).await {
                        return Err(CommitFailure::failed(error, objects));
                    }
                    if !packs.iter().any(|live| live.checksum == pack_ref.checksum) {
                        packs.push(pack_ref.clone());
                    }
                    pack_checksum = Some(pack_ref.checksum.clone());
                    pack_log = Some(log_pack(&pack_ref));
                }
                None => match self
                    .cut_full_pack(slug, bare, base_state.seq + 1, &mut objects)
                    .await
                {
                    Ok(pack_ref) => {
                        for old in &base_state.packs {
                            retired.push(RetiredPack {
                                checksum: old.checksum.clone(),
                                retired_at: now_rfc3339(),
                                retired_seq: base_state.seq + 1,
                            });
                        }
                        packs = vec![pack_ref.clone()];
                        pack_checksum = Some(pack_ref.checksum.clone());
                        pack_log = Some(log_pack(&pack_ref));
                    }
                    Err(error) => return Err(CommitFailure::failed(error, objects)),
                },
            },
        }

        let first_seq = base_state.seq + 1;
        let mut templates = Vec::new();
        for (_, plan) in plans {
            if plan.txns.is_empty() {
                continue;
            }
            templates.push(LogEntry {
                seq: 0,
                kind: LogKind::Push,
                txns: plan.txns.clone(),
                pack: pack_log.clone(),
                supersedes: supersedes(
                    plan,
                    base_state,
                    &self.config.layout,
                    slug,
                    self.config.storage,
                    incoming.is_some(),
                ),
                checkpoint: None,
                created_at: now_rfc3339(),
                writer: Some(writer_name()),
                meta: BTreeMap::new(),
            });
        }
        let (segment, entries) = match self.write_log_segment(slug, first_seq, templates).await {
            Ok(value) => value,
            Err(error) => return Err(CommitFailure::failed(error, objects)),
        };
        objects.push(segment.key.clone());
        if let Some(checksum) = &pack_checksum {
            if let Some(pack) = packs.iter_mut().find(|pack| &pack.checksum == checksum) {
                pack.seq = segment.first_seq;
            }
        }

        let mut refs = base_state.refs.clone();
        for update in &changed {
            match &update.new_sha {
                Some(new) => {
                    refs.insert(
                        update.refname.clone(),
                        ManifestRef {
                            sha: new.clone(),
                            bundle: bundle_map.get(&update.refname).cloned(),
                        },
                    );
                }
                None => {
                    refs.remove(&update.refname);
                }
            }
        }
        let mut peeled = base_state.peeled.clone();
        peeled.extend(after.peeled.clone());
        let mut segments = base_state.log.clone();
        segments.push(segment.clone());
        let state = ManifestState {
            seq: segment.last_seq,
            revision: base_state.revision + 1,
            writer: Some(writer_name()),
            refs,
            head: after.head.clone().or_else(|| base_state.head.clone()),
            peeled,
            packs,
            retired_packs: retired,
            log: segments,
            checkpoint: base_state.checkpoint.clone(),
            settings: base_state.settings.clone(),
            updated_at: Some(now_rfc3339()),
        };

        let mut plan_seq: BTreeMap<usize, u64> = BTreeMap::new();
        let mut entry_index = 0;
        for (index, plan) in plans {
            if plan.txns.is_empty() {
                continue;
            }
            if let Some(entry) = entries.get(entry_index) {
                plan_seq.insert(*index, entry.seq);
            }
            entry_index += 1;
        }
        let mut outcomes = Vec::new();
        for (index, plan) in plans {
            let moved = plan
                .moved
                .iter()
                .map(|(refname, sha)| PublishedRef {
                    refname: refname.clone(),
                    sha: sha.clone(),
                    bundle: bundle_map.get(refname).cloned(),
                    pack: pack_checksum.clone(),
                })
                .collect();
            outcomes.push((
                *index,
                RecordOutcome {
                    moved,
                    deleted: plan.deleted.clone(),
                    seq: plan_seq.get(index).copied().unwrap_or(segment.last_seq),
                },
            ));
        }
        let commit = BatchCommit {
            state: state.clone(),
            outcomes: outcomes.clone(),
        };
        let mode = match version {
            Some(version) => PutMode::Update(version),
            None => PutMode::Create,
        };
        match self.write_state(slug, state.clone(), mode).await {
            Ok(_) => {
                self.sync.set_applied_seq(slug, state.seq).await;
                self.prune(slug, &state, base_state).await;
                Ok(outcomes)
            }
            Err(WalError::Store(error)) if error.is_precondition_failed() => {
                Err(CommitFailure::precondition(objects, commit))
            }
            Err(error) => Err(CommitFailure::failed_with(error, objects, commit)),
        }
    }

    /// Write one segment, burning whole ranges until a free key is found.
    async fn write_log_segment(
        &self,
        slug: &str,
        base_seq: u64,
        templates: Vec<LogEntry>,
    ) -> Result<(LogSegmentRef, Vec<LogEntry>), WalError> {
        if templates.is_empty() {
            return Err(WalError::Corrupt(
                "refusing to append an empty log segment".into(),
            ));
        }
        let width = templates.len() as u64;
        let mut seq = base_seq;
        for _ in 0..1024 {
            let entries: Vec<LogEntry> = templates
                .iter()
                .enumerate()
                .map(|(offset, template)| {
                    let mut entry = template.clone();
                    entry.seq = seq + offset as u64;
                    entry
                })
                .collect();
            let key = self.config.layout.log_key(slug, seq);
            match log::write_segment(&self.store, &key, &entries).await {
                Ok(segment) => return Ok((segment, entries)),
                Err(WalError::Store(error)) if error.is_precondition_failed() => {
                    // A crashed or losing writer owns this slot: burn it.
                    seq += width;
                }
                Err(error) => return Err(error),
            }
        }
        Err(WalError::RetryExhausted {
            slug: slug.to_string(),
            attempts: 1024,
        })
    }

    async fn ensure_bundle(
        &self,
        slug: &str,
        bare: &Path,
        refname: &str,
        sha: &str,
    ) -> Result<(String, bool), WalError> {
        let key = self.config.layout.bundle_key(slug, refname, sha);
        if self.store.head(&key).await?.is_some() {
            return Ok((key, false));
        }
        let tmp = tmp_for("bundle", slug, sha);
        let result = async {
            let git_dir = format!("--git-dir={}", bare.display());
            let Some(path) = tmp.to_str() else {
                return Err(WalError::Other(anyhow::anyhow!(
                    "bundle tmp path is not UTF-8"
                )));
            };
            git::run_git(
                &[&git_dir, "bundle", "create", path, refname],
                &[],
                git::BUNDLE_TIMEOUT,
            )
            .await?;
            match put_file(&self.store, &key, &tmp, PutMode::Create).await {
                Ok(_) => Ok(true),
                Err(WalError::Store(error)) if error.is_precondition_failed() => Ok(false),
                Err(error) => Err(error),
            }
        }
        .await;
        let _ = tokio::fs::remove_file(&tmp).await;
        Ok((key, result?))
    }

    async fn cut_full_pack(
        &self,
        slug: &str,
        bare: &Path,
        seq: u64,
        objects: &mut Vec<String>,
    ) -> Result<PackRef, WalError> {
        let git_dir = format!("--git-dir={}", bare.display());
        let bytes = git::run_git_raw(
            &[&git_dir, "pack-objects", "--all", "--stdout"],
            &[],
            Duration::from_secs(300),
        )
        .await?;
        if bytes.is_empty() {
            return Err(WalError::Corrupt(
                "repository has no objects to pack".into(),
            ));
        }
        let ingested = git::ingest_pack(
            bare,
            &bytes,
            &git::IngestOptions {
                fsck: true,
                max_bytes: Some(self.config.limits.max_push_bytes),
                thin: true,
            },
        )
        .await?
        .ok_or_else(|| WalError::Corrupt("pack-objects produced no pack".into()))?;
        self.upload_ingested_pack(slug, &ingested, objects).await?;
        Ok(pack_ref(&ingested, seq))
    }

    async fn upload_ingested_pack(
        &self,
        slug: &str,
        pack: &IngestedPack,
        objects: &mut Vec<String>,
    ) -> Result<(), WalError> {
        let mut files = vec![
            (
                self.config.layout.pack_key(slug, &pack.checksum, "pack"),
                pack.pack_path.clone(),
            ),
            (
                self.config.layout.pack_key(slug, &pack.checksum, "idx"),
                pack.idx_path.clone(),
            ),
        ];
        if let Some(rev) = &pack.rev_path {
            files.push((
                self.config.layout.pack_key(slug, &pack.checksum, "rev"),
                rev.clone(),
            ));
        }
        for (key, path) in files {
            match put_file(&self.store, &key, &path, PutMode::Create).await {
                Ok(_) => objects.push(key),
                Err(WalError::Store(error)) if error.is_precondition_failed() => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    async fn adopt_if_landed(&self, slug: &str, commit: &BatchCommit) -> bool {
        match self.load_state(slug).await {
            Ok(Some((current, _))) => self.same_state(&current, &commit.state).unwrap_or(false),
            _ => false,
        }
    }

    /// Delete this attempt's objects that no manifest names.
    async fn cleanup_orphans(&self, slug: &str, objects: &[String]) {
        if objects.is_empty() {
            return;
        }
        let Ok(Some((state, _))) = self.load_state(slug).await else {
            return;
        };
        let named = named_objects(slug, &state, &self.config.layout);
        for key in objects {
            if !named.contains(key) {
                let _ = self.store.delete(key, None).await;
            }
        }
    }

    async fn prune(&self, slug: &str, next: &ManifestState, old: &ManifestState) {
        let _ = slug;
        for entry in next.refs.values() {
            if let Some(bundle) = &entry.bundle {
                self.prune_bundle_prefix(bundle).await;
            }
        }
        for (refname, entry) in &old.refs {
            if next.refs.contains_key(refname) {
                continue;
            }
            if let Some(bundle) = &entry.bundle {
                self.delete_bundle_prefix(bundle).await;
            }
        }
    }

    async fn delete_bundle_prefix(&self, any: &str) {
        let Some(prefix) = self.config.layout.bundle_prefix(any) else {
            return;
        };
        let prefix = format!("{prefix}/");
        let Ok(keys) = self.list_keys(&prefix).await else {
            return;
        };
        for key in keys {
            if key.ends_with(".bundle") {
                let _ = self.store.delete(&key, None).await;
            }
        }
    }

    async fn prune_bundle_prefix(&self, live: &str) {
        let Some(prefix) = self.config.layout.bundle_prefix(live) else {
            return;
        };
        let prefix = format!("{prefix}/");
        let Ok(keys) = self.list_keys(&prefix).await else {
            return;
        };
        for key in keys {
            if key != live && key.ends_with(".bundle") {
                let _ = self.store.delete(&key, None).await;
            }
        }
    }
}

/// One request's intended changes, validated against the working ref map.
struct Plan {
    after: BTreeMap<String, String>,
    txns: Vec<LogTxn>,
    moved: Vec<(String, String)>,
    deleted: Vec<String>,
}

struct BatchCommit {
    state: ManifestState,
    outcomes: Vec<(usize, RecordOutcome)>,
}

enum FailureKind {
    Precondition,
    Failed(WalError),
}

struct CommitFailure {
    kind: FailureKind,
    objects: Vec<String>,
    commit: Option<Box<BatchCommit>>,
}

impl CommitFailure {
    fn precondition(objects: Vec<String>, commit: BatchCommit) -> Self {
        Self {
            kind: FailureKind::Precondition,
            objects,
            commit: Some(Box::new(commit)),
        }
    }

    fn failed(error: WalError, objects: Vec<String>) -> Self {
        Self {
            kind: FailureKind::Failed(error),
            objects,
            commit: None,
        }
    }

    fn failed_with(error: WalError, objects: Vec<String>, commit: BatchCommit) -> Self {
        Self {
            kind: FailureKind::Failed(error),
            objects,
            commit: Some(Box::new(commit)),
        }
    }
}

fn fail_all(
    results: &mut [Option<Result<RecordOutcome, WalError>>],
    pending: &[usize],
    error: &WalError,
) {
    let failure = BatchFailure::from_error(error);
    for &index in pending {
        if let Some(slot) = results.get_mut(index) {
            *slot = Some(Err(failure.clone().into_error()));
        }
    }
}

fn plan_request(
    working: &BTreeMap<String, String>,
    updates: &[RefUpdate],
) -> Result<Plan, WalError> {
    let mut after = working.clone();
    let mut txns = Vec::new();
    let mut moved = Vec::new();
    let mut deleted = Vec::new();
    let mut seen = BTreeSet::new();
    for update in updates {
        if !seen.insert(update.refname.as_str()) {
            return Err(WalError::Other(anyhow::anyhow!(
                "duplicate refname {:?} in one publish",
                update.refname
            )));
        }
        let current = after.get(&update.refname).cloned();
        if current != update.expected_old {
            return Err(WalError::RefConflict {
                name: update.refname.clone(),
                expected: update.expected_old.clone(),
                actual: current,
            });
        }
        match &update.new_sha {
            Some(new) if current.as_deref() == Some(new.as_str()) => {}
            Some(new) => {
                txns.push(LogTxn::change(&update.refname, current, Some(new.clone())));
                after.insert(update.refname.clone(), new.clone());
                moved.push((update.refname.clone(), new.clone()));
            }
            None => {
                if current.is_some() {
                    txns.push(LogTxn::change(&update.refname, current, None));
                    after.remove(&update.refname);
                    deleted.push(update.refname.clone());
                }
            }
        }
    }
    Ok(Plan {
        after,
        txns,
        moved,
        deleted,
    })
}

fn diff_updates(
    before: &BTreeMap<String, String>,
    after: &BTreeMap<String, String>,
) -> Vec<git::RefUpdate> {
    let mut names: BTreeSet<String> = before.keys().cloned().collect();
    names.extend(after.keys().cloned());
    let mut updates = Vec::new();
    for refname in names {
        let old = before.get(&refname);
        let new = after.get(&refname);
        if old == new {
            continue;
        }
        updates.push(git::RefUpdate {
            refname,
            expected_old: old.cloned(),
            new_sha: new.cloned(),
        });
    }
    updates
}

fn moved_refs(
    before: &BTreeMap<String, String>,
    after: &BTreeMap<String, String>,
) -> Vec<(String, String)> {
    after
        .iter()
        .filter(|(name, sha)| before.get(*name) != Some(*sha))
        .map(|(name, sha)| (name.clone(), sha.clone()))
        .collect()
}

fn deleted_refs(
    before: &BTreeMap<String, String>,
    after: &BTreeMap<String, String>,
) -> Vec<String> {
    before
        .keys()
        .filter(|name| !after.contains_key(*name))
        .cloned()
        .collect()
}

fn revalidate(state: &ManifestState, txns: &[LogTxn]) -> Option<WalError> {
    for txn in txns {
        let actual = state.refs.get(&txn.refname).map(|entry| entry.sha.clone());
        if actual != txn.old {
            return Some(WalError::RefConflict {
                name: txn.refname.clone(),
                expected: txn.old.clone(),
                actual,
            });
        }
    }
    None
}

fn supersedes(
    plan: &Plan,
    base_state: &ManifestState,
    layout: &crate::config::Layout,
    slug: &str,
    storage: StorageMode,
    incoming: bool,
) -> Vec<String> {
    match storage {
        StorageMode::Bundle => plan
            .moved
            .iter()
            .map(|(refname, _)| refname)
            .chain(plan.deleted.iter())
            .filter_map(|refname| {
                base_state
                    .refs
                    .get(refname)
                    .and_then(|entry| entry.bundle.clone())
            })
            .collect(),
        StorageMode::Pack => {
            if incoming {
                Vec::new()
            } else {
                base_state
                    .packs
                    .iter()
                    .map(|pack| pack.pack_key(layout, slug))
                    .collect()
            }
        }
    }
}

fn named_objects(
    slug: &str,
    state: &ManifestState,
    layout: &crate::config::Layout,
) -> BTreeSet<String> {
    let mut named = BTreeSet::new();
    for entry in state.refs.values() {
        if let Some(bundle) = &entry.bundle {
            named.insert(bundle.clone());
        }
    }
    for pack in state.packs.iter() {
        for extension in ["pack", "idx", "rev"] {
            named.insert(layout.pack_key(slug, &pack.checksum, extension));
        }
    }
    for pack in state.retired_packs.iter() {
        for extension in ["pack", "idx", "rev"] {
            named.insert(layout.pack_key(slug, &pack.checksum, extension));
        }
    }
    for segment in &state.log {
        named.insert(segment.key.clone());
    }
    if let Some(checkpoint) = &state.checkpoint {
        named.insert(checkpoint.key.clone());
        named.insert(checkpoint.refs_key.clone());
    }
    named
}

fn pack_ref(pack: &IngestedPack, seq: u64) -> PackRef {
    PackRef {
        checksum: pack.checksum.clone(),
        pack_size: pack.pack_size,
        idx_size: pack.idx_size,
        object_count: pack.object_count,
        seq,
        tier: 0,
        has_rev: pack.rev_path.is_some(),
        has_bitmap: false,
        has_commit_graph: false,
        kind: PackKind::Objects,
    }
}

fn log_pack(pack: &PackRef) -> LogPack {
    LogPack {
        checksum: pack.checksum.clone(),
        pack_size: pack.pack_size,
        idx_size: pack.idx_size,
        object_count: pack.object_count,
        has_rev: pack.has_rev,
        has_bitmap: pack.has_bitmap,
    }
}
