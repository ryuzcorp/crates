//! The WAL: manifest commit point, bare-mirror cache and per-repository locks.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Context as _;
use tokio::sync::Mutex;

use crate::config::{tmp_path, WalConfig};
use crate::git::{
    cas_update, head_of_ref, init_bare, is_ancestor, is_full_sha, list_refs, run_git, set_ref,
    validate_slug, BUNDLE_TIMEOUT,
};
use crate::manifest::{ManifestCodec, ManifestRef};
use crate::store::ObjectStore;

/// One ref tip that moved in a publish.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishedRef {
    pub refname: String,
    pub sha: String,
    pub bundle: String,
}

/// What one publish persisted.
#[derive(Debug, Clone, Default)]
pub struct RecordOutcome {
    /// Refs whose manifest entry changed (new or moved), with their bundles.
    pub moved: Vec<PublishedRef>,
    /// Refs that belonged to the previous manifest and are gone now.
    pub deleted: Vec<String>,
}

/// A ref the caller wants moved before the publish: compare-and-swap from
/// `expected_old` (`None` = the ref must not exist yet).
#[derive(Debug, Clone)]
pub struct RefUpdate {
    pub refname: String,
    pub expected_old: Option<String>,
    pub new_sha: String,
}

impl RefUpdate {
    pub fn new(
        refname: impl Into<String>,
        expected_old: Option<impl Into<String>>,
        new_sha: impl Into<String>,
    ) -> Self {
        Self {
            refname: refname.into(),
            expected_old: expected_old.map(Into::into),
            new_sha: new_sha.into(),
        }
    }
}

/// Single-writer coordination for repositories: a per-slug mutex plus the
/// last manifest seq applied to each local bare mirror.
///
/// `applied_seq` only moves forward: a reader that syncs a manifest older than
/// one a concurrent write already applied must not drag the marker back. Cold
/// mirrors and purges reset/forget instead, so the next manifest wins.
#[derive(Clone, Default)]
pub struct GitSync {
    locks: Arc<Mutex<BTreeMap<String, Arc<Mutex<()>>>>>,
    applied: Arc<Mutex<BTreeMap<String, u64>>>,
}

impl GitSync {
    /// Hold across a whole publish (mirror CAS, bundles, manifest flip).
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

    /// Both slug locks for a slug-changing rename, taken in lexical order so
    /// two renames over the same pair serialize instead of deadlocking.
    /// Returns one guard for a same-slug pair.
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
        let second_guard = self.lock(second).await;
        (first_guard, Some(second_guard))
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

    /// Drop a slug's generation marker (purge). Call under the slug's lock.
    pub async fn forget(&self, slug: &str) {
        self.applied.lock().await.remove(slug);
    }
}

/// Borrowed WAL handle for one repository scope.
///
/// Cheap to build per call; the shared state lives in the [`ObjectStore`] and
/// [`GitSync`] it borrows.
pub struct Wal<'a, S: ObjectStore, C: ManifestCodec> {
    store: &'a S,
    config: &'a WalConfig,
    codec: &'a C,
    sync: &'a GitSync,
}

impl<'a, S: ObjectStore, C: ManifestCodec> Wal<'a, S, C> {
    pub fn new(store: &'a S, config: &'a WalConfig, codec: &'a C, sync: &'a GitSync) -> Self {
        Self {
            store,
            config,
            codec,
            sync,
        }
    }

    pub fn manifest_key(&self, slug: &str) -> String {
        self.config.layout.manifest_key(slug)
    }

    pub fn mirror_path(&self, slug: &str) -> PathBuf {
        self.config.mirror_path(slug)
    }

    /// Read the manifest. `None` means the slug has never been published.
    pub async fn read_manifest(&self, slug: &str) -> anyhow::Result<Option<C::Manifest>> {
        let Some(bytes) = self.store.get(&self.manifest_key(slug)).await? else {
            return Ok(None);
        };
        Ok(Some(self.codec.decode(&bytes)?))
    }

    /// The manifest when the local mirror still needs it: `None` when none
    /// exists or `applied_seq` already covers it. Unlocked; a caller that
    /// decides to sync must re-check under the slug's lock.
    pub async fn pending_manifest(&self, slug: &str) -> anyhow::Result<Option<C::Manifest>> {
        let Some(manifest) = self.read_manifest(slug).await? else {
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
        Ok(Some(manifest))
    }

    async fn write_manifest(&self, slug: &str, manifest: &C::Manifest) -> anyhow::Result<()> {
        let bytes = self.codec.encode(manifest)?;
        self.store.put(&self.manifest_key(slug), bytes).await
    }

    /// Create the bare mirror and the empty manifest (seq 0, no refs).
    pub async fn init_repo(&self, slug: &str) -> anyhow::Result<()> {
        validate_slug(slug)?;
        let _guard = self.sync.lock(slug).await;
        let bare = self.mirror_path(slug);
        if bare.join("HEAD").exists() {
            anyhow::bail!("repo for {slug} already exists");
        }
        if bare.exists() {
            tokio::fs::remove_dir_all(&bare).await?;
        }
        init_bare(self.config, &bare).await?;
        let manifest = self.codec.build(0, Vec::new())?;
        self.write_manifest(slug, &manifest).await?;
        self.sync.reset_applied_seq(slug, 0).await;
        Ok(())
    }

    /// Per-slug publish guard. Callers that also hold an app-level lock take
    /// this one last.
    pub async fn lock(&self, slug: &str) -> tokio::sync::OwnedMutexGuard<()> {
        self.sync.lock(slug).await
    }

    /// The mirror, rebuilt from the manifest when missing or stale. Hot path
    /// serves local without the lock.
    pub async fn ensure_synced(&self, slug: &str) -> anyhow::Result<PathBuf> {
        validate_slug(slug)?;
        let bare = self.mirror_path(slug);
        if !bare.join("HEAD").exists() {
            self.rehydrate(slug).await?;
            return Ok(bare);
        }
        if self.pending_manifest(slug).await?.is_some() {
            self.rehydrate(slug).await?;
        }
        Ok(bare)
    }

    /// [`Self::ensure_synced`] for a caller already holding the slug lock.
    pub async fn ensure_synced_locked(&self, slug: &str) -> anyhow::Result<PathBuf> {
        validate_slug(slug)?;
        let bare = self.mirror_path(slug);
        if !bare.join("HEAD").exists() {
            self.rehydrate_locked(slug).await?;
            return Ok(bare);
        }
        if self.pending_manifest(slug).await?.is_some() {
            self.rehydrate_locked(slug).await?;
        }
        Ok(bare)
    }

    /// Rebuild the mirror from the manifest. Returns the manifest's ref tips.
    pub async fn rehydrate(&self, slug: &str) -> anyhow::Result<BTreeMap<String, String>> {
        validate_slug(slug)?;
        let _guard = self.sync.lock(slug).await;
        self.rehydrate_locked(slug).await
    }

    async fn rehydrate_locked(&self, slug: &str) -> anyhow::Result<BTreeMap<String, String>> {
        let manifest = self.read_manifest(slug).await?;
        let (seq, entries) = match &manifest {
            Some(manifest) => (self.codec.seq(manifest), self.codec.refs_map(manifest)),
            None => (0, BTreeMap::new()),
        };
        let expected: BTreeMap<String, String> = entries
            .iter()
            .map(|(refname, entry)| (refname.clone(), entry.sha.clone()))
            .collect();
        let bare = self.mirror_path(slug);
        let local = if bare.join("HEAD").exists() {
            list_refs(&bare, &self.config.extra_ref_prefixes).await?
        } else {
            BTreeMap::new()
        };
        if bare.join("HEAD").exists() && local == expected {
            self.sync.set_applied_seq(slug, seq).await;
            return Ok(expected);
        }
        // Download every bundle before touching the mirror, so a missing key
        // fails without destroying a working cache.
        let mut staged: Vec<(PathBuf, String, String)> = Vec::new();
        for (refname, entry) in &entries {
            let tmp = tmp_path(&format!("rehydrate-{slug}"));
            if !self.store.get_to_file(&entry.bundle, &tmp).await? {
                for (path, _, _) in &staged {
                    let _ = tokio::fs::remove_file(path).await;
                }
                anyhow::bail!("bundle {} missing for {slug}", entry.bundle);
            }
            staged.push((tmp, refname.clone(), entry.sha.clone()));
        }
        let result = async {
            if bare.exists() {
                tokio::fs::remove_dir_all(&bare).await?;
            }
            init_bare(self.config, &bare).await?;
            let git_dir = format!("--git-dir={}", bare.display());
            for (path, refname, sha) in &staged {
                let Some(bundle) = path.to_str() else {
                    anyhow::bail!("bundle tmp path is not valid UTF-8");
                };
                run_git(
                    &[&git_dir, "fetch", bundle, &format!("+{sha}:{refname}")],
                    &[],
                    BUNDLE_TIMEOUT,
                )
                .await?;
            }
            Ok::<_, anyhow::Error>(())
        }
        .await;
        for (path, _, _) in &staged {
            let _ = tokio::fs::remove_file(path).await;
        }
        result?;
        self.sync.set_applied_seq(slug, seq).await;
        Ok(expected)
    }

    /// Apply ref updates/deletions and publish them in one manifest flip.
    pub async fn apply(
        &self,
        slug: &str,
        updates: &[RefUpdate],
        deletes: &[String],
    ) -> anyhow::Result<RecordOutcome> {
        let _guard = self.lock(slug).await;
        self.apply_locked(slug, updates, deletes).await
    }

    /// [`Self::apply`] for a caller holding the slug lock.
    pub async fn apply_locked(
        &self,
        slug: &str,
        updates: &[RefUpdate],
        deletes: &[String],
    ) -> anyhow::Result<RecordOutcome> {
        validate_slug(slug)?;
        for update in updates {
            if !is_full_sha(&update.new_sha) {
                anyhow::bail!(
                    "publish needs a full sha for {}, got {:?}",
                    update.refname,
                    update.new_sha
                );
            }
        }
        let bare = self.ensure_synced_locked(slug).await?;
        let before = list_refs(&bare, &self.config.extra_ref_prefixes).await?;
        let before = self.config.filter_refs(before);
        // Mutate the mirror; on any failure restore every ref we touched.
        let mut touched: Vec<&str> = Vec::new();
        for update in updates {
            touched.push(update.refname.as_str());
            if let Err(e) = cas_update(
                &bare,
                &update.refname,
                update.expected_old.as_deref(),
                &update.new_sha,
            )
            .await
            {
                self.restore(&bare, &before, &touched).await;
                return Err(e);
            }
        }
        for refname in deletes {
            touched.push(refname.as_str());
            if let Err(e) = set_ref(&bare, refname, None).await {
                self.restore(&bare, &before, &touched).await;
                return Err(e);
            }
        }
        let after = list_refs(&bare, &self.config.extra_ref_prefixes).await?;
        let after = self.config.filter_refs(after);
        self.sync_refs_locked(slug, &bare, &before, after).await
    }

    /// Persist a push git already accepted: read the refs after git ran and
    /// compare them with `before`.
    pub async fn record_push(
        &self,
        slug: &str,
        before: &BTreeMap<String, String>,
    ) -> anyhow::Result<RecordOutcome> {
        let _guard = self.lock(slug).await;
        self.record_push_locked(slug, before).await
    }

    /// [`Self::record_push`] for a caller holding the slug lock (the HTTP
    /// server holds it across `git receive-pack`).
    pub async fn record_push_locked(
        &self,
        slug: &str,
        before: &BTreeMap<String, String>,
    ) -> anyhow::Result<RecordOutcome> {
        validate_slug(slug)?;
        let bare = self.mirror_path(slug);
        if !bare.join("HEAD").exists() {
            anyhow::bail!("repo for {slug} has no mirror");
        }
        let before = self.config.filter_refs(before.clone());
        let after = list_refs(&bare, &self.config.extra_ref_prefixes).await?;
        let after = self.config.filter_refs(after);
        self.sync_refs_locked(slug, &bare, &before, after).await
    }

    /// Bundle every changed ref, then write one manifest. On failure the
    /// mirror is restored to `before` and orphan bundles are removed.
    async fn sync_refs_locked(
        &self,
        slug: &str,
        bare: &Path,
        before: &BTreeMap<String, String>,
        after: BTreeMap<String, String>,
    ) -> anyhow::Result<RecordOutcome> {
        let old = self.read_manifest(slug).await?;
        let old_seq = old.as_ref().map(|m| self.codec.seq(m)).unwrap_or(0);
        let old_refs = old
            .as_ref()
            .map(|m| self.codec.refs_map(m))
            .unwrap_or_default();

        let mut next_refs: BTreeMap<String, ManifestRef> = BTreeMap::new();
        let mut moved: Vec<PublishedRef> = Vec::new();
        let mut uploaded: Vec<String> = Vec::new();
        for (refname, sha) in &after {
            if let Some(entry) = old_refs.get(refname) {
                if entry.sha == *sha {
                    next_refs.insert(refname.clone(), entry.clone());
                    continue;
                }
            }
            let key = self.config.layout.bundle_key(slug, refname, sha);
            match self.write_bundle(bare, slug, refname, sha, &key).await {
                Ok(()) => {
                    next_refs.insert(
                        refname.clone(),
                        ManifestRef {
                            sha: sha.clone(),
                            bundle: key.clone(),
                        },
                    );
                    uploaded.push(key.clone());
                    moved.push(PublishedRef {
                        refname: refname.clone(),
                        sha: sha.clone(),
                        bundle: key,
                    });
                }
                Err(e) => {
                    self.rollback(slug, bare, before, &after, &old_refs, &uploaded)
                        .await;
                    return Err(e);
                }
            }
        }

        let seq = old_seq + 1;
        let manifest = match self
            .codec
            .build(seq, next_refs.clone().into_iter().collect())
        {
            Ok(manifest) => manifest,
            Err(e) => {
                self.rollback(slug, bare, before, &after, &old_refs, &uploaded)
                    .await;
                return Err(e);
            }
        };
        if let Err(e) = self.write_manifest(slug, &manifest).await {
            // The write may have landed despite the error (a response lost
            // after the store applied it). Re-read to learn the truth: a
            // manifest that already names our refs at our seq means the flip
            // happened, so adopt it instead of rolling back under it.
            let landed = matches!(
                self.read_manifest(slug).await,
                Ok(Some(current))
                    if self.codec.seq(&current) == seq
                        && self.codec.refs_map(&current) == next_refs
            );
            if landed {
                self.sync.set_applied_seq(slug, seq).await;
                self.prune(slug, &after, &next_refs, &old_refs).await;
                return Ok(RecordOutcome {
                    moved,
                    deleted: deleted_refs(&old_refs, &after),
                });
            }
            self.rollback(slug, bare, before, &after, &old_refs, &uploaded)
                .await;
            return Err(e);
        }
        self.sync.set_applied_seq(slug, seq).await;
        self.prune(slug, &after, &next_refs, &old_refs).await;
        Ok(RecordOutcome {
            moved,
            deleted: deleted_refs(&old_refs, &after),
        })
    }

    async fn write_bundle(
        &self,
        bare: &Path,
        slug: &str,
        refname: &str,
        sha: &str,
        key: &str,
    ) -> anyhow::Result<()> {
        let tmp = tmp_path(&format!("bundle-{slug}-{sha}"));
        let result = async {
            let git_dir = format!("--git-dir={}", bare.display());
            let Some(path) = tmp.to_str() else {
                anyhow::bail!("bundle tmp path is not valid UTF-8");
            };
            run_git(
                &[&git_dir, "bundle", "create", path, refname],
                &[],
                BUNDLE_TIMEOUT,
            )
            .await?;
            self.store.put_file(key, &tmp).await
        }
        .await;
        let _ = tokio::fs::remove_file(&tmp).await;
        result.with_context(|| format!("publishing {refname}"))
    }

    /// Restore refs to `before` for every changed/removed ref, then delete
    /// uploaded bundles that the old manifest does not name (orphans).
    async fn rollback(
        &self,
        slug: &str,
        bare: &Path,
        before: &BTreeMap<String, String>,
        after: &BTreeMap<String, String>,
        old_refs: &BTreeMap<String, ManifestRef>,
        uploaded: &[String],
    ) {
        let touched: Vec<&str> = before
            .keys()
            .chain(after.keys())
            .map(String::as_str)
            .collect();
        self.restore(bare, before, &touched).await;
        for key in uploaded {
            if !old_refs.values().any(|entry| entry.bundle == *key) {
                let _ = self.store.delete(key).await;
            }
        }
        let _ = slug;
    }

    async fn restore(&self, bare: &Path, before: &BTreeMap<String, String>, refs: &[&str]) {
        for refname in refs {
            let _ = set_ref(bare, refname, before.get(*refname).map(String::as_str)).await;
        }
    }

    /// Keep only the live bundle per ref and delete removed refs' prefixes.
    async fn prune(
        &self,
        slug: &str,
        after: &BTreeMap<String, String>,
        next_refs: &BTreeMap<String, ManifestRef>,
        old_refs: &BTreeMap<String, ManifestRef>,
    ) {
        for (refname, entry) in next_refs {
            if after.contains_key(refname) {
                self.prune_bundle_prefix(&entry.bundle).await;
            }
        }
        for (refname, entry) in old_refs {
            if !after.contains_key(refname) {
                self.delete_bundle_prefix(&entry.bundle).await;
            }
        }
        let _ = slug;
    }

    /// Delete superseded bundles under one ref prefix, keeping `live`.
    async fn prune_bundle_prefix(&self, live: &str) {
        let Some(prefix) = self.config.layout.bundle_prefix(live) else {
            return;
        };
        let prefix = format!("{prefix}/");
        let Ok(keys) = self.store.list(&prefix).await else {
            return;
        };
        for key in keys {
            if key != live && key.ends_with(".bundle") {
                let _ = self.store.delete(&key).await;
            }
        }
    }

    /// Delete every bundle under one ref prefix.
    async fn delete_bundle_prefix(&self, key: &str) {
        let Some(prefix) = self.config.layout.bundle_prefix(key) else {
            return;
        };
        let prefix = format!("{prefix}/");
        let Ok(keys) = self.store.list(&prefix).await else {
            return;
        };
        for name in keys {
            if name.ends_with(".bundle") {
                let _ = self.store.delete(&name).await;
            }
        }
    }

    /// Delete the mirror and the whole repository prefix, and forget the
    /// slug's generation so a recreated slug's seq is applied.
    pub async fn purge(&self, slug: &str) -> anyhow::Result<()> {
        validate_slug(slug)?;
        let _guard = self.lock(slug).await;
        let bare = self.mirror_path(slug);
        match tokio::fs::remove_dir_all(&bare).await {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        self.store
            .delete_prefix(&self.config.layout.repo_prefix(slug))
            .await?;
        self.sync.forget(slug).await;
        Ok(())
    }

    /// The head of `refname` in the mirror (rehydrating when needed).
    pub async fn head_of(&self, slug: &str, refname: &str) -> anyhow::Result<Option<String>> {
        let bare = self.ensure_synced(slug).await?;
        head_of_ref(&bare, refname).await
    }

    /// Fast-forward check against the local mirror.
    pub async fn is_fast_forward(&self, slug: &str, old: &str, new: &str) -> anyhow::Result<bool> {
        let bare = self.ensure_synced(slug).await?;
        Ok(is_ancestor(&bare, old, new).await)
    }
}

fn deleted_refs(
    old_refs: &BTreeMap<String, ManifestRef>,
    after: &BTreeMap<String, String>,
) -> Vec<String> {
    old_refs
        .keys()
        .filter(|refname| !after.contains_key(*refname))
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    use crate::config::Layout;
    use crate::git;
    use crate::manifest::{RefsCodec, MANIFEST_VERSION};
    use crate::store::MemoryStore;

    fn config(dir: &Path) -> WalConfig {
        WalConfig::new(dir.join("git"), Layout::new("git"))
    }

    async fn setup(slug: &str) -> (tempfile::TempDir, WalConfig, MemoryStore, GitSync) {
        let dir = tempfile::tempdir().unwrap();
        let cfg = config(dir.path());
        let store = MemoryStore::new();
        let sync = GitSync::default();
        Wal::new(&store, &cfg, &RefsCodec, &sync)
            .init_repo(slug)
            .await
            .unwrap();
        (dir, cfg, store, sync)
    }

    async fn commit_on_empty_tree(bare: &Path, parent: Option<&str>) -> String {
        let git_dir = format!("--git-dir={}", bare.display());
        let tree = git::run_git_stdin(&[&git_dir, "mktree"], &[], &[], Duration::from_secs(15))
            .await
            .map(|b| String::from_utf8(b).unwrap())
            .unwrap();
        let tree = tree.trim().to_string();
        let mut args = vec![git_dir.as_str(), "commit-tree", tree.as_str(), "-m", "test"];
        if let Some(p) = parent {
            args.extend(["-p", p]);
        }
        git::run_git(
            &args,
            &[
                ("GIT_AUTHOR_NAME", "wal-test"),
                ("GIT_AUTHOR_EMAIL", "wal-test@example.com"),
                ("GIT_COMMITTER_NAME", "wal-test"),
                ("GIT_COMMITTER_EMAIL", "wal-test@example.com"),
            ],
            Duration::from_secs(15),
        )
        .await
        .map(|s| s.trim().to_string())
        .unwrap()
    }

    #[tokio::test]
    async fn init_writes_empty_manifest_and_purge_clears_it() {
        let (_dir, cfg, store, sync) = setup("grocery").await;
        let wal = Wal::new(&store, &cfg, &RefsCodec, &sync);
        let manifest = wal.read_manifest("grocery").await.unwrap().unwrap();
        assert_eq!(manifest.version, MANIFEST_VERSION);
        assert_eq!(manifest.seq, 0);
        assert!(manifest.refs.is_empty());

        wal.purge("grocery").await.unwrap();
        assert!(wal.read_manifest("grocery").await.unwrap().is_none());
        assert!(!wal.mirror_path("grocery").exists());
    }

    #[tokio::test]
    async fn publish_advances_manifest_and_prunes_old_bundle() {
        let (_dir, cfg, store, sync) = setup("publish").await;
        let wal = Wal::new(&store, &cfg, &RefsCodec, &sync);
        let bare = wal.mirror_path("publish");
        let first = commit_on_empty_tree(&bare, None).await;
        let outcome = wal
            .apply(
                "publish",
                &[RefUpdate::new("refs/heads/main", None::<String>, &first)],
                &[],
            )
            .await
            .unwrap();
        assert_eq!(outcome.moved.len(), 1);
        let manifest = wal.read_manifest("publish").await.unwrap().unwrap();
        assert_eq!(manifest.seq, 1);
        assert_eq!(manifest.refs["refs/heads/main"].sha, first);
        assert_eq!(sync.applied_seq("publish").await, Some(1));

        let second = commit_on_empty_tree(&bare, Some(&first)).await;
        wal.apply(
            "publish",
            &[RefUpdate::new(
                "refs/heads/main",
                Some(first.clone()),
                &second,
            )],
            &[],
        )
        .await
        .unwrap();
        let manifest = wal.read_manifest("publish").await.unwrap().unwrap();
        assert_eq!(manifest.seq, 2);
        assert_eq!(manifest.refs["refs/heads/main"].sha, second);
        let first_key = cfg.layout.bundle_key("publish", "refs/heads/main", &first);
        assert!(
            store.get(&first_key).await.unwrap().is_none(),
            "the superseded bundle is pruned after the flip"
        );
    }

    #[tokio::test]
    async fn publish_cas_conflict_leaves_mirror_and_manifest_alone() {
        let (_dir, cfg, store, sync) = setup("cas").await;
        let wal = Wal::new(&store, &cfg, &RefsCodec, &sync);
        let bare = wal.mirror_path("cas");
        let first = commit_on_empty_tree(&bare, None).await;
        wal.apply(
            "cas",
            &[RefUpdate::new("refs/heads/main", None::<String>, &first)],
            &[],
        )
        .await
        .unwrap();
        let other = commit_on_empty_tree(&bare, Some(&first)).await;
        let err = wal
            .apply(
                "cas",
                &[RefUpdate::new(
                    "refs/heads/main",
                    Some("f".repeat(40)),
                    &other,
                )],
                &[],
            )
            .await
            .unwrap_err();
        assert!(format!("{err:#}").contains("tip moved"), "{err:#}");
        let manifest = wal.read_manifest("cas").await.unwrap().unwrap();
        assert_eq!(manifest.seq, 1);
        assert_eq!(manifest.refs["refs/heads/main"].sha, first);
    }

    #[tokio::test]
    async fn multi_ref_publish_and_delete_share_one_manifest() {
        let (_dir, cfg, store, sync) = setup("multi").await;
        let wal = Wal::new(&store, &cfg, &RefsCodec, &sync);
        let bare = wal.mirror_path("multi");
        let main = commit_on_empty_tree(&bare, None).await;
        let side = commit_on_empty_tree(&bare, Some(&main)).await;
        // Move refs directly, as a git push would.
        set_ref(&bare, "refs/heads/main", Some(&main))
            .await
            .unwrap();
        set_ref(&bare, "refs/heads/side", Some(&side))
            .await
            .unwrap();
        let before = BTreeMap::from([("refs/heads/main".to_string(), main.clone())]);
        let outcome = wal.record_push("multi", &before).await.unwrap();
        assert_eq!(outcome.moved.len(), 2);
        assert_eq!(outcome.deleted.len(), 0);
        let manifest = wal.read_manifest("multi").await.unwrap().unwrap();
        assert_eq!(manifest.seq, 1);
        assert_eq!(manifest.refs.len(), 2);

        set_ref(&bare, "refs/heads/side", None).await.unwrap();
        let before = BTreeMap::from([
            ("refs/heads/main".to_string(), main.clone()),
            ("refs/heads/side".to_string(), side.clone()),
        ]);
        let outcome = wal.record_push("multi", &before).await.unwrap();
        assert_eq!(outcome.deleted, vec!["refs/heads/side"]);
        let side_key = cfg.layout.bundle_key("multi", "refs/heads/side", &side);
        assert!(store.get(&side_key).await.unwrap().is_none());
        let manifest = wal.read_manifest("multi").await.unwrap().unwrap();
        assert_eq!(manifest.seq, 2);
        assert_eq!(manifest.refs.len(), 1);
    }

    #[tokio::test]
    async fn cold_rehydrate_rebuilds_every_ref_from_bundles() {
        let (_dir, cfg, store, sync) = setup("cold").await;
        let wal = Wal::new(&store, &cfg, &RefsCodec, &sync);
        let bare = wal.mirror_path("cold");
        let main = commit_on_empty_tree(&bare, None).await;
        let side = commit_on_empty_tree(&bare, Some(&main)).await;
        set_ref(&bare, "refs/heads/main", Some(&main))
            .await
            .unwrap();
        set_ref(&bare, "refs/heads/side", Some(&side))
            .await
            .unwrap();
        wal.record_push("cold", &BTreeMap::new()).await.unwrap();

        let fresh_sync = GitSync::default();
        let fresh = Wal::new(&store, &cfg, &RefsCodec, &fresh_sync);
        let rebuilt = fresh.rehydrate("cold").await.unwrap();
        assert_eq!(rebuilt.get("refs/heads/main"), Some(&main));
        assert_eq!(rebuilt.get("refs/heads/side"), Some(&side));
        let bare = fresh.mirror_path("cold");
        assert_eq!(
            head_of_ref(&bare, "refs/heads/main").await.unwrap(),
            Some(main)
        );
        assert_eq!(
            head_of_ref(&bare, "refs/heads/side").await.unwrap(),
            Some(side)
        );
    }

    #[tokio::test]
    async fn failed_manifest_read_leaves_mirror_untouched() {
        let (_dir, cfg, store, sync) = setup("unreadable").await;
        let wal = Wal::new(&store, &cfg, &RefsCodec, &sync);
        let bare = wal.mirror_path("unreadable");
        let sha = commit_on_empty_tree(&bare, None).await;
        store
            .put(&wal.manifest_key("unreadable"), b"{not json".to_vec())
            .await
            .unwrap();
        assert!(wal
            .apply(
                "unreadable",
                &[RefUpdate::new("refs/heads/main", None::<String>, &sha)],
                &[],
            )
            .await
            .is_err());
        assert!(head_of_ref(&bare, "refs/heads/main")
            .await
            .unwrap()
            .is_none());
        assert!(
            store
                .list("git/unreadable/refs/heads/main/")
                .await
                .unwrap()
                .is_empty(),
            "no bundle is uploaded when the old manifest cannot be read"
        );
    }

    #[tokio::test]
    async fn opposite_rename_pairs_serialize_without_deadlock() {
        let sync = GitSync::default();
        let a = sync.clone();
        let b = sync.clone();
        let pair = tokio::time::timeout(Duration::from_secs(5), async {
            let left = tokio::spawn(async move { a.lock_pair("alpha", "beta").await });
            let right = tokio::spawn(async move { b.lock_pair("beta", "alpha").await });
            let _ = left.await.unwrap();
            let _ = right.await.unwrap();
        })
        .await;
        assert!(pair.is_ok(), "opposite rename pairs must not deadlock");
        let (_, second) = sync.lock_pair("demo", "demo").await;
        assert!(second.is_none(), "same-slug rename holds one guard");
    }

    #[tokio::test]
    async fn applied_seq_never_moves_backward() {
        let sync = GitSync::default();
        sync.set_applied_seq("s", 5).await;
        sync.set_applied_seq("s", 3).await;
        assert_eq!(sync.applied_seq("s").await, Some(5));
        sync.reset_applied_seq("s", 1).await;
        assert_eq!(sync.applied_seq("s").await, Some(1));
        sync.forget("s").await;
        assert_eq!(sync.applied_seq("s").await, None);
    }
}
