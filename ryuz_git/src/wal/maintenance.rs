//! Maintenance: connectivity checks, compaction, collection and repair.
//!
//! Every operation here is safe against concurrent publishes: each one
//! re-reads the manifest, mutates only its own fields, and writes it back with
//! a CAS, retrying on `PreconditionFailed`. Immutable bytes (packs, reports,
//! markers) land before the manifest flip; nothing a live or retired manifest
//! names is ever deleted.
//!
//! Cross-instance exclusion uses the `leases/compact` lease. The public entry
//! points take the lease themselves and fail fast when another host holds it;
//! the `*_at` variants take an explicit mirror and no lease, which is what
//! embedders and tests use.

use std::collections::BTreeSet;
use std::path::Path;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use chrono::{SecondsFormat, Utc};
use serde::{Deserialize, Serialize};

use crate::config::StorageMode;
use crate::error::{GitError, WalError};
use crate::git::{
    check_connectivity, ingest_pack, run_git, run_git_output, run_git_stdin, IngestOptions,
    IngestedPack, PROTOCOL_TIMEOUT, QUICK_TIMEOUT,
};
use crate::manifest::{ManifestCodec, ManifestState, PackKind, PackRef, RetiredPack};
use crate::store::{ObjectStoreExt as _, PutMode};
use crate::wal::checkpoint::put_immutable_file;
use crate::wal::lease::{self, LeaseGuard, LeaseRequest};
use crate::wal::Wal;

/// Lease name every maintenance operation takes.
pub const MAINTENANCE_LEASE: &str = "compact";

/// Errors specific to maintenance.
#[derive(Debug, thiserror::Error)]
pub enum MaintenanceError {
    #[error("repository {slug} uses bundle storage; compaction needs pack storage")]
    NotPackMode { slug: String },
    #[error("pack {checksum} is not in the live set")]
    UnknownPack { checksum: String },
    #[error("maintenance lease {name} is held elsewhere")]
    LeaseHeld { name: String },
}

impl From<MaintenanceError> for WalError {
    fn from(error: MaintenanceError) -> Self {
        Self::Other(error.into())
    }
}

/// Result of one connectivity check.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct FsckReport {
    /// Manifest sequence the check ran against.
    pub seq: u64,
    /// RFC 3339 timestamp.
    pub at: String,
    pub host: String,
    /// Object ids reachable from refs but absent locally.
    #[serde(default)]
    pub missing: Vec<String>,
    /// Size of `missing` (kept explicit for readers that page the list).
    #[serde(default)]
    pub missing_total: u64,
    /// Every other diagnostic `git fsck` printed.
    #[serde(default)]
    pub problems: Vec<String>,
    pub elapsed_secs: f64,
    /// Sequence a repair installed objects for, when one ran.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repaired_seq: Option<u64>,
}

impl FsckReport {
    pub fn is_healthy(&self) -> bool {
        self.missing.is_empty() && self.problems.is_empty()
    }
}

/// How much a compaction should change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompactOptions {
    /// Tier of the pack a compaction produces. 0 = push, 1 = compacted.
    pub target_tier: u32,
    /// How many superseded packs stay live instead of being retired.
    pub retain: usize,
    /// Compact even when the live set is already at `target_tier`.
    pub force: bool,
}

impl Default for CompactOptions {
    fn default() -> Self {
        Self {
            target_tier: 1,
            retain: 0,
            force: false,
        }
    }
}

/// What a collection pass did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GcReport {
    pub scanned: u64,
    pub deleted: Vec<String>,
    pub young: u64,
    pub live: u64,
}

impl GcReport {
    pub fn deleted_count(&self) -> usize {
        self.deleted.len()
    }
}

/// A connection to a source of missing objects (for example an upstream
/// mirror). Implementations own their transport; this module only installs and
/// publishes the resulting pack.
#[async_trait]
pub trait RepairSource: Send + Sync {
    /// Return one pack that satisfies as many `missing` objects as possible, or
    /// `None` when the source cannot help.
    async fn fetch_pack(&self, missing: &[String]) -> Result<Option<Vec<u8>>, WalError>;
}

/// Result of a repair attempt.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RepairOutcome {
    pub seq: u64,
    pub missing: Vec<String>,
    pub installed: Option<PackRef>,
}

// ---------------------------------------------------------------------------
// fsck
// ---------------------------------------------------------------------------

/// Run `git fsck --connectivity-only --no-dangling` on the synced mirror and
/// persist the report at `layout.fsck_key`.
pub async fn fsck<C: ManifestCodec>(wal: &Wal<C>, slug: &str) -> Result<FsckReport, WalError> {
    let _lease = take_lease(wal, slug).await?;
    let _lock = wal.sync().lock(slug).await;
    let mirror = wal.ensure_synced_locked(slug).await?;
    fsck_at(wal, slug, &mirror).await
}

/// [`fsck`] against an explicit mirror, without taking a lease.
pub async fn fsck_at<C: ManifestCodec>(
    wal: &Wal<C>,
    slug: &str,
    mirror: &Path,
) -> Result<FsckReport, WalError> {
    let Some((manifest, _)) = wal.load_manifest(slug).await? else {
        return Err(WalError::NotFound(slug.to_string()));
    };
    let seq = wal.codec().state(&manifest).seq;
    let started = Instant::now();
    let git_dir = format!("--git-dir={}", mirror.display());
    let mut lines = Vec::new();
    let output = run_git_output(
        &[&git_dir, "fsck", "--connectivity-only", "--no-dangling"],
        None,
        &[],
        PROTOCOL_TIMEOUT,
    )
    .await?;
    for stream in [&output.stdout, &output.stderr] {
        lines.extend(
            String::from_utf8_lossy(stream)
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .map(str::to_string),
        );
    }
    if !output.status.success() && lines.is_empty() {
        lines.push(format!("git fsck exited with {}", output.status));
    }
    let mut missing = BTreeSet::new();
    let mut problems = BTreeSet::new();
    for line in lines {
        match line.strip_prefix("missing ") {
            Some(rest) => {
                if let Some(oid) = rest.split_whitespace().last() {
                    missing.insert(oid.to_string());
                }
            }
            None => {
                problems.insert(line.to_string());
            }
        }
    }
    let missing: Vec<String> = missing.into_iter().collect();
    let report = FsckReport {
        seq,
        at: now_rfc3339(),
        host: hostname(),
        missing_total: missing.len() as u64,
        missing,
        problems: problems.into_iter().collect(),
        elapsed_secs: started.elapsed().as_secs_f64(),
        repaired_seq: None,
    };
    put_report(wal, slug, &report).await?;
    Ok(report)
}

async fn put_report<C: ManifestCodec>(
    wal: &Wal<C>,
    slug: &str,
    report: &FsckReport,
) -> Result<(), WalError> {
    let key = wal.config().layout.fsck_key(slug);
    wal.store()
        .put_bytes(&key, serde_json::to_vec(report)?, PutMode::Overwrite)
        .await?;
    Ok(())
}

/// Read the last fsck report, when one exists.
pub async fn read_fsck_report<C: ManifestCodec>(
    wal: &Wal<C>,
    slug: &str,
) -> Result<Option<FsckReport>, WalError> {
    let key = wal.config().layout.fsck_key(slug);
    match wal.store().get_bytes(&key).await? {
        Some((_, bytes)) => Ok(Some(serde_json::from_slice(&bytes)?)),
        None => Ok(None),
    }
}

// ---------------------------------------------------------------------------
// compaction
// ---------------------------------------------------------------------------

/// Repack every reachable object into one pack, upload it, and CAS the pack
/// set. Superseded packs move to `retired_packs`; their bytes stay available.
pub async fn compact<C: ManifestCodec>(
    wal: &Wal<C>,
    slug: &str,
    opts: CompactOptions,
) -> Result<Option<PackRef>, WalError> {
    let _lease = take_lease(wal, slug).await?;
    let _lock = wal.sync().lock(slug).await;
    let mirror = wal.ensure_synced_locked(slug).await?;
    compact_at(wal, slug, &mirror, opts).await
}

/// [`compact`] against an explicit mirror, without taking a lease.
pub async fn compact_at<C: ManifestCodec>(
    wal: &Wal<C>,
    slug: &str,
    mirror: &Path,
    opts: CompactOptions,
) -> Result<Option<PackRef>, WalError> {
    if wal.config().storage != StorageMode::Pack {
        return Err(MaintenanceError::NotPackMode {
            slug: slug.to_string(),
        }
        .into());
    }
    let Some((manifest, _)) = wal.load_manifest(slug).await? else {
        return Err(WalError::NotFound(slug.to_string()));
    };
    let initial = wal.codec().state(&manifest);
    if initial.refs.is_empty() {
        return Ok(None);
    }
    if !opts.force && initial.packs.len() == 1 && initial.packs[0].tier >= opts.target_tier {
        return Ok(None);
    }

    // 1. Build the pack locally. `--all` covers every ref, so no ref list is
    //    needed and the pack is complete for this snapshot.
    let snapshot_seq = initial.seq;
    let pack_dir = mirror.join("objects").join("pack");
    let base = pack_dir.join("pack");
    let base_str = base
        .to_str()
        .ok_or_else(|| WalError::Other(anyhow::anyhow!("mirror path is not UTF-8")))?;
    let git_dir = format!("--git-dir={}", mirror.display());
    let output = run_git(
        &[
            &git_dir,
            "pack-objects",
            "--all",
            "--revs",
            "--delta-base-offset",
            "--threads=1",
            "--index-version=2",
            base_str,
        ],
        &[],
        PROTOCOL_TIMEOUT,
    )
    .await?;
    let checksum = output
        .split_whitespace()
        .last()
        .filter(|value| {
            (value.len() == 40 || value.len() == 64)
                && value.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
        .ok_or_else(|| GitError::Pack(format!("pack-objects reported no checksum: {output:?}")))?
        .to_lowercase();
    let pack_path = pack_dir.join(format!("pack-{checksum}.pack"));
    let idx_path = pack_dir.join(format!("pack-{checksum}.idx"));
    let rev_path = pack_dir.join(format!("pack-{checksum}.rev"));
    if !pack_path.exists() || !idx_path.exists() {
        return Err(GitError::Pack(format!(
            "pack-objects did not leave pack-{checksum} in {}",
            pack_dir.display()
        ))
        .into());
    }
    if !rev_path.exists() {
        let pack_arg = pack_path
            .to_str()
            .ok_or_else(|| WalError::Other(anyhow::anyhow!("pack path is not UTF-8")))?;
        run_git(
            &[&git_dir, "index-pack", "--rev-index", pack_arg],
            &[],
            PROTOCOL_TIMEOUT,
        )
        .await?;
    }
    let pack_size = tokio::fs::metadata(&pack_path).await?.len();
    let idx_size = tokio::fs::metadata(&idx_path).await?.len();
    let object_count = count_indexed_objects(&idx_path).await?;

    // 2. Upload immutable bytes before the manifest names them.
    let layout = &wal.config().layout;
    put_immutable_file(wal, &layout.pack_key(slug, &checksum, "pack"), &pack_path).await?;
    put_immutable_file(wal, &layout.pack_key(slug, &checksum, "idx"), &idx_path).await?;
    let has_rev = rev_path.exists();
    if has_rev {
        put_immutable_file(wal, &layout.pack_key(slug, &checksum, "rev"), &rev_path).await?;
    }

    // 3. CAS the pack set. Only packs that predate this snapshot may be
    //    retired; anything a concurrent publish added stays live.
    let attempts = wal.config().publish_retries.max(1);
    for _ in 0..attempts {
        let Some((manifest, version)) = wal.load_manifest(slug).await? else {
            return Err(WalError::NotFound(slug.to_string()));
        };
        let state = wal.codec().state(&manifest);
        if let Some(existing) = state.packs.iter().find(|pack| pack.checksum == checksum) {
            return Ok(Some(existing.clone()));
        }
        let new_pack = PackRef {
            checksum: checksum.clone(),
            pack_size,
            idx_size,
            object_count,
            seq: snapshot_seq,
            tier: opts.target_tier,
            has_rev,
            has_bitmap: false,
            has_commit_graph: false,
            kind: PackKind::History,
        };
        let mut eligible: Vec<PackRef> = state
            .packs
            .iter()
            .filter(|pack| pack.seq <= snapshot_seq)
            .cloned()
            .collect();
        eligible.sort_by(|left, right| {
            left.seq
                .cmp(&right.seq)
                .then_with(|| left.checksum.cmp(&right.checksum))
        });
        let retired_count = eligible.len().saturating_sub(opts.retain);
        let (retire, keep) = eligible.split_at(retired_count);
        let retire = retire.to_vec();
        let mut next = state.clone();
        // Packs a concurrent publish added after this snapshot stay live: they
        // carry objects our `--all` pack could not see.
        next.packs = state
            .packs
            .iter()
            .filter(|pack| pack.seq > snapshot_seq)
            .cloned()
            .collect();
        next.packs.extend(keep.iter().cloned());
        next.packs.push(new_pack.clone());
        next.retired_packs
            .retain(|retired| retired.checksum != checksum);
        for pack in &retire {
            if !next
                .retired_packs
                .iter()
                .any(|retired| retired.checksum == pack.checksum)
            {
                next.retired_packs.push(RetiredPack {
                    checksum: pack.checksum.clone(),
                    retired_at: now_rfc3339(),
                    retired_seq: state.seq,
                });
            }
        }
        let next_manifest = wal.codec().from_state(next)?;
        match wal
            .write_manifest(slug, &next_manifest, PutMode::Update(version))
            .await
        {
            Ok(_) => {
                prune_local_packs(mirror, &retire).await;
                return Ok(Some(new_pack));
            }
            Err(WalError::Store(error)) if error.is_precondition_failed() => continue,
            Err(error) => return Err(error),
        }
    }
    Err(WalError::RetryExhausted {
        slug: slug.to_string(),
        attempts,
    })
}

async fn count_indexed_objects(idx_path: &Path) -> Result<u64, WalError> {
    let index = tokio::fs::read(idx_path).await?;
    let listing = run_git_stdin(&["show-index"], &index, &[], QUICK_TIMEOUT).await?;
    Ok(String::from_utf8_lossy(&listing)
        .lines()
        .filter(|line| !line.trim().is_empty())
        .count() as u64)
}

/// Remove the local copies of packs the manifest just retired. Only called
/// after the CAS flip; the bytes remain in the store.
async fn prune_local_packs(mirror: &Path, retired: &[PackRef]) {
    let retired: BTreeSet<&str> = retired.iter().map(|pack| pack.checksum.as_str()).collect();
    if retired.is_empty() {
        return;
    }
    let dir = mirror.join("objects").join("pack");
    let Ok(mut entries) = tokio::fs::read_dir(&dir).await else {
        return;
    };
    while let Ok(Some(entry)) = entries.next_entry().await {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let Some(rest) = name.strip_prefix("pack-") else {
            continue;
        };
        let Some((checksum, _)) = rest.split_once('.') else {
            continue;
        };
        if retired.contains(checksum) {
            let _ = tokio::fs::remove_file(entry.path()).await;
        }
    }
}

/// Move the named live packs into `retired_packs`. Their bytes stay named, so
/// they remain downloadable; they are just no longer live.
pub async fn retire<C: ManifestCodec>(
    wal: &Wal<C>,
    slug: &str,
    checksums: &[String],
) -> Result<Vec<RetiredPack>, WalError> {
    let _lease = take_lease(wal, slug).await?;
    retire_at(wal, slug, checksums).await
}

/// [`retire`] without taking a lease.
pub async fn retire_at<C: ManifestCodec>(
    wal: &Wal<C>,
    slug: &str,
    checksums: &[String],
) -> Result<Vec<RetiredPack>, WalError> {
    let attempts = wal.config().publish_retries.max(1);
    for _ in 0..attempts {
        let Some((manifest, version)) = wal.load_manifest(slug).await? else {
            return Err(WalError::NotFound(slug.to_string()));
        };
        let state = wal.codec().state(&manifest);
        let live: BTreeSet<&str> = state
            .packs
            .iter()
            .map(|pack| pack.checksum.as_str())
            .collect();
        let already: BTreeSet<&str> = state
            .retired_packs
            .iter()
            .map(|pack| pack.checksum.as_str())
            .collect();
        for checksum in checksums {
            if !live.contains(checksum.as_str()) && !already.contains(checksum.as_str()) {
                return Err(MaintenanceError::UnknownPack {
                    checksum: checksum.clone(),
                }
                .into());
            }
        }
        let mut next = state.clone();
        let mut retired_now = Vec::new();
        for checksum in checksums {
            if !live.contains(checksum.as_str()) {
                continue;
            }
            let retired = RetiredPack {
                checksum: checksum.clone(),
                retired_at: now_rfc3339(),
                retired_seq: state.seq,
            };
            next.retired_packs.push(retired.clone());
            retired_now.push(retired);
        }
        if retired_now.is_empty() {
            return Ok(Vec::new());
        }
        next.retired_packs
            .sort_by(|left, right| left.checksum.cmp(&right.checksum));
        next.retired_packs
            .dedup_by(|left, right| left.checksum == right.checksum);
        next.packs
            .retain(|pack| !checksums.iter().any(|checksum| checksum == &pack.checksum));
        let next_manifest = wal.codec().from_state(next)?;
        match wal
            .write_manifest(slug, &next_manifest, PutMode::Update(version))
            .await
        {
            Ok(_) => return Ok(retired_now),
            Err(WalError::Store(error)) if error.is_precondition_failed() => continue,
            Err(error) => return Err(error),
        }
    }
    Err(WalError::RetryExhausted {
        slug: slug.to_string(),
        attempts,
    })
}

// ---------------------------------------------------------------------------
// collection
// ---------------------------------------------------------------------------

/// Delete `wal/*` and log objects the manifest does not name, once they are
/// older than `retention_grace`.
///
/// The store contract exposes no modification time, so age is tracked from the
/// first collection pass that sees an unreferenced object: a marker at
/// `<repo>/gc/seen/<key>.json` records `first_seen_unix_ms`. Until
/// `retention_grace` has elapsed on that marker the object is kept. The object
/// and its marker are removed together.
pub async fn gc<C: ManifestCodec>(
    wal: &Wal<C>,
    slug: &str,
    now: u64,
) -> Result<GcReport, WalError> {
    let _lease = take_lease(wal, slug).await?;
    gc_at(wal, slug, now).await
}

/// [`gc`] without taking a lease (tests and lease-holding callers).
pub async fn gc_at<C: ManifestCodec>(
    wal: &Wal<C>,
    slug: &str,
    now: u64,
) -> Result<GcReport, WalError> {
    use futures::StreamExt as _;

    let Some((manifest, _)) = wal.load_manifest(slug).await? else {
        return Err(WalError::NotFound(slug.to_string()));
    };
    let state = wal.codec().state(&manifest);
    let layout = &wal.config().layout;
    let repo_prefix = layout.repo_prefix(slug);

    let mut named = BTreeSet::new();
    for checksum in state
        .packs
        .iter()
        .map(|pack| &pack.checksum)
        .chain(state.retired_packs.iter().map(|pack| &pack.checksum))
    {
        for extension in ["pack", "idx", "rev", "bitmap"] {
            named.insert(format!("wal/{checksum}.{extension}"));
        }
    }
    for segment in &state.log {
        named.insert(segment.key.clone());
        if let Some(relative) = segment.key.strip_prefix(repo_prefix.as_str()) {
            named.insert(relative.to_string());
        }
    }
    for bundle in state
        .refs
        .values()
        .filter_map(|entry| entry.bundle.as_deref())
    {
        named.insert(bundle.to_string());
        if let Some(relative) = bundle.strip_prefix(repo_prefix.as_str()) {
            named.insert(relative.to_string());
        }
    }

    let grace_ms = wal.config().retention_grace.as_millis() as u64;
    let mut report = GcReport::default();
    for prefix in [format!("{repo_prefix}wal/"), format!("{repo_prefix}log/")] {
        let mut stream = wal.store().list(&prefix, None);
        while let Some(item) = stream.next().await {
            let meta = item?;
            report.scanned += 1;
            let relative = meta
                .key
                .strip_prefix(repo_prefix.as_str())
                .unwrap_or(meta.key.as_str())
                .to_string();
            if named.contains(&relative) || named.contains(&meta.key) {
                report.live += 1;
                continue;
            }
            let marker_key = marker_key(&repo_prefix, &relative);
            let Some(first_seen) = first_seen(wal, &marker_key, now).await? else {
                // Another pass created the marker first; treat as young.
                report.young += 1;
                continue;
            };
            if now.saturating_sub(first_seen) < grace_ms {
                report.young += 1;
                continue;
            }
            match wal.store().delete(&meta.key, None).await {
                Ok(()) => {}
                Err(error) if error.is_not_found() => {}
                Err(error) => return Err(error.into()),
            }
            let _ = wal.store().delete(&marker_key, None).await;
            report.deleted.push(meta.key);
        }
    }

    // Bundle keys sit under their ref path, not under `wal/`. Scan the repo
    // prefix only for `.bundle` objects and apply the same grace period, so a
    // superseded bundle is never deleted by a publish that another host is
    // still racing.
    let mut stream = wal.store().list(&repo_prefix, None);
    while let Some(item) = stream.next().await {
        let meta = item?;
        if !meta.key.ends_with(".bundle") {
            continue;
        }
        report.scanned += 1;
        let relative = meta
            .key
            .strip_prefix(repo_prefix.as_str())
            .unwrap_or(meta.key.as_str())
            .to_string();
        if named.contains(&relative) || named.contains(&meta.key) {
            report.live += 1;
            continue;
        }
        let marker_key = marker_key(&repo_prefix, &relative);
        let Some(first_seen) = first_seen(wal, &marker_key, now).await? else {
            report.young += 1;
            continue;
        };
        if now.saturating_sub(first_seen) < grace_ms {
            report.young += 1;
            continue;
        }
        match wal.store().delete(&meta.key, None).await {
            Ok(()) => {}
            Err(error) if error.is_not_found() => {}
            Err(error) => return Err(error.into()),
        }
        let _ = wal.store().delete(&marker_key, None).await;
        report.deleted.push(meta.key);
    }
    Ok(report)
}

fn marker_key(repo_prefix: &str, relative: &str) -> String {
    format!("{repo_prefix}gc/seen/{}.json", relative.replace('/', "_"))
}

/// First-seen timestamp for a key, creating the marker when absent.
async fn first_seen<C: ManifestCodec>(
    wal: &Wal<C>,
    marker_key: &str,
    now: u64,
) -> Result<Option<u64>, WalError> {
    #[derive(Serialize, Deserialize)]
    struct Marker {
        first_seen_unix_ms: u64,
    }
    if let Some((_, bytes)) = wal.store().get_bytes(marker_key).await? {
        let marker: Marker = serde_json::from_slice(&bytes)?;
        return Ok(Some(marker.first_seen_unix_ms));
    }
    let marker = Marker {
        first_seen_unix_ms: now,
    };
    match wal
        .store()
        .put_bytes(marker_key, serde_json::to_vec(&marker)?, PutMode::Create)
        .await
    {
        Ok(_) => Ok(Some(now)),
        Err(error) if error.is_precondition_failed() => {
            match wal.store().get_bytes(marker_key).await? {
                Some((_, bytes)) => {
                    let marker: Marker = serde_json::from_slice(&bytes)?;
                    Ok(Some(marker.first_seen_unix_ms))
                }
                None => Ok(None),
            }
        }
        Err(error) => Err(error.into()),
    }
}

/// Live and retired pack checksums, for callers that need the protected set.
pub fn protected_packs(state: &ManifestState) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for pack in &state.packs {
        out.insert(pack.checksum.clone());
    }
    for pack in &state.retired_packs {
        out.insert(pack.checksum.clone());
    }
    out
}

// ---------------------------------------------------------------------------
// repair
// ---------------------------------------------------------------------------

/// Fetch missing objects from `source`, install them as a live pack, and
/// update `fsck.json`.
pub async fn repair<C: ManifestCodec>(
    wal: &Wal<C>,
    slug: &str,
    source: &dyn RepairSource,
) -> Result<RepairOutcome, WalError> {
    let _lease = take_lease(wal, slug).await?;
    let _lock = wal.sync().lock(slug).await;
    let mirror = wal.ensure_synced_locked(slug).await?;
    let report = fsck_at(wal, slug, &mirror).await?;
    let mut outcome = RepairOutcome {
        seq: report.seq,
        missing: report.missing.clone(),
        installed: None,
    };
    if report.missing.is_empty() {
        return Ok(outcome);
    }
    let Some(pack) = source.fetch_pack(&report.missing).await? else {
        return Ok(outcome);
    };
    let options = IngestOptions {
        fsck: true,
        max_bytes: Some(wal.config().limits.max_push_bytes),
        thin: true,
    };
    let Some(installed) = ingest_pack(&mirror, &pack, &options).await? else {
        return Ok(outcome);
    };
    let pack_ref = publish_ingested(wal, slug, &installed).await?;
    let tips: Vec<String> = {
        let Some((manifest, _)) = wal.load_manifest(slug).await? else {
            return Err(WalError::NotFound(slug.to_string()));
        };
        wal.codec()
            .state(&manifest)
            .refs
            .values()
            .map(|entry| entry.sha.clone())
            .collect()
    };
    let remaining = match check_connectivity(&mirror, &tips, false).await {
        Ok(()) => Vec::new(),
        Err(GitError::MissingObject { oid }) => vec![oid],
        Err(error) => return Err(error.into()),
    };
    let repaired = FsckReport {
        missing_total: remaining.len() as u64,
        missing: remaining,
        repaired_seq: Some(report.seq),
        ..report
    };
    put_report(wal, slug, &repaired).await?;
    outcome.installed = Some(pack_ref);
    Ok(outcome)
}

async fn publish_ingested<C: ManifestCodec>(
    wal: &Wal<C>,
    slug: &str,
    installed: &IngestedPack,
) -> Result<PackRef, WalError> {
    let layout = &wal.config().layout;
    put_immutable_file(
        wal,
        &layout.pack_key(slug, &installed.checksum, "pack"),
        &installed.pack_path,
    )
    .await?;
    put_immutable_file(
        wal,
        &layout.pack_key(slug, &installed.checksum, "idx"),
        &installed.idx_path,
    )
    .await?;
    let has_rev = match &installed.rev_path {
        Some(path) => {
            put_immutable_file(
                wal,
                &layout.pack_key(slug, &installed.checksum, "rev"),
                path,
            )
            .await?;
            true
        }
        None => false,
    };
    let attempts = wal.config().publish_retries.max(1);
    for _ in 0..attempts {
        let Some((manifest, version)) = wal.load_manifest(slug).await? else {
            return Err(WalError::NotFound(slug.to_string()));
        };
        let state = wal.codec().state(&manifest);
        if let Some(existing) = state
            .packs
            .iter()
            .find(|pack| pack.checksum == installed.checksum)
        {
            return Ok(existing.clone());
        }
        let pack = PackRef {
            checksum: installed.checksum.clone(),
            pack_size: installed.pack_size,
            idx_size: installed.idx_size,
            object_count: installed.object_count,
            seq: state.seq,
            tier: 0,
            has_rev,
            has_bitmap: false,
            has_commit_graph: false,
            kind: PackKind::Objects,
        };
        let mut next = state.clone();
        next.packs.push(pack.clone());
        let next_manifest = wal.codec().from_state(next)?;
        match wal
            .write_manifest(slug, &next_manifest, PutMode::Update(version))
            .await
        {
            Ok(_) => return Ok(pack),
            Err(WalError::Store(error)) if error.is_precondition_failed() => continue,
            Err(error) => return Err(error),
        }
    }
    Err(WalError::RetryExhausted {
        slug: slug.to_string(),
        attempts,
    })
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

async fn take_lease<C: ManifestCodec>(wal: &Wal<C>, slug: &str) -> Result<LeaseGuard, WalError> {
    let request = LeaseRequest::new(MAINTENANCE_LEASE)
        .purpose("maintenance")
        .ttl(wal.config().lease_ttl)
        .wait(Duration::from_secs(30));
    match lease::acquire(wal, slug, &request).await? {
        Some(guard) => Ok(guard),
        None => Err(MaintenanceError::LeaseHeld {
            name: MAINTENANCE_LEASE.to_string(),
        }
        .into()),
    }
}

pub(crate) fn now_rfc3339() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
}

pub(crate) fn hostname() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "unknown".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Layout, WalConfig};
    use crate::manifest::{LogSegmentRef, ManifestRef, RefsCodec};
    use crate::store::{MemoryStore, PutBody, PutOptions};
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use std::process::Command;
    use std::sync::Arc;

    fn wal(storage: StorageMode, retention_grace: Duration) -> Wal<RefsCodec> {
        let store = Arc::new(MemoryStore::new());
        let mut config = WalConfig::new(
            crate::config::tmp_path("s3-wal-maint-repos"),
            Layout::new("git"),
        );
        config.storage = storage;
        config.retention_grace = retention_grace;
        Wal::new(store, Arc::new(config), Arc::new(RefsCodec))
    }

    fn live_pack(checksum: &str, seq: u64, tier: u32) -> PackRef {
        PackRef {
            checksum: checksum.to_string(),
            pack_size: 100,
            idx_size: 10,
            object_count: 1,
            seq,
            tier,
            has_rev: false,
            has_bitmap: false,
            has_commit_graph: false,
            kind: PackKind::Objects,
        }
    }

    async fn seed_manifest(wal: &Wal<RefsCodec>, state: ManifestState) {
        let manifest = RefsCodec.from_state(state).unwrap();
        let bytes = RefsCodec.encode(&manifest).unwrap();
        wal.store()
            .put_bytes(&wal.manifest_key("demo"), bytes, PutMode::Create)
            .await
            .unwrap();
    }

    fn run_git_in(dir: &Path, args: &[&str]) -> String {
        let output = Command::new("git")
            .args(args)
            .current_dir(dir)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("HOME", "/nonexistent")
            .output()
            .expect("git runs");
        assert!(
            output.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).into_owned()
    }

    /// A real worktree commit plus a bare mirror clone. Returns (mirror, tip).
    fn real_repo(prefix: &str) -> (PathBuf, String) {
        let work = crate::config::tmp_path(&format!("{prefix}-work"));
        std::fs::create_dir_all(&work).unwrap();
        run_git_in(&work, &["init", "-q", "-b", "main"]);
        run_git_in(&work, &["config", "user.email", "test@example.com"]);
        run_git_in(&work, &["config", "user.name", "Test"]);
        std::fs::write(work.join("file.txt"), "hello\n").unwrap();
        run_git_in(&work, &["add", "file.txt"]);
        run_git_in(&work, &["commit", "-q", "-m", "one"]);
        std::fs::write(work.join("file.txt"), "hello\nworld\n").unwrap();
        run_git_in(&work, &["commit", "-q", "-am", "two"]);
        let tip = run_git_in(&work, &["rev-parse", "HEAD"]).trim().to_string();

        let mirror = crate::config::tmp_path(&format!("{prefix}-mirror.git"));
        run_git_in(
            &work,
            &[
                "clone",
                "-q",
                "--bare",
                work.to_str().unwrap(),
                mirror.to_str().unwrap(),
            ],
        );
        (mirror, tip)
    }

    fn pack_mode_manifest(tip: &str, seq: u64, packs: Vec<PackRef>) -> ManifestState {
        ManifestState {
            seq,
            refs: BTreeMap::from([("refs/heads/main".to_string(), ManifestRef::pack(tip))]),
            packs,
            ..ManifestState::default()
        }
    }

    #[tokio::test]
    async fn fsck_reports_healthy_repo() {
        let wal = wal(StorageMode::Pack, Duration::from_secs(60));
        let (mirror, tip) = real_repo("fsck");
        seed_manifest(&wal, pack_mode_manifest(&tip, 3, Vec::new())).await;

        let report = fsck_at(&wal, "demo", &mirror).await.unwrap();
        assert_eq!(report.seq, 3);
        assert!(report.is_healthy(), "{report:?}");
        assert_eq!(report.missing_total, 0);
        assert!(!report.at.is_empty());

        let stored = read_fsck_report(&wal, "demo").await.unwrap().unwrap();
        assert_eq!(stored, report);
        assert!(wal
            .store()
            .exists(&wal.config().layout.fsck_key("demo"))
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn compaction_uploads_pack_and_retires_superseded() {
        let wal = wal(StorageMode::Pack, Duration::from_secs(60));
        let (mirror, tip) = real_repo("compact");
        let old = live_pack(&"e".repeat(40), 1, 0);
        seed_manifest(&wal, pack_mode_manifest(&tip, 4, vec![old.clone()])).await;

        let new = compact_at(&wal, "demo", &mirror, CompactOptions::default())
            .await
            .unwrap()
            .expect("compaction produced a pack");
        assert_eq!(new.tier, 1);
        assert_eq!(new.kind, PackKind::History);
        assert_eq!(new.seq, 4);
        assert!(new.object_count >= 2, "{new:?}");
        assert!(new.pack_size > 0 && new.idx_size > 0);

        let layout = &wal.config().layout;
        for extension in ["pack", "idx"] {
            let key = layout.pack_key("demo", &new.checksum, extension);
            assert!(
                wal.store().exists(&key).await.unwrap(),
                "missing {key} in the store"
            );
        }

        let manifest = wal.read_manifest("demo").await.unwrap().unwrap();
        let state = RefsCodec.state(&manifest);
        assert_eq!(state.seq, 4);
        assert_eq!(state.packs.len(), 1);
        assert_eq!(state.packs[0].checksum, new.checksum);
        assert_eq!(state.retired_packs.len(), 1);
        assert_eq!(state.retired_packs[0].checksum, old.checksum);

        // Without `force` a compacted singleton is left alone.
        assert!(compact_at(&wal, "demo", &mirror, CompactOptions::default())
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn compaction_reports_bundle_mode() {
        let wal = wal(StorageMode::Bundle, Duration::from_secs(60));
        let (mirror, tip) = real_repo("bundle-mode");
        seed_manifest(&wal, pack_mode_manifest(&tip, 1, Vec::new())).await;
        let error = compact_at(&wal, "demo", &mirror, CompactOptions::default())
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            WalError::Other(error) if error.to_string().contains("pack storage")
        ));
    }

    #[tokio::test]
    async fn retire_moves_live_packs_and_keeps_bytes_named() {
        let wal = wal(StorageMode::Pack, Duration::from_secs(60));
        let pack = live_pack(&"a".repeat(40), 1, 0);
        seed_manifest(
            &wal,
            ManifestState {
                seq: 2,
                refs: BTreeMap::from([(
                    "refs/heads/main".to_string(),
                    ManifestRef::pack("b".repeat(40)),
                )]),
                packs: vec![pack.clone()],
                ..ManifestState::default()
            },
        )
        .await;

        let retired = retire_at(&wal, "demo", std::slice::from_ref(&pack.checksum))
            .await
            .unwrap();
        assert_eq!(retired.len(), 1);
        assert_eq!(retired[0].checksum, pack.checksum);

        let manifest = wal.read_manifest("demo").await.unwrap().unwrap();
        let state = RefsCodec.state(&manifest);
        assert!(state.packs.is_empty());
        assert_eq!(state.retired_packs.len(), 1);

        // Retiring an unknown pack is a typed error.
        let error = retire_at(&wal, "demo", &["f".repeat(40)])
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            WalError::Other(error) if error.to_string().contains("not in the live set")
        ));

        // Already-retired packs are idempotent.
        let again = retire_at(&wal, "demo", std::slice::from_ref(&pack.checksum))
            .await
            .unwrap();
        assert!(again.is_empty());
    }

    #[tokio::test]
    async fn gc_collects_superseded_bundles_after_grace() {
        let wal = wal(StorageMode::Bundle, Duration::from_millis(1_000));
        let layout = wal.config().layout.clone();
        let live_sha = "a".repeat(40);
        let old_sha = "b".repeat(40);
        let live = layout.bundle_key("demo", "refs/heads/main", &live_sha);
        let old = layout.bundle_key("demo", "refs/heads/main", &old_sha);
        seed_manifest(
            &wal,
            ManifestState {
                seq: 2,
                refs: BTreeMap::from([(
                    "refs/heads/main".to_string(),
                    ManifestRef::bundle(live_sha.clone(), live.clone()),
                )]),
                ..ManifestState::default()
            },
        )
        .await;
        let store = wal.store().clone();
        for key in [&live, &old] {
            store
                .put_bytes(key, b"bundle".to_vec(), PutMode::Create)
                .await
                .unwrap();
        }

        let first = gc_at(&wal, "demo", 10_000).await.unwrap();
        assert!(first.deleted.is_empty(), "{first:?}");
        let second = gc_at(&wal, "demo", 11_000).await.unwrap();
        assert_eq!(second.deleted, vec![old.clone()], "{second:?}");
        assert!(store.exists(&live).await.unwrap());
        assert!(!store.exists(&old).await.unwrap());
    }

    #[tokio::test]
    async fn gc_keeps_live_retired_and_young_objects() {
        let wal = wal(StorageMode::Pack, Duration::from_millis(1_000));
        let layout = wal.config().layout.clone();
        let live = "a".repeat(40);
        let retired = "b".repeat(40);
        let orphan = "c".repeat(40);
        let live_log = layout.log_key("demo", 2);
        let orphan_log = layout.log_key("demo", 1);
        seed_manifest(
            &wal,
            ManifestState {
                seq: 2,
                refs: BTreeMap::from([(
                    "refs/heads/main".to_string(),
                    ManifestRef::pack("d".repeat(40)),
                )]),
                packs: vec![live_pack(&live, 2, 0)],
                retired_packs: vec![RetiredPack {
                    checksum: retired.clone(),
                    retired_at: now_rfc3339(),
                    retired_seq: 1,
                }],
                log: vec![LogSegmentRef {
                    key: live_log.clone(),
                    first_seq: 2,
                    last_seq: 2,
                    size: 5,
                    sealed: true,
                }],
                ..ManifestState::default()
            },
        )
        .await;

        let store = wal.store().clone();
        let objects = [
            layout.pack_key("demo", &live, "pack"),
            layout.pack_key("demo", &retired, "pack"),
            layout.pack_key("demo", &orphan, "pack"),
            live_log.clone(),
            orphan_log.clone(),
        ];
        for key in &objects {
            store
                .put_bytes(key, b"bytes".to_vec(), PutMode::Create)
                .await
                .unwrap();
        }

        // First pass only records first-seen markers; nothing is deleted.
        let first = gc_at(&wal, "demo", 10_000).await.unwrap();
        assert!(first.deleted.is_empty(), "{first:?}");
        assert_eq!(first.live, 3);
        assert_eq!(first.young, 2);

        // Exactly at the grace boundary the orphans go, live/retired stay.
        let second = gc_at(&wal, "demo", 11_000).await.unwrap();
        assert_eq!(second.deleted_count(), 2, "{second:?}");
        assert!(second
            .deleted
            .contains(&layout.pack_key("demo", &orphan, "pack")));
        assert!(second.deleted.contains(&orphan_log));
        for key in [
            layout.pack_key("demo", &live, "pack"),
            layout.pack_key("demo", &retired, "pack"),
            live_log.clone(),
        ] {
            assert!(store.exists(&key).await.unwrap(), "{key} was collected");
        }
        assert!(!store
            .exists(&layout.pack_key("demo", &orphan, "pack"))
            .await
            .unwrap());

        // A further pass has nothing left to do.
        let third = gc_at(&wal, "demo", 20_000).await.unwrap();
        assert!(third.deleted.is_empty());
    }

    #[tokio::test]
    async fn gc_spares_named_objects_when_marker_predates_them() {
        let wal = wal(StorageMode::Pack, Duration::from_millis(10));
        let layout = wal.config().layout.clone();
        let live = "a".repeat(40);
        let key = layout.pack_key("demo", &live, "pack");
        seed_manifest(
            &wal,
            ManifestState {
                seq: 1,
                refs: BTreeMap::from([(
                    "refs/heads/main".to_string(),
                    ManifestRef::pack("d".repeat(40)),
                )]),
                packs: vec![live_pack(&live, 1, 0)],
                ..ManifestState::default()
            },
        )
        .await;
        wal.store()
            .put(
                &key,
                PutBody::Bytes(bytes::Bytes::from_static(b"pack")),
                PutOptions::create(),
            )
            .await
            .unwrap();
        let report = gc_at(&wal, "demo", 1_000_000).await.unwrap();
        assert!(report.deleted.is_empty());
        assert!(wal.store().exists(&key).await.unwrap());
    }
}
