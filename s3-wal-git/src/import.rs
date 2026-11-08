//! Import a local git repository (working tree or bare) into the WAL.
//!
//! The source is fetched into the local bare mirror, connectivity is verified,
//! then the ref snapshot is handed to [`Wal::record_push_locked`] so the
//! immutable objects and the manifest CAS always go through the WAL. Nothing
//! here writes `MANIFEST.json` directly.
//!
//! Import is resumable. A small marker object records the intent (slug plus
//! hash of the source ref set), the phase (`started`, `verified`, `uploaded`),
//! every immutable object this import already uploaded, and the manifest
//! version the import was based on. Re-running against the same ref set is a
//! no-op; re-running after a failure skips finished uploads. If the target
//! moved while an interrupted import was parked, the import refuses unless
//! `force` is set.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config::{tmp_path, ObjectFormat, StorageMode};
use crate::error::{GitError, StoreError, WalError};
use crate::git::ingest::IngestOptions;
use crate::git::{
    check_connectivity, ingest_pack, is_ancestor, is_full_sha, validate_refname, validate_slug,
    IngestedPack, RefSnapshot, BUNDLE_TIMEOUT, QUICK_TIMEOUT,
};
use crate::manifest::ManifestCodec;
use crate::store::{ObjectStoreExt, PutBody, PutMode, PutOptions};
use crate::wal::{RecordOutcome, Wal};

const MARKER_VERSION: u8 = 1;
const MARKER_CONTENT_TYPE: &str = "application/json";

/// How the import stores objects. `None` uses the configured storage mode.
#[derive(Debug, Clone, Default)]
pub struct ImportOptions {
    pub mode: Option<StorageMode>,
    /// Overwrite a target ref that moved or diverged.
    pub force: bool,
    /// Run a full connectivity walk before uploading.
    pub verify: bool,
    /// Optional hard cap for one uploaded object, on top of config limits.
    pub max_bytes: Option<u64>,
    /// Recorded in logs/marker; has no manifest meaning yet.
    pub message: Option<String>,
}

/// Import lifecycle recorded in the marker object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ImportPhase {
    Started,
    Verified,
    Uploaded,
}

/// Resumable intent marker, stored under `git/<slug>/imports/<hash>.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportMarker {
    pub version: u8,
    pub slug: String,
    /// Hash of slug + storage mode + head + ref set.
    pub intent: String,
    /// Display form of the source (path or `bundle:<sha256>`).
    pub source: String,
    pub mode: String,
    /// Ref set this intent is allowed to publish.
    pub refs: BTreeMap<String, String>,
    pub head: Option<String>,
    pub peeled: BTreeMap<String, String>,
    pub phase: ImportPhase,
    /// Immutable object keys already uploaded by this import.
    pub done: BTreeSet<String>,
    /// Manifest version this import was based on (conflict/safety check).
    pub target_version: Option<String>,
    /// Publish sequence observed after the successful manifest write.
    pub target_seq: Option<u64>,
    pub message: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// Result of one import run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportReport {
    pub slug: String,
    pub mode: String,
    pub source: String,
    pub intent: String,
    pub marker_key: String,
    pub refs: BTreeMap<String, String>,
    pub head: Option<String>,
    pub seq: u64,
    /// Object keys uploaded by this run.
    pub uploaded: Vec<String>,
    pub bytes_uploaded: u64,
    /// The manifest already matched the source ref set.
    pub no_op: bool,
    /// The marker had finished uploads from an earlier run.
    pub resumed: bool,
}

/// Typed import failures.
#[derive(Debug, thiserror::Error)]
pub enum ImportError {
    #[error("invalid repository slug: {0}")]
    InvalidSlug(String),
    #[error("source repository does not exist: {0}")]
    SourceNotFound(String),
    #[error("source is not a git repository: {0}")]
    NotARepository(String),
    #[error("source repository is the target mirror: {0}")]
    SourceIsTarget(String),
    #[error("source repository has no refs to import")]
    EmptySource,
    #[error("this repository stores {configured}; import requested {requested}")]
    StorageMismatch {
        configured: &'static str,
        requested: &'static str,
    },
    #[error("source object id {oid} for {refname} is not a full {format} id")]
    BadObjectId {
        refname: String,
        oid: String,
        format: ObjectFormat,
    },
    #[error(
        "target ref {refname} moved: expected {expected}, found {actual}; pass force to overwrite"
    )]
    TargetMoved {
        refname: String,
        expected: String,
        actual: String,
    },
    #[error("ref {refname} would not fast-forward: {old} is not an ancestor of {new}; pass force")]
    NotFastForward {
        refname: String,
        old: String,
        new: String,
    },
    #[error("repository has {actual} refs; limit is {limit}")]
    TooManyRefs { actual: usize, limit: usize },
    #[error("{kind} is {size} bytes; limit is {limit}")]
    TooLarge { kind: String, size: u64, limit: u64 },
    #[error("missing object {oid} while importing {refname}")]
    MissingObject { refname: String, oid: String },
    #[error("import marker {key} is corrupt: {message}")]
    CorruptMarker { key: String, message: String },
    #[error(transparent)]
    Wal(#[from] WalError),
    #[error(transparent)]
    Git(#[from] GitError),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

/// Import the repository at `path` (working tree or bare) under `slug`.
pub async fn import_repo<C: ManifestCodec>(
    wal: &Wal<C>,
    slug: &str,
    path: impl AsRef<Path>,
    opts: &ImportOptions,
) -> Result<ImportReport, ImportError> {
    validate_slug(slug).map_err(|_| ImportError::InvalidSlug(slug.to_string()))?;
    let path = path.as_ref();
    if !path.exists() {
        return Err(ImportError::SourceNotFound(path.display().to_string()));
    }
    let source = snapshot_source(path, wal).await?;
    let display = canonical_display(path);
    import_snapshot(wal, slug, source, display, opts).await
}

/// Import a git bundle (`.bundle` bytes) under `slug`.
pub async fn import_bundle<C: ManifestCodec>(
    wal: &Wal<C>,
    slug: &str,
    bundle_bytes: &[u8],
) -> Result<ImportReport, ImportError> {
    import_bundle_with_options(wal, slug, bundle_bytes, &ImportOptions::default()).await
}

/// [`import_bundle`] with explicit options and a hard upload cap.
pub async fn import_bundle_with_options<C: ManifestCodec>(
    wal: &Wal<C>,
    slug: &str,
    bundle_bytes: &[u8],
    opts: &ImportOptions,
) -> Result<ImportReport, ImportError> {
    validate_slug(slug).map_err(|_| ImportError::InvalidSlug(slug.to_string()))?;
    let digest = hex::encode(Sha256::digest(bundle_bytes));
    let staged = TempDir::new("import-bundle-src")?;
    let bundle_path = staged.path.join("input.bundle");
    tokio::fs::write(&bundle_path, bundle_bytes).await?;
    let bare = staged.path.join("repo.git");
    let bare_str = path_str(&bare)?;
    crate::git::run_git(&["init", "--bare", bare_str], &[], QUICK_TIMEOUT)
        .await
        .map_err(|_| ImportError::NotARepository("bundle".into()))?;
    let git_dir = format!("--git-dir={}", bare.display());
    let bundle_str = path_str(&bundle_path)?;
    crate::git::run_git(
        &[
            &git_dir,
            "fetch",
            "--force",
            bundle_str,
            "+refs/heads/*:refs/heads/*",
            "+refs/tags/*:refs/tags/*",
        ],
        &[],
        BUNDLE_TIMEOUT,
    )
    .await?;
    // A bundle may record HEAD; otherwise pick the configured/default branch.
    if source_head(&bare).await?.is_none() {
        if let Some(branch) = first_branch(&bare).await? {
            crate::git::run_git(
                &[&git_dir, "symbolic-ref", "HEAD", &branch],
                &[],
                QUICK_TIMEOUT,
            )
            .await?;
        }
    }
    if let Some(max) = opts.max_bytes {
        if bundle_bytes.len() as u64 > max {
            return Err(ImportError::TooLarge {
                kind: "bundle input".into(),
                size: bundle_bytes.len() as u64,
                limit: max,
            });
        }
    }
    let source = snapshot_source(&bare, wal).await?;
    let display = format!("bundle:{digest}");
    import_snapshot(wal, slug, source, display, opts).await
}

#[derive(Debug)]
struct SourceRepo {
    /// Git repository the mirror should fetch from (survives until import).
    fetch: PathBuf,
    refs: BTreeMap<String, String>,
    head: Option<String>,
    peeled: BTreeMap<String, String>,
}

async fn snapshot_source<C: ManifestCodec>(
    path: &Path,
    wal: &Wal<C>,
) -> Result<SourceRepo, ImportError> {
    let path_str = path_str(path)?;
    // Cheap repository probe so a plain directory is a typed error.
    if crate::git::run_git(
        &["-C", path_str, "rev-parse", "--git-dir"],
        &[],
        QUICK_TIMEOUT,
    )
    .await
    .is_err()
    {
        return Err(ImportError::NotARepository(path.display().to_string()));
    }

    let mut prefixes: Vec<String> = vec!["refs/heads/".into(), "refs/tags/".into()];
    for extra in &wal.config().extra_ref_prefixes {
        let mut prefix = extra.clone();
        if !prefix.ends_with('/') {
            prefix.push('/');
        }
        if !prefixes.contains(&prefix) {
            prefixes.push(prefix);
        }
    }

    let mut refs = BTreeMap::new();
    let mut peeled = BTreeMap::new();
    for prefix in &prefixes {
        let out = crate::git::run_git(
            &[
                "-C",
                path_str,
                "for-each-ref",
                "--format=%(objectname) %(*objectname) %(refname)",
                prefix,
            ],
            &[],
            QUICK_TIMEOUT,
        )
        .await?;
        for line in out.lines() {
            let mut parts = line.splitn(3, ' ');
            let Some(oid) = parts.next() else { continue };
            let Some(target) = parts.next() else { continue };
            let Some(refname) = parts.next() else {
                continue;
            };
            let refname = refname.trim();
            if refname.is_empty() {
                continue;
            }
            validate_refname(refname)?;
            let oid = oid.trim().to_lowercase();
            if !is_full_sha(&oid, wal.config().object_format) {
                return Err(ImportError::BadObjectId {
                    refname: refname.to_string(),
                    oid,
                    format: wal.config().object_format,
                });
            }
            refs.insert(refname.to_string(), oid);
            let target = target.trim().to_lowercase();
            if !target.is_empty() {
                peeled.insert(refname.to_string(), target);
            }
        }
    }

    // `only_refs` is an allow-list on the source side as well.
    if !wal.config().only_refs.is_empty() {
        refs.retain(|name, _| wal.config().only_refs.iter().any(|only| only == name));
        peeled.retain(|name, _| refs.contains_key(name));
    }

    let head = source_head(path)
        .await?
        .filter(|target| refs.contains_key(target));
    Ok(SourceRepo {
        fetch: path.to_path_buf(),
        refs,
        head,
        peeled,
    })
}

async fn source_head(path: &Path) -> Result<Option<String>, ImportError> {
    let path_str = path_str(path)?;
    match crate::git::run_git(
        &["-C", path_str, "symbolic-ref", "--quiet", "HEAD"],
        &[],
        QUICK_TIMEOUT,
    )
    .await
    {
        Ok(out) => {
            let value = out.trim();
            Ok((!value.is_empty()).then(|| value.to_string()))
        }
        Err(_) => Ok(None),
    }
}

async fn first_branch(bare: &Path) -> Result<Option<String>, ImportError> {
    let git_dir = format!("--git-dir={}", bare.display());
    let out = crate::git::run_git(
        &[
            &git_dir,
            "for-each-ref",
            "--format=%(refname)",
            "refs/heads/",
        ],
        &[],
        QUICK_TIMEOUT,
    )
    .await?;
    Ok(out
        .lines()
        .find(|line| !line.trim().is_empty())
        .map(|line| line.trim().to_string()))
}

fn canonical_display(path: &Path) -> String {
    std::fs::canonicalize(path)
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| path.display().to_string())
}

fn path_str(path: &Path) -> Result<&str, ImportError> {
    path.to_str()
        .ok_or_else(|| ImportError::NotARepository(path.display().to_string()))
}

fn mode_str(mode: StorageMode) -> &'static str {
    match mode {
        StorageMode::Bundle => "bundle",
        StorageMode::Pack => "pack",
    }
}

/// Marker key for an intent hash.
pub fn marker_key<C: ManifestCodec>(wal: &Wal<C>, slug: &str, intent: &str) -> String {
    format!(
        "{}imports/{intent}.json",
        wal.config().layout.repo_prefix(slug)
    )
}

/// Intent hash: slug, mode, head and the exact sorted ref set.
pub fn intent_hash(
    slug: &str,
    mode: StorageMode,
    head: Option<&str>,
    refs: &BTreeMap<String, String>,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(slug.as_bytes());
    hasher.update([0]);
    hasher.update(mode_str(mode).as_bytes());
    hasher.update([0]);
    hasher.update(head.unwrap_or("").as_bytes());
    hasher.update([0]);
    for (name, sha) in refs {
        hasher.update(name.as_bytes());
        hasher.update([0]);
        hasher.update(sha.as_bytes());
        hasher.update([0]);
    }
    hex::encode(hasher.finalize())
}

async fn read_marker(
    store: &dyn crate::store::ObjectStore,
    key: &str,
) -> Result<Option<ImportMarker>, ImportError> {
    let Some((_meta, bytes)) = store.get_bytes(key).await? else {
        return Ok(None);
    };
    if bytes.is_empty() {
        return Ok(None);
    }
    let marker: ImportMarker =
        serde_json::from_slice(&bytes).map_err(|error| ImportError::CorruptMarker {
            key: key.to_string(),
            message: error.to_string(),
        })?;
    if marker.version != MARKER_VERSION {
        return Err(ImportError::CorruptMarker {
            key: key.to_string(),
            message: format!("unsupported marker version {}", marker.version),
        });
    }
    Ok(Some(marker))
}

async fn write_marker(
    store: &dyn crate::store::ObjectStore,
    key: &str,
    marker: &mut ImportMarker,
) -> Result<(), ImportError> {
    marker.updated_at = Utc::now().to_rfc3339();
    let bytes = serde_json::to_vec(marker)?;
    store
        .put(
            key,
            PutBody::Bytes(bytes.into()),
            PutOptions {
                mode: PutMode::Overwrite,
                content_type: Some(MARKER_CONTENT_TYPE),
                immutable: false,
            },
        )
        .await?;
    Ok(())
}

async fn import_snapshot<C: ManifestCodec>(
    wal: &Wal<C>,
    slug: &str,
    source: SourceRepo,
    display: String,
    opts: &ImportOptions,
) -> Result<ImportReport, ImportError> {
    if source.refs.is_empty() {
        return Err(ImportError::EmptySource);
    }
    let mode = opts.mode.unwrap_or(wal.config().storage);
    if mode != wal.config().storage {
        return Err(ImportError::StorageMismatch {
            configured: mode_str(wal.config().storage),
            requested: mode_str(mode),
        });
    }
    // `init_repo` takes the slug lock itself, so run it before locking.
    if wal.load_manifest(slug).await?.is_none() {
        match wal.init_repo(slug).await {
            Ok(()) | Err(WalError::AlreadyExists(_)) => {}
            Err(error) => return Err(error.into()),
        }
    }
    let _guard = wal.sync().lock(slug).await;

    let loaded = wal.load_manifest(slug).await?;
    let (manifest, version) = loaded.ok_or_else(|| {
        ImportError::Wal(WalError::Corrupt(format!(
            "init_repo left no manifest for {slug}"
        )))
    })?;
    let current_refs: BTreeMap<String, String> = wal
        .codec()
        .refs(&manifest)
        .into_iter()
        .map(|(name, entry)| (name, entry.sha))
        .collect();
    let current_entries = wal.codec().refs_map(&manifest);
    let current_head = wal.codec().state(&manifest).head;
    let version_str = version.to_string();

    let head = source.head.clone().or_else(|| {
        let default_ref = format!("refs/heads/{}", wal.config().default_branch);
        source
            .refs
            .contains_key(&default_ref)
            .then_some(default_ref)
            .or_else(|| {
                source
                    .refs
                    .keys()
                    .find(|name| name.starts_with("refs/heads/"))
                    .cloned()
            })
    });
    let head = head.or_else(|| current_head.clone());

    let intent = intent_hash(slug, mode, head.as_deref(), &source.refs);
    let key = marker_key(wal, slug, &intent);
    let store = wal.store();
    let marker = read_marker(store.as_ref(), &key).await?;

    if source.refs.len() > wal.config().limits.max_refs {
        return Err(ImportError::TooManyRefs {
            actual: source.refs.len(),
            limit: wal.config().limits.max_refs,
        });
    }

    let matches = |refs: &BTreeMap<String, String>| -> bool {
        source
            .refs
            .iter()
            .all(|(name, sha)| refs.get(name).map(|cur| cur == sha).unwrap_or(false))
    };

    if matches(&current_refs) {
        // Crash after the manifest CAS, or a genuine re-run: nothing to do.
        let now = Utc::now().to_rfc3339();
        let mut marker = marker.unwrap_or_else(|| ImportMarker {
            version: MARKER_VERSION,
            slug: slug.to_string(),
            intent: intent.clone(),
            source: display.clone(),
            mode: mode_str(mode).to_string(),
            refs: source.refs.clone(),
            head: head.clone(),
            peeled: source.peeled.clone(),
            phase: ImportPhase::Uploaded,
            done: BTreeSet::new(),
            target_version: None,
            target_seq: None,
            message: opts.message.clone(),
            created_at: now.clone(),
            updated_at: now,
        });
        marker.phase = ImportPhase::Uploaded;
        marker.target_version = Some(version_str.clone());
        marker.target_seq = Some(wal.codec().seq(&manifest));
        marker.source = display.clone();
        write_marker(store.as_ref(), &key, &mut marker).await?;
        return Ok(ImportReport {
            slug: slug.to_string(),
            mode: mode_str(mode).to_string(),
            source: display,
            intent,
            marker_key: key,
            refs: source.refs,
            head,
            seq: wal.codec().seq(&manifest),
            uploaded: Vec::new(),
            bytes_uploaded: 0,
            no_op: true,
            resumed: false,
        });
    }

    let resumed = marker
        .as_ref()
        .is_some_and(|marker| !marker.done.is_empty());

    if let Some(marker) = &marker {
        if !opts.force {
            let target_moved = marker
                .target_version
                .as_deref()
                .is_some_and(|expected| expected != version_str)
                && marker.refs.iter().any(|(name, sha)| {
                    current_refs
                        .get(name)
                        .map(|current| current != sha)
                        .unwrap_or(true)
                });
            if target_moved {
                let (refname, expected) = marker
                    .refs
                    .iter()
                    .find(|(name, sha)| {
                        current_refs
                            .get(*name)
                            .map(|current| current != *sha)
                            .unwrap_or(true)
                    })
                    .map(|(name, sha)| (name.clone(), sha.clone()))
                    .unwrap_or_else(|| ("HEAD".to_string(), String::new()));
                return Err(ImportError::TargetMoved {
                    refname,
                    expected,
                    actual: version_str,
                });
            }
        }
    }

    // Start from a mirror that exactly matches the manifest: a failed earlier
    // run may have left fetched refs behind. An empty manifest with an
    // existing mirror is the one case rehydrate leaves untouched.
    let mirror = wal.mirror_path(slug);
    let source_path = std::fs::canonicalize(&source.fetch).ok();
    let mirror_path = std::fs::canonicalize(&mirror).ok();
    if source_path.is_some() && source_path == mirror_path {
        return Err(ImportError::SourceIsTarget(display));
    }
    if current_refs.is_empty() && mirror.join("HEAD").exists() {
        tokio::fs::remove_dir_all(&mirror).await?;
    }
    wal.rehydrate_locked(slug).await?;

    fetch_source(wal, &mirror, &source.fetch, &source.refs).await?;
    if let Some(head) = &head {
        let head_line = format!("ref: {head}\n");
        tokio::fs::write(mirror.join("HEAD"), head_line).await?;
    }

    let tips: Vec<String> = source.refs.values().cloned().collect();
    if opts.verify {
        check_connectivity(&mirror, &tips, false).await?;
    }

    if !opts.force {
        for (refname, sha) in &source.refs {
            let Some(current) = current_refs.get(refname) else {
                continue;
            };
            if current == sha {
                continue;
            }
            if refname.starts_with("refs/heads/") {
                if !is_ancestor(&mirror, current, sha).await {
                    return Err(ImportError::NotFastForward {
                        refname: refname.clone(),
                        old: current.clone(),
                        new: sha.clone(),
                    });
                }
            } else {
                return Err(ImportError::TargetMoved {
                    refname: refname.clone(),
                    expected: current.clone(),
                    actual: sha.clone(),
                });
            }
        }
    }

    let now = Utc::now().to_rfc3339();
    let mut marker = marker.unwrap_or_else(|| ImportMarker {
        version: MARKER_VERSION,
        slug: slug.to_string(),
        intent: intent.clone(),
        source: display.clone(),
        mode: mode_str(mode).to_string(),
        refs: source.refs.clone(),
        head: head.clone(),
        peeled: source.peeled.clone(),
        phase: ImportPhase::Started,
        done: BTreeSet::new(),
        target_version: None,
        target_seq: None,
        message: opts.message.clone(),
        created_at: now.clone(),
        updated_at: now,
    });
    // Ref set is immutable for this intent; refresh diagnostics fields.
    marker.refs = source.refs.clone();
    marker.head = head.clone();
    marker.peeled = source.peeled.clone();
    marker.source = display.clone();
    marker.mode = mode_str(mode).to_string();
    if marker.target_version.is_none() {
        marker.target_version = Some(version_str.clone());
    }
    marker.phase = ImportPhase::Started;
    write_marker(store.as_ref(), &key, &mut marker).await?;
    marker.phase = ImportPhase::Verified;
    write_marker(store.as_ref(), &key, &mut marker).await?;

    let mut uploaded = Vec::new();
    let mut bytes_uploaded = 0u64;
    let pack = match mode {
        StorageMode::Bundle => {
            prepare_bundles(
                wal,
                slug,
                &mirror,
                &source.refs,
                &current_entries,
                &mut marker,
                &key,
                opts,
                &mut uploaded,
                &mut bytes_uploaded,
            )
            .await?;
            None
        }
        StorageMode::Pack => Some(
            prepare_pack(
                wal,
                slug,
                &mirror,
                &mut marker,
                &key,
                opts,
                &mut uploaded,
                &mut bytes_uploaded,
            )
            .await?,
        ),
    };

    if wal.config().limits.max_repo_bytes > 0 {
        let total = repo_bytes(wal, slug, &manifest, bytes_uploaded).await?;
        if total > wal.config().limits.max_repo_bytes {
            return Err(ImportError::TooLarge {
                kind: "repository".into(),
                size: total,
                limit: wal.config().limits.max_repo_bytes,
            });
        }
    }

    // record_push classifies the delta between the snapshot taken before the
    // mirror changed and the mirror's current refs.
    let mut before_refs = current_refs.clone();
    if !wal.config().only_refs.is_empty() {
        before_refs.retain(|name, _| wal.config().only_refs.iter().any(|only| only == name));
    }
    let before = RefSnapshot {
        refs: before_refs,
        head: current_head.clone(),
        peeled: wal.codec().state(&manifest).peeled.clone(),
    };
    let outcome: RecordOutcome = wal.record_push_locked(slug, &before, pack).await?;

    let updated = wal.load_manifest(slug).await?;
    if let Some((manifest, version)) = updated {
        marker.target_version = Some(version.to_string());
        marker.target_seq = Some(outcome.seq.max(wal.codec().seq(&manifest)));
        for moved in &outcome.moved {
            if let Some(bundle) = &moved.bundle {
                marker.done.insert(bundle.clone());
            }
            if let Some(pack) = &moved.pack {
                marker.done.insert(pack.clone());
            }
        }
        marker.phase = ImportPhase::Uploaded;
        write_marker(store.as_ref(), &key, &mut marker).await?;
        Ok(ImportReport {
            slug: slug.to_string(),
            mode: mode_str(mode).to_string(),
            source: display,
            intent,
            marker_key: key,
            refs: source.refs,
            head,
            seq: outcome.seq,
            uploaded,
            bytes_uploaded,
            no_op: false,
            resumed,
        })
    } else {
        Err(ImportError::Wal(WalError::Corrupt(format!(
            "manifest for {slug} vanished after record_push"
        ))))
    }
}

async fn fetch_source<C: ManifestCodec>(
    wal: &Wal<C>,
    mirror: &Path,
    source: &Path,
    refs: &BTreeMap<String, String>,
) -> Result<(), ImportError> {
    let git_dir = format!("--git-dir={}", mirror.display());
    let mut args: Vec<String> = vec![
        git_dir,
        "fetch".into(),
        "--force".into(),
        "--no-auto-gc".into(),
    ];
    args.push(path_str(source)?.to_string());
    let only = wal.config().only_refs.clone();
    if only.is_empty() {
        args.push("+refs/heads/*:refs/heads/*".into());
        args.push("+refs/tags/*:refs/tags/*".into());
        for extra in &wal.config().extra_ref_prefixes {
            let mut prefix = extra.clone();
            if !prefix.ends_with('/') {
                prefix.push('/');
            }
            args.push(format!("+{prefix}*:{prefix}*"));
        }
    } else {
        for refname in only {
            if refs.contains_key(&refname) {
                args.push(format!("+{refname}:{refname}"));
            }
        }
    }
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    crate::git::run_git(&refs, &[], BUNDLE_TIMEOUT).await?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn prepare_bundles<C: ManifestCodec>(
    wal: &Wal<C>,
    slug: &str,
    mirror: &Path,
    refs: &BTreeMap<String, String>,
    current: &BTreeMap<String, crate::manifest::ManifestRef>,
    marker: &mut ImportMarker,
    marker_key: &str,
    opts: &ImportOptions,
    uploaded: &mut Vec<String>,
    bytes_uploaded: &mut u64,
) -> Result<(), ImportError> {
    let store = wal.store();
    let git_dir = format!("--git-dir={}", mirror.display());
    for (refname, sha) in refs {
        let needs_bundle = current
            .get(refname)
            .map(|entry| entry.sha != *sha || entry.bundle.is_none())
            .unwrap_or(true);
        if !needs_bundle {
            continue;
        }
        let key = wal.config().layout.bundle_key(slug, refname, sha);
        if marker.done.contains(&key) {
            continue;
        }
        let staged = TempFile::new("import-bundle")?;
        let bundle_str = path_str(&staged.path)?;
        crate::git::run_git(
            &[&git_dir, "bundle", "create", bundle_str, refname],
            &[],
            BUNDLE_TIMEOUT,
        )
        .await?;
        crate::git::run_git(
            &[&git_dir, "bundle", "verify", bundle_str],
            &[],
            BUNDLE_TIMEOUT,
        )
        .await?;
        let bytes = tokio::fs::read(&staged.path).await?;
        let size = bytes.len() as u64;
        check_limit(
            &format!("bundle for {refname}"),
            size,
            effective_limit(wal.config().limits.max_bundle_bytes, opts.max_bytes),
        )?;
        if upload_object(
            store.as_ref(),
            &key,
            PutBody::Bytes(bytes.into()),
            marker,
            marker_key,
        )
        .await?
        {
            uploaded.push(key.clone());
            *bytes_uploaded += size;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn prepare_pack<C: ManifestCodec>(
    wal: &Wal<C>,
    slug: &str,
    mirror: &Path,
    marker: &mut ImportMarker,
    marker_key: &str,
    opts: &ImportOptions,
    uploaded: &mut Vec<String>,
    bytes_uploaded: &mut u64,
) -> Result<IngestedPack, ImportError> {
    let store = wal.store();
    let git_dir = format!("--git-dir={}", mirror.display());
    let dir = TempDir::new("import-pack")?;
    let base = dir.path.join("full");
    let base_str = path_str(&base)?;
    let out = crate::git::run_git(
        &[&git_dir, "pack-objects", "--all", base_str],
        &[],
        BUNDLE_TIMEOUT,
    )
    .await?;
    let checksum = out
        .split_whitespace()
        .last()
        .map(str::to_string)
        .filter(|value| is_full_sha(value, wal.config().object_format))
        .ok_or_else(|| {
            ImportError::Git(GitError::Pack(format!(
                "pack-objects did not report a pack id: {out:?}"
            )))
        })?;
    let pack_path = dir.path.join(format!("full-{checksum}.pack"));
    let idx_path = dir.path.join(format!("full-{checksum}.idx"));
    let rev_path = dir.path.join(format!("full-{checksum}.rev"));
    let pack_size = tokio::fs::metadata(&pack_path).await?.len();
    let limit = effective_limit(wal.config().limits.max_push_bytes, opts.max_bytes);
    check_limit("full pack", pack_size, limit)?;

    let pack_key = wal.config().layout.pack_key(slug, &checksum, "pack");
    let idx_key = wal.config().layout.pack_key(slug, &checksum, "idx");
    let rev_key = wal.config().layout.pack_key(slug, &checksum, "rev");
    if !marker.done.contains(&pack_key)
        && upload_object(
            store.as_ref(),
            &pack_key,
            PutBody::File(pack_path.clone()),
            marker,
            marker_key,
        )
        .await?
    {
        uploaded.push(pack_key.clone());
        *bytes_uploaded += pack_size;
    }
    let idx_size = tokio::fs::metadata(&idx_path).await?.len();
    if !marker.done.contains(&idx_key)
        && upload_object(
            store.as_ref(),
            &idx_key,
            PutBody::File(idx_path.clone()),
            marker,
            marker_key,
        )
        .await?
    {
        uploaded.push(idx_key.clone());
        *bytes_uploaded += idx_size;
    }
    if rev_path.exists() {
        let size = tokio::fs::metadata(&rev_path).await?.len();
        if !marker.done.contains(&rev_key)
            && upload_object(
                store.as_ref(),
                &rev_key,
                PutBody::File(rev_path.clone()),
                marker,
                marker_key,
            )
            .await?
        {
            uploaded.push(rev_key.clone());
            *bytes_uploaded += size;
        }
    }

    // Index the pack in the mirror so record_push can name the exact bytes.
    let bytes = tokio::fs::read(&pack_path).await?;
    let ingested = ingest_pack(
        mirror,
        &bytes,
        &IngestOptions {
            fsck: opts.verify,
            max_bytes: Some(limit).filter(|limit| *limit > 0),
            thin: false,
        },
    )
    .await?
    .ok_or_else(|| ImportError::Git(GitError::Pack("empty import pack".into())))?;
    if ingested.checksum != checksum {
        return Err(ImportError::Git(GitError::Pack(format!(
            "pack checksum changed: built {checksum}, ingested {}",
            ingested.checksum
        ))));
    }
    Ok(ingested)
}

fn effective_limit(config: u64, override_limit: Option<u64>) -> u64 {
    match (config, override_limit) {
        (0, None) => 0,
        (0, Some(limit)) => limit,
        (config, None) => config,
        (config, Some(limit)) => config.min(limit),
    }
}

fn check_limit(kind: &str, size: u64, limit: u64) -> Result<(), ImportError> {
    if limit > 0 && size > limit {
        Err(ImportError::TooLarge {
            kind: kind.to_string(),
            size,
            limit,
        })
    } else {
        Ok(())
    }
}

/// Put an immutable object with `Create`; an existing key is success.
async fn upload_object(
    store: &dyn crate::store::ObjectStore,
    key: &str,
    body: PutBody,
    marker: &mut ImportMarker,
    marker_key: &str,
) -> Result<bool, ImportError> {
    let result = store
        .put(
            key,
            body,
            PutOptions {
                mode: PutMode::Create,
                content_type: None,
                immutable: true,
            },
        )
        .await;
    match result {
        Ok(_) => {
            marker.done.insert(key.to_string());
            write_marker(store, marker_key, marker).await?;
            Ok(true)
        }
        Err(StoreError::PreconditionFailed { .. }) => {
            marker.done.insert(key.to_string());
            write_marker(store, marker_key, marker).await?;
            Ok(false)
        }
        Err(error) => Err(ImportError::Store(error)),
    }
}

async fn repo_bytes<C: ManifestCodec>(
    wal: &Wal<C>,
    _slug: &str,
    manifest: &C::Manifest,
    extra: u64,
) -> Result<u64, ImportError> {
    let store = wal.store();
    let mut total = extra;
    for (_name, entry) in wal.codec().refs(manifest) {
        if let Some(key) = entry.bundle {
            if let Some(meta) = store.head(&key).await? {
                total = total.saturating_add(meta.size);
            }
        }
    }
    let state = wal.codec().state(manifest);
    for pack in state.packs {
        total = total
            .saturating_add(pack.pack_size)
            .saturating_add(pack.idx_size);
    }
    Ok(total)
}

struct TempFile {
    path: PathBuf,
}

impl TempFile {
    fn new(prefix: &str) -> Result<Self, ImportError> {
        let path = tmp_path(prefix);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        Ok(Self { path })
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(prefix: &str) -> Result<Self, ImportError> {
        let path = tmp_path(prefix);
        std::fs::create_dir_all(&path)?;
        Ok(Self { path })
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Layout, WalConfig};
    use crate::git::{run_git, QUICK_TIMEOUT};
    use crate::manifest::RefsCodec;
    use crate::store::{FaultStore, MemoryStore};
    use std::sync::Arc;

    struct Source {
        dir: tempfile::TempDir,
        main: String,
        dev: String,
    }

    async fn git(args: &[&str]) -> String {
        run_git(args, &[], QUICK_TIMEOUT).await.expect("git")
    }

    async fn make_source() -> Source {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_str().unwrap();
        git(&["init", "-q", "-b", "main", path]).await;
        for message in ["one", "two"] {
            git(&[
                "-C",
                path,
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.com",
                "commit",
                "-q",
                "--allow-empty",
                "-m",
                message,
            ])
            .await;
        }
        git(&["-C", path, "branch", "dev"]).await;
        git(&[
            "-C",
            path,
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.com",
            "tag",
            "-a",
            "v1",
            "-m",
            "v1",
        ])
        .await;
        let main = git(&["-C", path, "rev-parse", "refs/heads/main"])
            .await
            .trim()
            .to_string();
        let dev = git(&["-C", path, "rev-parse", "refs/heads/dev"])
            .await
            .trim()
            .to_string();
        Source { dir, main, dev }
    }

    fn wal_with(store: crate::store::DynStore, repos: &Path) -> Wal<RefsCodec> {
        let config = WalConfig::new(repos, Layout::new("git"));
        Wal::new(store, Arc::new(config), Arc::new(RefsCodec))
    }

    #[tokio::test]
    async fn import_export_roundtrip_keeps_refs() {
        let source = make_source().await;
        let repos = tempfile::tempdir().unwrap();
        let wal = wal_with(Arc::new(MemoryStore::new()), repos.path());

        let report = import_repo(&wal, "demo", source.dir.path(), &ImportOptions::default())
            .await
            .unwrap();
        assert!(!report.no_op);
        assert_eq!(report.refs.get("refs/heads/main"), Some(&source.main));
        assert_eq!(report.refs.get("refs/heads/dev"), Some(&source.dev));
        assert_eq!(report.head.as_deref(), Some("refs/heads/main"));
        assert!(report.uploaded.iter().any(|key| key.ends_with(".bundle")));

        let again = import_repo(&wal, "demo", source.dir.path(), &ImportOptions::default())
            .await
            .unwrap();
        assert!(again.no_op, "re-running a completed import must be a no-op");

        let out = repos.path().join("export.bundle");
        let export = crate::export::export_to_path(&wal, "demo", &out)
            .await
            .unwrap();
        assert_eq!(export.refs.get("refs/heads/main"), Some(&source.main));

        // Materialise the export and compare every ref.
        let check = tempfile::tempdir().unwrap();
        let check_path = check.path().to_str().unwrap();
        git(&["init", "-q", "--bare", check_path]).await;
        git(&[
            "--git-dir",
            check_path,
            "fetch",
            "-q",
            out.to_str().unwrap(),
            "+refs/*:refs/*",
        ])
        .await;
        let refs = git(&["--git-dir", check_path, "show-ref"]).await;
        let map: BTreeMap<String, String> = refs
            .lines()
            .filter_map(|line| line.split_once(' '))
            .map(|(sha, name)| (name.trim().to_string(), sha.to_string()))
            .collect();
        assert_eq!(map.get("refs/heads/main"), Some(&source.main));
        assert_eq!(map.get("refs/heads/dev"), Some(&source.dev));
    }

    #[tokio::test]
    async fn import_resumes_after_upload_failure() {
        let source = make_source().await;
        let repos = tempfile::tempdir().unwrap();
        let fault = FaultStore::new(Arc::new(MemoryStore::new()));
        let wal = wal_with(Arc::new(fault.clone()), repos.path());

        let bundle_key = wal
            .config()
            .layout
            .bundle_key("demo", "refs/heads/main", &source.main);
        fault.fail_key(bundle_key.clone(), 1, "simulated upload failure");

        let error = import_repo(&wal, "demo", source.dir.path(), &ImportOptions::default())
            .await
            .unwrap_err();
        assert!(matches!(error, ImportError::Store(_)), "{error:?}");

        let report = import_repo(&wal, "demo", source.dir.path(), &ImportOptions::default())
            .await
            .unwrap();
        assert!(!report.no_op);
        assert!(
            report.uploaded.contains(&bundle_key),
            "the previously failed object must be uploaded on resume"
        );
        assert_eq!(report.refs.get("refs/heads/main"), Some(&source.main));

        // Marker reached the uploaded phase with the finished object.
        let intent = report.intent.clone();
        let key = marker_key(&wal, "demo", &intent);
        let marker = read_marker(wal.store().as_ref(), &key)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(marker.phase, ImportPhase::Uploaded);
        assert!(marker.done.contains(&bundle_key));
    }

    #[tokio::test]
    async fn import_bundle_bytes_roundtrip() {
        let source = make_source().await;
        let bundle_path = source.dir.path().join("source.bundle");
        git(&[
            "-C",
            source.dir.path().to_str().unwrap(),
            "bundle",
            "create",
            bundle_path.to_str().unwrap(),
            "--all",
            "HEAD",
        ])
        .await;
        let bytes = tokio::fs::read(&bundle_path).await.unwrap();

        let repos = tempfile::tempdir().unwrap();
        let wal = wal_with(Arc::new(MemoryStore::new()), repos.path());
        let report = import_bundle(&wal, "demo", &bytes).await.unwrap();
        assert_eq!(report.refs.get("refs/heads/main"), Some(&source.main));
        assert!(report.source.starts_with("bundle:"));
    }

    #[tokio::test]
    async fn moved_target_requires_force() {
        let source = make_source().await;
        let repos = tempfile::tempdir().unwrap();
        let wal = wal_with(Arc::new(MemoryStore::new()), repos.path());
        import_repo(&wal, "demo", source.dir.path(), &ImportOptions::default())
            .await
            .unwrap();

        // Rewind the source branch, which is not a fast-forward.
        let path = source.dir.path().to_str().unwrap();
        let first = git(&["-C", path, "rev-list", "--max-parents=0", "HEAD"])
            .await
            .trim()
            .to_string();
        git(&["-C", path, "reset", "--hard", &first]).await;

        let error = import_repo(&wal, "demo", source.dir.path(), &ImportOptions::default())
            .await
            .unwrap_err();
        assert!(
            matches!(error, ImportError::NotFastForward { .. }),
            "{error:?}"
        );

        let forced = ImportOptions {
            force: true,
            ..ImportOptions::default()
        };
        let report = import_repo(&wal, "demo", source.dir.path(), &forced)
            .await
            .unwrap();
        assert_eq!(report.refs.get("refs/heads/main"), Some(&first));
    }

    #[test]
    fn intent_changes_with_ref_set() {
        let refs = BTreeMap::from([("refs/heads/main".to_string(), "a".repeat(40))]);
        let first = intent_hash("demo", StorageMode::Bundle, Some("refs/heads/main"), &refs);
        let second = intent_hash("demo", StorageMode::Pack, Some("refs/heads/main"), &refs);
        assert_ne!(first, second);
        let mut other = refs.clone();
        other.insert("refs/heads/dev".into(), "b".repeat(40));
        assert_ne!(
            first,
            intent_hash("demo", StorageMode::Bundle, Some("refs/heads/main"), &other)
        );
    }
}
