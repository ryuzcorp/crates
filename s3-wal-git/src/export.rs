//! Export a WAL repository back to a local git bundle.
//!
//! Export reads the manifest (the only source of truth), verifies that every
//! immutable object the manifest names is present — and, by default, that the
//! pack/bundle checksums are intact — rebuilds the local mirror through the WAL
//! and writes one self-contained bundle. Nothing is inferred from local cache
//! state.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config::{tmp_path, ObjectFormat};
use crate::error::{GitError, StoreError, WalError};
use crate::git::{is_full_sha, validate_refname, BUNDLE_TIMEOUT, QUICK_TIMEOUT};
use crate::manifest::{ManifestCodec, ManifestRef, ManifestState};
use crate::store::{write_stream_atomic, GetOptions, GetResult};
use crate::wal::Wal;

/// Export knobs.
#[derive(Debug, Clone)]
pub struct ExportOptions {
    /// Re-hash stored packs and bundles before materialising the export.
    pub verify_checksums: bool,
}

impl Default for ExportOptions {
    fn default() -> Self {
        Self {
            verify_checksums: true,
        }
    }
}

/// Ref snapshot written as JSON by [`export_refs`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExportRefs {
    pub slug: String,
    pub seq: u64,
    pub version: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub head: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub peeled: BTreeMap<String, String>,
    pub refs: BTreeMap<String, String>,
}

/// Result of a bundle export.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportReport {
    pub slug: String,
    pub seq: u64,
    pub head: Option<String>,
    pub peeled: BTreeMap<String, String>,
    pub refs: BTreeMap<String, String>,
    pub path: Option<PathBuf>,
    pub bytes: u64,
    pub sha256: String,
    pub verified: bool,
}

/// Typed export failures.
#[derive(Debug, thiserror::Error)]
pub enum ExportError {
    #[error("repository {0} has no manifest")]
    NotFound(String),
    #[error("repository {0} has no refs to export")]
    EmptyRepository(String),
    #[error("manifest names missing {kind} object {key}")]
    MissingObject { kind: &'static str, key: String },
    #[error("ref {refname} points at {sha}, which is not a full {format} id")]
    BadObjectId {
        refname: String,
        sha: String,
        format: ObjectFormat,
    },
    #[error("manifest ref {refname} has neither a bundle nor a live pack")]
    UnbackedRef { refname: String },
    #[error("checksum verification failed for {key}: {message}")]
    Checksum { key: String, message: String },
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

/// Export `slug` to `path` as one self-contained git bundle.
pub async fn export_to_path<C: ManifestCodec>(
    wal: &Wal<C>,
    slug: &str,
    path: impl AsRef<Path>,
) -> Result<ExportReport, ExportError> {
    export_to_path_with(wal, slug, path, &ExportOptions::default()).await
}

/// [`export_to_path`] with explicit options.
pub async fn export_to_path_with<C: ManifestCodec>(
    wal: &Wal<C>,
    slug: &str,
    path: impl AsRef<Path>,
    opts: &ExportOptions,
) -> Result<ExportReport, ExportError> {
    let path = path.as_ref().to_path_buf();
    let _guard = wal.sync().lock(slug).await;
    let (manifest, _version) = wal
        .load_manifest(slug)
        .await?
        .ok_or_else(|| ExportError::NotFound(slug.to_string()))?;
    let refs_map = wal.codec().refs_map(&manifest);
    if refs_map.is_empty() {
        return Err(ExportError::EmptyRepository(slug.to_string()));
    }
    let state = wal.codec().state(&manifest);
    let refs = collect_refs(wal, &refs_map, &state)?;
    verify_objects(wal, slug, &refs_map, &state, opts.verify_checksums).await?;

    let mirror = wal.ensure_synced_locked(slug).await?;
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            tokio::fs::create_dir_all(parent).await?;
        }
    }
    let staged = StagedPath {
        path: path.clone(),
        keep: false,
    };
    create_bundle(&mirror, &staged.path, &refs, state.head.as_deref()).await?;

    let bytes = tokio::fs::read(&staged.path).await?;
    if opts.verify_checksums {
        verify_bundle(&mirror, &staged.path).await?;
    }
    let sha256 = hex::encode(Sha256::digest(&bytes));
    Ok(ExportReport {
        slug: slug.to_string(),
        seq: wal.codec().seq(&manifest),
        head: state.head,
        peeled: state.peeled,
        refs: refs
            .into_iter()
            .map(|(name, entry)| (name, entry.sha))
            .collect(),
        path: Some(staged.into_path()),
        bytes: bytes.len() as u64,
        sha256,
        verified: opts.verify_checksums,
    })
}

/// Export `slug` as bundle bytes (for tests and API callers).
pub async fn export_bundle<C: ManifestCodec>(
    wal: &Wal<C>,
    slug: &str,
) -> Result<Vec<u8>, ExportError> {
    export_bundle_with(wal, slug, &ExportOptions::default()).await
}

/// [`export_bundle`] with explicit options.
pub async fn export_bundle_with<C: ManifestCodec>(
    wal: &Wal<C>,
    slug: &str,
    opts: &ExportOptions,
) -> Result<Vec<u8>, ExportError> {
    let staged = StagedPath::temp("export-bundle")?;
    export_to_path_with(wal, slug, &staged.path, opts).await?;
    Ok(tokio::fs::read(&staged.path).await?)
}

/// The manifest refs as JSON-serializable data. No mirror is built.
pub async fn export_refs<C: ManifestCodec>(
    wal: &Wal<C>,
    slug: &str,
) -> Result<ExportRefs, ExportError> {
    let _guard = wal.sync().lock(slug).await;
    let (manifest, _version) = wal
        .load_manifest(slug)
        .await?
        .ok_or_else(|| ExportError::NotFound(slug.to_string()))?;
    let refs_map = wal.codec().refs_map(&manifest);
    let state = wal.codec().state(&manifest);
    let refs = collect_refs(wal, &refs_map, &state)?;
    verify_objects(wal, slug, &refs_map, &state, false).await?;
    Ok(ExportRefs {
        slug: slug.to_string(),
        seq: wal.codec().seq(&manifest),
        version: crate::manifest::MANIFEST_VERSION,
        head: state.head,
        peeled: state.peeled,
        refs: refs
            .into_iter()
            .map(|(name, entry)| (name, entry.sha))
            .collect(),
    })
}

/// [`export_refs`] encoded as JSON.
pub async fn export_refs_json<C: ManifestCodec>(
    wal: &Wal<C>,
    slug: &str,
) -> Result<Vec<u8>, ExportError> {
    Ok(serde_json::to_vec_pretty(&export_refs(wal, slug).await?)?)
}

fn collect_refs<C: ManifestCodec>(
    wal: &Wal<C>,
    refs: &BTreeMap<String, ManifestRef>,
    _state: &ManifestState,
) -> Result<BTreeMap<String, ManifestRef>, ExportError> {
    let format = wal.config().object_format;
    let mut out = BTreeMap::new();
    for (refname, entry) in refs {
        validate_refname(refname)?;
        if !is_full_sha(&entry.sha, format) {
            return Err(ExportError::BadObjectId {
                refname: refname.clone(),
                sha: entry.sha.clone(),
                format,
            });
        }
        out.insert(refname.clone(), entry.clone());
    }
    Ok(out)
}

/// Every object named by the manifest exists, and (optionally) verifies.
async fn verify_objects<C: ManifestCodec>(
    wal: &Wal<C>,
    slug: &str,
    refs: &BTreeMap<String, ManifestRef>,
    state: &ManifestState,
    deep: bool,
) -> Result<(), ExportError> {
    let store = wal.store();
    let has_packs = !state.packs.is_empty();
    for (refname, entry) in refs {
        if let Some(key) = &entry.bundle {
            if store.head(key).await?.is_none() {
                return Err(ExportError::MissingObject {
                    kind: "bundle",
                    key: key.clone(),
                });
            }
        } else if !has_packs {
            return Err(ExportError::UnbackedRef {
                refname: refname.clone(),
            });
        }
    }

    let layout = &wal.config().layout;
    for pack in &state.packs {
        let pack_key = layout.pack_key(slug, &pack.checksum, "pack");
        let idx_key = layout.pack_key(slug, &pack.checksum, "idx");
        if store.head(&pack_key).await?.is_none() {
            return Err(ExportError::MissingObject {
                kind: "pack",
                key: pack_key,
            });
        }
        if store.head(&idx_key).await?.is_none() {
            return Err(ExportError::MissingObject {
                kind: "idx",
                key: idx_key,
            });
        }
        if deep {
            let staged = StagedPath::temp_with_extension("export-pack-verify", "pack")?;
            download(store.as_ref(), &pack_key, &staged.path).await?;
            let staged_idx = StagedPath {
                path: staged.path.with_extension("idx"),
                keep: false,
            };
            download(store.as_ref(), &idx_key, &staged_idx.path).await?;
            let idx_file = staged_idx
                .path
                .to_str()
                .ok_or_else(|| ExportError::Checksum {
                    key: pack_key.clone(),
                    message: "temporary path is not UTF-8".into(),
                })?;
            crate::git::run_git(&["verify-pack", "-v", idx_file], &[], BUNDLE_TIMEOUT)
                .await
                .map_err(|error| ExportError::Checksum {
                    key: pack_key.clone(),
                    message: error.to_string(),
                })?;
        }
    }

    if deep {
        for (refname, entry) in refs {
            let Some(key) = &entry.bundle else { continue };
            let staged = StagedPath::temp("export-bundle-verify")?;
            download(store.as_ref(), key, &staged.path).await?;
            let file = staged.path.to_str().ok_or_else(|| ExportError::Checksum {
                key: key.clone(),
                message: "temporary path is not UTF-8".into(),
            })?;
            let heads = crate::git::run_git(&["bundle", "list-heads", file], &[], QUICK_TIMEOUT)
                .await
                .map_err(|error| ExportError::Checksum {
                    key: key.clone(),
                    message: error.to_string(),
                })?;
            let present = heads.lines().any(|line| {
                line.split_once(' ')
                    .map(|(sha, name)| {
                        sha.eq_ignore_ascii_case(&entry.sha) && name.trim() == refname
                    })
                    .unwrap_or(false)
            });
            if !present {
                return Err(ExportError::Checksum {
                    key: key.clone(),
                    message: format!("bundle does not contain {refname} at {}", entry.sha),
                });
            }
        }
    }

    let _ = slug;
    Ok(())
}

async fn download(
    store: &dyn crate::store::ObjectStore,
    key: &str,
    dest: &Path,
) -> Result<(), ExportError> {
    let result = store
        .get(key, GetOptions::default())
        .await
        .map_err(|error| {
            if matches!(error, StoreError::NotFound { .. }) {
                ExportError::MissingObject {
                    kind: "object",
                    key: key.to_string(),
                }
            } else {
                ExportError::Store(error)
            }
        })?;
    let GetResult::Object { body, .. } = result else {
        return Err(ExportError::MissingObject {
            kind: "object",
            key: key.to_string(),
        });
    };
    write_stream_atomic(body, dest).await?;
    Ok(())
}

async fn create_bundle(
    mirror: &Path,
    path: &Path,
    refs: &BTreeMap<String, ManifestRef>,
    head: Option<&str>,
) -> Result<(), ExportError> {
    let git_dir = format!("--git-dir={}", mirror.display());
    let path_str = path.to_str().ok_or_else(|| {
        ExportError::Git(GitError::InvalidInput("export path is not UTF-8".into()))
    })?;
    let mut args: Vec<String> = vec![git_dir, "bundle".into(), "create".into(), path_str.into()];
    for refname in refs.keys() {
        args.push(refname.clone());
    }
    if let Some(head) = head {
        if refs.contains_key(head) {
            args.push("HEAD".into());
        }
    }
    let args_ref: Vec<&str> = args.iter().map(String::as_str).collect();
    crate::git::run_git(&args_ref, &[], BUNDLE_TIMEOUT).await?;
    Ok(())
}

async fn verify_bundle(mirror: &Path, path: &Path) -> Result<(), ExportError> {
    let git_dir = format!("--git-dir={}", mirror.display());
    let path_str = path.to_str().ok_or_else(|| {
        ExportError::Git(GitError::InvalidInput("export path is not UTF-8".into()))
    })?;
    crate::git::run_git(
        &[&git_dir, "bundle", "verify", path_str],
        &[],
        QUICK_TIMEOUT,
    )
    .await
    .map_err(|error| ExportError::Checksum {
        key: path_str.to_string(),
        message: error.to_string(),
    })?;
    Ok(())
}

struct StagedPath {
    path: PathBuf,
    keep: bool,
}

impl StagedPath {
    fn temp(prefix: &str) -> Result<Self, ExportError> {
        let path = tmp_path(prefix);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        Ok(Self { path, keep: false })
    }

    fn temp_with_extension(prefix: &str, extension: &str) -> Result<Self, ExportError> {
        let path = tmp_path(prefix).with_extension(extension);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        Ok(Self { path, keep: false })
    }

    fn into_path(mut self) -> PathBuf {
        self.keep = true;
        self.path.clone()
    }
}

impl Drop for StagedPath {
    fn drop(&mut self) {
        if !self.keep {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Layout, WalConfig};
    use crate::import::{import_repo, ImportOptions};
    use crate::manifest::RefsCodec;
    use crate::store::MemoryStore;
    use std::sync::Arc;

    fn wal(repos: &Path) -> Wal<RefsCodec> {
        Wal::new(
            Arc::new(MemoryStore::new()),
            Arc::new(WalConfig::new(repos, Layout::new("git"))),
            Arc::new(RefsCodec),
        )
    }

    #[tokio::test]
    async fn export_refs_json_has_manifest_refs() {
        let src = tempfile::tempdir().unwrap();
        let path = src.path().to_str().unwrap();
        crate::git::run_git(&["init", "-q", "-b", "main", path], &[], QUICK_TIMEOUT)
            .await
            .unwrap();
        crate::git::run_git(
            &[
                "-C",
                path,
                "-c",
                "user.name=T",
                "-c",
                "user.email=t@example.com",
                "commit",
                "-q",
                "--allow-empty",
                "-m",
                "one",
            ],
            &[],
            QUICK_TIMEOUT,
        )
        .await
        .unwrap();
        let repos = tempfile::tempdir().unwrap();
        let wal = wal(repos.path());
        import_repo(&wal, "demo", src.path(), &ImportOptions::default())
            .await
            .unwrap();

        let refs = export_refs(&wal, "demo").await.unwrap();
        assert!(refs.refs.contains_key("refs/heads/main"));
        let json = serde_json::to_value(&refs).unwrap();
        assert_eq!(json["slug"], "demo");
        assert!(json["refs"]["refs/heads/main"].is_string());

        let bundle = export_bundle(&wal, "demo").await.unwrap();
        assert!(!bundle.is_empty());
    }

    #[tokio::test]
    async fn export_missing_repository_is_typed() {
        let repos = tempfile::tempdir().unwrap();
        let wal = wal(repos.path());
        let error = export_bundle(&wal, "absent").await.unwrap_err();
        assert!(matches!(error, ExportError::NotFound(_)), "{error:?}");
    }
}
