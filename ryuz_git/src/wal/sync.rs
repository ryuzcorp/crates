//! Mirror synchronization: rebuild from the manifest when missing or stale.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::error::WalError;
use crate::git;
use crate::manifest::ManifestCodec;
use crate::wal::{get_to_file, tmp_for};

use super::Wal;

impl<C: ManifestCodec> Wal<C> {
    /// The mirror, rebuilt from the manifest when missing or stale.
    pub async fn ensure_synced(&self, slug: &str) -> Result<PathBuf, WalError> {
        git::validate_slug(slug)?;
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
    pub async fn ensure_synced_locked(&self, slug: &str) -> Result<PathBuf, WalError> {
        git::validate_slug(slug)?;
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
    pub async fn rehydrate(&self, slug: &str) -> Result<BTreeMap<String, String>, WalError> {
        let _guard = self.lock(slug).await;
        self.rehydrate_locked(slug).await
    }

    /// Compare the local ref snapshot with the manifest; rebuild only when it
    /// differs. Immutable inputs are downloaded before the mirror is touched,
    /// and installed with copy-plus-rename so a partial download never looks
    /// like a valid pack or bundle.
    pub(crate) async fn rehydrate_locked(
        &self,
        slug: &str,
    ) -> Result<BTreeMap<String, String>, WalError> {
        let manifest = self.read_manifest(slug).await?;
        let (seq, state) = match &manifest {
            Some(manifest) => (self.codec.seq(manifest), self.codec.state(manifest)),
            None => (0, crate::manifest::ManifestState::default()),
        };
        let expected: BTreeMap<String, String> = state
            .refs
            .iter()
            .map(|(name, entry)| (name.clone(), entry.sha.clone()))
            .collect();
        let bare = self.mirror_path(slug);
        let exists = bare.join("HEAD").exists();
        let local = if exists {
            self.config.filter_refs(
                git::snapshot_refs(&bare, &self.config.extra_ref_prefixes)
                    .await?
                    .refs,
            )
        } else {
            BTreeMap::new()
        };
        let head_matches = match &state.head {
            Some(head) => {
                git::symbolic_head(&bare).await.ok().flatten().as_deref() == Some(head.as_str())
            }
            None => true,
        };
        if exists && local == expected && head_matches {
            self.sync.reset_applied_seq(slug, seq).await;
            return Ok(expected);
        }

        // Stage every immutable input before touching the mirror, so a missing
        // object fails without destroying a working cache.
        let mut staged_bundles: Vec<(PathBuf, String, String)> = Vec::new();
        let mut staged_packs: Vec<(String, PathBuf, PathBuf, Option<PathBuf>)> = Vec::new();
        let mut cleanup: Vec<PathBuf> = Vec::new();
        let result = async {
            for (refname, entry) in &state.refs {
                let Some(bundle) = &entry.bundle else {
                    continue;
                };
                let tmp = tmp_for("rehydrate", slug, "bundle");
                match get_to_file(&self.store, bundle, &tmp).await {
                    Ok(true) => {}
                    Ok(false) => {
                        return Err(WalError::Corrupt(format!(
                            "bundle {bundle} is missing for {slug}"
                        )));
                    }
                    Err(error) => return Err(error),
                }
                cleanup.push(tmp.clone());
                staged_bundles.push((tmp, refname.clone(), entry.sha.clone()));
            }
            for pack in &state.packs {
                if !pack.checksum.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                    return Err(WalError::Corrupt(format!(
                        "manifest has an invalid pack checksum {:?}",
                        pack.checksum
                    )));
                }
                let pack_tmp = tmp_for("rehydrate", slug, "pack");
                let idx_tmp = tmp_for("rehydrate", slug, "idx");
                if !get_to_file(
                    &self.store,
                    &pack.pack_key(&self.config.layout, slug),
                    &pack_tmp,
                )
                .await?
                {
                    return Err(WalError::Corrupt(format!(
                        "pack {} is missing for {slug}",
                        pack.checksum
                    )));
                }
                cleanup.push(pack_tmp.clone());
                if !get_to_file(
                    &self.store,
                    &pack.idx_key(&self.config.layout, slug),
                    &idx_tmp,
                )
                .await?
                {
                    return Err(WalError::Corrupt(format!(
                        "pack index {} is missing for {slug}",
                        pack.checksum
                    )));
                }
                cleanup.push(idx_tmp.clone());
                let rev_tmp = if pack.has_rev {
                    let path = tmp_for("rehydrate", slug, "rev");
                    if get_to_file(
                        &self.store,
                        &self.config.layout.pack_key(slug, &pack.checksum, "rev"),
                        &path,
                    )
                    .await?
                    {
                        cleanup.push(path.clone());
                        Some(path)
                    } else {
                        None
                    }
                } else {
                    None
                };
                staged_packs.push((pack.checksum.clone(), pack_tmp, idx_tmp, rev_tmp));
            }

            if !bare.join("HEAD").exists() {
                if bare.exists() {
                    tokio::fs::remove_dir_all(&bare).await?;
                }
                git::init_bare(&self.config, &bare).await?;
            }
            install_packs(&bare, &staged_packs).await?;
            let git_dir = format!("--git-dir={}", bare.display());
            for (tmp, refname, sha) in &staged_bundles {
                let Some(bundle) = tmp.to_str() else {
                    return Err(WalError::Corrupt("bundle tmp path is not UTF-8".into()));
                };
                // Fetch the bundle's own ref: a `<sha>:<ref>` refspec fails for
                // annotated tags, whose tip is the tag object.
                git::run_git(
                    &[
                        &git_dir,
                        "fetch",
                        "--no-tags",
                        bundle,
                        &format!("+{refname}:{refname}"),
                    ],
                    &[],
                    git::BUNDLE_TIMEOUT,
                )
                .await?;
                let head = git::head_of_ref(&bare, refname).await?;
                if head.as_deref() != Some(sha.as_str()) {
                    return Err(WalError::Corrupt(format!(
                        "bundle {bundle} produced {refname} at {head:?}, manifest says {sha}"
                    )));
                }
            }

            // The manifest is authoritative: drop local refs it does not name,
            // then force every named ref to its tip.
            for refname in local.keys() {
                if !expected.contains_key(refname) {
                    git::set_ref(&bare, refname, None).await?;
                }
            }
            for (refname, sha) in &expected {
                if !git::has_object(&bare, sha).await? {
                    return Err(WalError::Corrupt(format!(
                        "manifest names {refname} at {sha}, which is not in the mirror"
                    )));
                }
                if git::head_of_ref(&bare, refname).await?.as_deref() != Some(sha.as_str()) {
                    git::set_ref(&bare, refname, Some(sha)).await?;
                }
            }
            let head = state
                .head
                .clone()
                .unwrap_or_else(|| format!("refs/heads/{}", self.config.default_branch));
            tokio::fs::write(bare.join("HEAD"), format!("ref: {head}\n")).await?;
            Ok::<_, WalError>(())
        }
        .await;
        for path in &cleanup {
            let _ = tokio::fs::remove_file(path).await;
        }
        result?;
        self.sync.reset_applied_seq(slug, seq).await;
        Ok(expected)
    }
}

/// Install downloaded packs with copy-plus-rename inside `objects/pack`.
async fn install_packs(
    bare: &Path,
    packs: &[(String, PathBuf, PathBuf, Option<PathBuf>)],
) -> Result<(), WalError> {
    if packs.is_empty() {
        return Ok(());
    }
    let dir = bare.join("objects").join("pack");
    tokio::fs::create_dir_all(&dir).await?;
    for (checksum, pack, idx, rev) in packs {
        install_file(pack, &dir.join(format!("pack-{checksum}.pack"))).await?;
        install_file(idx, &dir.join(format!("pack-{checksum}.idx"))).await?;
        if let Some(rev) = rev {
            install_file(rev, &dir.join(format!("pack-{checksum}.rev"))).await?;
        }
    }
    Ok(())
}

async fn install_file(source: &Path, dest: &Path) -> Result<(), WalError> {
    if dest.exists() {
        return Ok(());
    }
    let tmp = dest.with_extension(format!("tmp-{}", std::process::id()));
    tokio::fs::copy(source, &tmp).await?;
    match tokio::fs::rename(&tmp, dest).await {
        Ok(()) => Ok(()),
        Err(error) => {
            let _ = tokio::fs::remove_file(&tmp).await;
            Err(error.into())
        }
    }
}
