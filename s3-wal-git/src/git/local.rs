//! Local bare-repository helpers: object installation, ref transactions and
//! checkout-free reads.
//!
//! The local mirror is a cache. Nothing here consults the manifest or the
//! object store; callers install immutable packs first and move refs only
//! after the manifest write succeeded.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::fs;

use crate::config::{ObjectFormat, WalConfig};
use crate::error::GitError;
use crate::git::ingest::{repository_format, IngestedPack};
use crate::git::{
    apply_ref_transaction as git_apply_ref_transaction, head_of_ref, init_bare, is_ancestor,
    is_full_sha, resolve_oid, run_git, run_git_raw, snapshot_refs, validate_refname, RefSnapshot,
    RefUpdate, PROTOCOL_TIMEOUT, QUICK_TIMEOUT,
};

/// Source files for one pack, wherever they currently live.
#[derive(Debug, Clone, Copy)]
pub struct PackSource<'a> {
    pub checksum: &'a str,
    pub pack_path: &'a Path,
    pub idx_path: &'a Path,
    /// Optional reverse index (`pack-<hash>.rev`).
    pub rev_path: Option<&'a Path>,
}

/// One complete pack inside `objects/pack`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackFiles {
    pub checksum: String,
    pub pack_path: PathBuf,
    pub idx_path: PathBuf,
    pub rev_path: Option<PathBuf>,
    pub pack_size: u64,
    pub idx_size: u64,
}

/// A bare repository on the local filesystem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalRepo {
    path: PathBuf,
}

static COPY_SEQ: AtomicU64 = AtomicU64::new(0);

impl LocalRepo {
    /// Open an existing bare repository.
    ///
    /// The path must be UTF-8 (it is interpolated into `--git-dir=` argv) and
    /// must look like a git directory: a `HEAD` file and an `objects`
    /// directory. A missing repository is an input error, not an empty one.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, GitError> {
        let path = path.into();
        let text = path
            .to_str()
            .ok_or_else(|| GitError::InvalidInput("repository path is not UTF-8".into()))?;
        if text.is_empty() {
            return Err(GitError::InvalidInput("repository path is empty".into()));
        }
        if text.contains('\0') {
            return Err(GitError::InvalidInput(
                "repository path contains a NUL byte".into(),
            ));
        }
        if !path.is_dir() {
            return Err(GitError::InvalidInput(format!(
                "repository path {text:?} is not a directory"
            )));
        }
        if !path.join("HEAD").is_file() || !path.join("objects").is_dir() {
            return Err(GitError::InvalidInput(format!(
                "repository path {text:?} is not a git directory"
            )));
        }
        Ok(Self { path })
    }

    /// Create a bare repository with the configured object format and hidden
    /// refs, then open it.
    pub async fn init(path: impl Into<PathBuf>, cfg: &WalConfig) -> Result<Self, GitError> {
        let path = path.into();
        let text = path
            .to_str()
            .ok_or_else(|| GitError::InvalidInput("repository path is not UTF-8".into()))?;
        if text.contains('\0') {
            return Err(GitError::InvalidInput(
                "repository path contains a NUL byte".into(),
            ));
        }
        init_bare(cfg, &path).await?;
        Self::open(path)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// `--git-dir=<path>` as a single argv element.
    pub fn git_dir(&self) -> Result<String, GitError> {
        let text = self
            .path
            .to_str()
            .ok_or_else(|| GitError::InvalidInput("repository path is not UTF-8".into()))?;
        Ok(format!("--git-dir={text}"))
    }

    pub fn pack_dir(&self) -> PathBuf {
        self.path.join("objects").join("pack")
    }

    pub async fn object_format(&self) -> Result<ObjectFormat, GitError> {
        repository_format(&self.path).await
    }

    // ---------------------------------------------------------------- refs

    /// Branches, tags, extra prefixes, symbolic HEAD and peeled tag targets.
    pub async fn ref_snapshot(&self, extra_prefixes: &[String]) -> Result<RefSnapshot, GitError> {
        snapshot_refs(&self.path, extra_prefixes).await
    }

    /// Map view of [`Self::ref_snapshot`].
    pub async fn refs(&self) -> Result<BTreeMap<String, String>, GitError> {
        Ok(self.ref_snapshot(&[]).await?.refs)
    }

    pub async fn head_of_ref(&self, refname: &str) -> Result<Option<String>, GitError> {
        head_of_ref(&self.path, refname).await
    }

    pub async fn symbolic_head(&self) -> Result<Option<String>, GitError> {
        crate::git::symbolic_head(&self.path).await
    }

    /// Point `HEAD` at another ref without checking anything out.
    pub async fn set_symbolic_head(&self, target: &str) -> Result<(), GitError> {
        validate_refname(target)?;
        let git_dir = self.git_dir()?;
        run_git(
            &[&git_dir, "symbolic-ref", "HEAD", target],
            &[],
            QUICK_TIMEOUT,
        )
        .await
        .map(|_| ())
    }

    /// Apply every update atomically and roll the touched refs back if git
    /// still reports a failure.
    ///
    /// An update whose `expected_old` is `None` is made conditional on the
    /// value seen in the snapshot taken just before the transaction, so a
    /// concurrent writer wins instead of being clobbered.
    ///
    /// `git update-ref --stdin` already uses prepare/commit, so a failure
    /// normally leaves nothing behind. The snapshot restore covers git
    /// versions and filesystems where the commit step can fail after some
    /// refs were written; the original refs are reinstated from the snapshot.
    pub async fn apply_ref_transaction(&self, updates: &[RefUpdate]) -> Result<(), GitError> {
        if updates.is_empty() {
            return Ok(());
        }
        let snapshot = self.ref_snapshot(&[]).await?;
        let normalized: Vec<RefUpdate> = updates
            .iter()
            .map(|update| RefUpdate {
                refname: update.refname.clone(),
                expected_old: update
                    .expected_old
                    .clone()
                    .or_else(|| snapshot.refs.get(&update.refname).cloned()),
                new_sha: update.new_sha.clone(),
            })
            .collect();
        match git_apply_ref_transaction(&self.path, &normalized).await {
            Ok(()) => Ok(()),
            Err(error) => match self.restore_snapshot(&snapshot, updates).await {
                Ok(()) => Err(error),
                Err(rollback) => Err(GitError::Other(anyhow::anyhow!(
                    "ref transaction failed: {error}; rollback failed: {rollback}"
                ))),
            },
        }
    }

    /// Reinstate the refs (and symbolic HEAD) recorded in `snapshot`.
    ///
    /// Only refs named in `updates` are touched: restoring the whole
    /// repository would clobber concurrent work on unrelated refs. Each value
    /// is restored unconditionally: the transaction already failed, so there
    /// is no meaningful old value left to compare against.
    async fn restore_snapshot(
        &self,
        snapshot: &RefSnapshot,
        updates: &[RefUpdate],
    ) -> Result<(), GitError> {
        let mut seen = BTreeMap::<String, ()>::new();
        for update in updates {
            if seen.insert(update.refname.clone(), ()).is_some() {
                continue;
            }
            match snapshot.refs.get(&update.refname) {
                Some(old) => {
                    crate::git::set_ref(&self.path, &update.refname, Some(old)).await?;
                }
                None => {
                    crate::git::set_ref(&self.path, &update.refname, None).await?;
                }
            }
        }
        if let Some(expected) = &snapshot.head {
            if self.symbolic_head().await?.as_deref() != Some(expected.as_str()) {
                self.set_symbolic_head(expected).await?;
            }
        }
        Ok(())
    }

    // --------------------------------------------------------------- packs

    /// Copy `source` into `objects/pack` under its content-addressed name.
    ///
    /// The index is installed last, so a reader never sees a pack whose index
    /// is missing. Existing destinations are left untouched, which makes pack
    /// installation idempotent and safe to replay.
    pub async fn install_pack(&self, source: &PackSource<'_>) -> Result<PackFiles, GitError> {
        let format = self.object_format().await?;
        let checksum = source.checksum.to_ascii_lowercase();
        if !is_full_sha(&checksum, format) {
            return Err(GitError::InvalidInput(format!(
                "pack checksum {checksum:?} is not a full {} object id",
                format
            )));
        }
        let dir = self.pack_dir();
        fs::create_dir_all(&dir).await.map_err(GitError::Io)?;

        let pack_path = dir.join(format!("pack-{checksum}.pack"));
        copy_atomic(source.pack_path, &pack_path).await?;
        let rev_path = match source.rev_path {
            Some(rev) => {
                let target = dir.join(format!("pack-{checksum}.rev"));
                copy_atomic(rev, &target).await?;
                Some(target)
            }
            None => None,
        };
        // `git index-pack --keep` places a sibling marker; carry it over so a
        // concurrent `git gc` cannot prune a pack that is about to become
        // reachable.
        let keep_source = source.pack_path.with_extension("keep");
        if fs::metadata(&keep_source).await.is_ok() {
            let target = dir.join(format!("pack-{checksum}.keep"));
            copy_atomic(&keep_source, &target).await?;
        }
        let idx_path = dir.join(format!("pack-{checksum}.idx"));
        copy_atomic(source.idx_path, &idx_path).await?;

        let pack_size = fs::metadata(&pack_path).await.map_err(GitError::Io)?.len();
        let idx_size = fs::metadata(&idx_path).await.map_err(GitError::Io)?.len();
        Ok(PackFiles {
            checksum,
            pack_path,
            idx_path,
            rev_path,
            pack_size,
            idx_size,
        })
    }

    /// [`Self::install_pack`] for an [`IngestedPack`] whose files are local.
    pub async fn install_ingested(&self, pack: &IngestedPack) -> Result<PackFiles, GitError> {
        self.install_pack(&PackSource {
            checksum: &pack.checksum,
            pack_path: &pack.pack_path,
            idx_path: &pack.idx_path,
            rev_path: pack.rev_path.as_deref(),
        })
        .await
    }

    /// Every complete pack in `objects/pack`, sorted by checksum.
    ///
    /// A `.pack` without its `.idx` is not usable by git and is omitted;
    /// callers that care about debris use [`Self::remove_pack`].
    pub async fn packs(&self) -> Result<Vec<PackFiles>, GitError> {
        let dir = self.pack_dir();
        let mut entries = match fs::read_dir(&dir).await {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(GitError::Io(error)),
        };
        let format = self.object_format().await?;
        let mut found = BTreeMap::<String, (PathBuf, PathBuf, Option<PathBuf>)>::new();
        while let Some(entry) = entries.next_entry().await.map_err(GitError::Io)? {
            let Some(name) = entry.file_name().to_str().map(str::to_string) else {
                continue;
            };
            let Some(rest) = name.strip_prefix("pack-") else {
                continue;
            };
            let Some((checksum, extension)) = rest.rsplit_once('.') else {
                continue;
            };
            if !is_full_sha(checksum, format) {
                continue;
            }
            let checksum = checksum.to_ascii_lowercase();
            let slot = found
                .entry(checksum)
                .or_insert_with(|| (PathBuf::new(), PathBuf::new(), None));
            let path = entry.path();
            match extension {
                "pack" => slot.0 = path,
                "idx" => slot.1 = path,
                "rev" => slot.2 = Some(path),
                _ => {}
            }
        }
        let mut packs = Vec::new();
        for (checksum, (pack_path, idx_path, rev_path)) in found {
            if pack_path.as_os_str().is_empty() || idx_path.as_os_str().is_empty() {
                continue;
            }
            let pack_size = fs::metadata(&pack_path).await.map_err(GitError::Io)?.len();
            let idx_size = fs::metadata(&idx_path).await.map_err(GitError::Io)?.len();
            packs.push(PackFiles {
                checksum,
                pack_path,
                idx_path,
                rev_path,
                pack_size,
                idx_size,
            });
        }
        Ok(packs)
    }

    /// Remove every file belonging to `checksum`. Returns whether the pack
    /// itself was present.
    pub async fn remove_pack(&self, checksum: &str) -> Result<bool, GitError> {
        let format = self.object_format().await?;
        let checksum = checksum.to_ascii_lowercase();
        if !is_full_sha(&checksum, format) {
            return Err(GitError::InvalidInput(format!(
                "pack checksum {checksum:?} is not a full {} object id",
                format
            )));
        }
        let dir = self.pack_dir();
        let mut removed_pack = false;
        for extension in ["pack", "idx", "rev", "keep", "bitmap", "promisor"] {
            let path = dir.join(format!("pack-{checksum}.{extension}"));
            match fs::remove_file(&path).await {
                Ok(()) => {
                    if extension == "pack" {
                        removed_pack = true;
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(GitError::Io(error)),
            }
        }
        Ok(removed_pack)
    }

    /// Pack loose refs into `packed-refs` (checkout-free).
    pub async fn pack_refs(&self) -> Result<(), GitError> {
        let git_dir = self.git_dir()?;
        run_git(
            &[&git_dir, "pack-refs", "--all", "--prune"],
            &[],
            PROTOCOL_TIMEOUT,
        )
        .await
        .map(|_| ())
    }

    // ------------------------------------------------------------- objects

    pub async fn has_object(&self, oid: &str) -> Result<bool, GitError> {
        self.validate_oid(oid).await?;
        crate::git::has_object(&self.path, oid).await
    }

    /// Resolve a revision (ref, tag, abbreviated oid) to a full object id.
    pub async fn resolve(&self, rev: &str) -> Result<Option<String>, GitError> {
        validate_rev(rev)?;
        resolve_oid(&self.path, rev).await
    }

    /// Whether `old` is an ancestor of `new`; `false` when either is missing.
    pub async fn is_ancestor(&self, old: &str, new: &str) -> bool {
        is_ancestor(&self.path, old, new).await
    }

    /// Object type (`commit`, `tree`, `blob`, `tag`), or `None` when absent.
    pub async fn object_type(&self, oid: &str) -> Result<Option<String>, GitError> {
        self.validate_oid(oid).await?;
        let git_dir = self.git_dir()?;
        match run_git(&[&git_dir, "cat-file", "-t", oid], &[], QUICK_TIMEOUT).await {
            Ok(out) => Ok(Some(out.trim().to_string())),
            Err(error) if is_missing_object(&error) => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// Object size in bytes, or `None` when absent.
    pub async fn object_size(&self, oid: &str) -> Result<Option<u64>, GitError> {
        self.validate_oid(oid).await?;
        let git_dir = self.git_dir()?;
        let out = match run_git(&[&git_dir, "cat-file", "-s", oid], &[], QUICK_TIMEOUT).await {
            Ok(out) => out,
            Err(error) if is_missing_object(&error) => return Ok(None),
            Err(error) => return Err(error),
        };
        out.trim()
            .parse::<u64>()
            .map(Some)
            .map_err(|_| GitError::Protocol(format!("cat-file -s printed {out:?}")))
    }

    /// Blob bytes by object id.
    pub async fn cat_blob(&self, oid: &str) -> Result<Vec<u8>, GitError> {
        self.validate_oid(oid).await?;
        let git_dir = self.git_dir()?;
        run_git_raw(&[&git_dir, "cat-file", "blob", oid], &[], QUICK_TIMEOUT).await
    }

    /// Contents of `path` at `rev`, without a work tree.
    pub async fn blob_at(&self, rev: &str, path: &str) -> Result<Option<Vec<u8>>, GitError> {
        validate_rev(rev)?;
        validate_tree_path(path)?;
        let git_dir = self.git_dir()?;
        let spec = format!("{rev}:{path}");
        match run_git_raw(&[&git_dir, "cat-file", "blob", &spec], &[], QUICK_TIMEOUT).await {
            Ok(bytes) => Ok(Some(bytes)),
            Err(error) if is_missing_object(&error) => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// Loose plus packed object count.
    pub async fn count_objects(&self) -> Result<u64, GitError> {
        let git_dir = self.git_dir()?;
        let out = run_git(&[&git_dir, "count-objects", "-v"], &[], QUICK_TIMEOUT).await?;
        let mut total = 0u64;
        for line in out.lines() {
            let Some((key, value)) = line.split_once(':') else {
                continue;
            };
            if key == "count" || key == "in-pack" {
                total = total.saturating_add(
                    value
                        .trim()
                        .parse::<u64>()
                        .map_err(|_| GitError::Protocol(format!("count-objects: {line:?}")))?,
                );
            }
        }
        Ok(total)
    }

    /// `git fsck`, connectivity-only unless `full`.
    pub async fn fsck(&self, full: bool) -> Result<(), GitError> {
        let git_dir = self.git_dir()?;
        let mode = if full {
            "--full"
        } else {
            "--connectivity-only"
        };
        match run_git(
            &[&git_dir, "fsck", mode, "--no-dangling", "--no-progress"],
            &[],
            PROTOCOL_TIMEOUT,
        )
        .await
        {
            Ok(_) => Ok(()),
            Err(GitError::Subprocess { stderr, .. }) => Err(GitError::Fsck(stderr)),
            Err(error) => Err(error),
        }
    }

    async fn validate_oid(&self, oid: &str) -> Result<(), GitError> {
        let format = self.object_format().await?;
        if !is_full_sha(oid, format) {
            return Err(GitError::InvalidInput(format!(
                "{oid:?} is not a full {} object id",
                format
            )));
        }
        Ok(())
    }
}

/// Copy `source` to `target` via a temporary file in the target directory.
///
/// The rename makes the file appear atomically. An existing target wins: the
/// content is addressed and therefore already correct.
async fn copy_atomic(source: &Path, target: &Path) -> Result<(), GitError> {
    if let (Ok(source), Ok(target)) = (
        fs::canonicalize(source).await,
        fs::canonicalize(target).await,
    ) {
        if source == target {
            return Ok(());
        }
    }
    if fs::metadata(target).await.is_ok() {
        return Ok(());
    }
    let source_meta = fs::metadata(source).await.map_err(GitError::Io)?;
    if !source_meta.is_file() {
        return Err(GitError::InvalidInput(format!(
            "pack source {} is not a file",
            source.display()
        )));
    }
    let parent = target.parent().ok_or_else(|| {
        GitError::InvalidInput(format!("pack target {} has no parent", target.display()))
    })?;
    let seq = COPY_SEQ.fetch_add(1, Ordering::Relaxed);
    let tmp = parent.join(format!(".tmp-pack-{}-{seq}", std::process::id()));
    let copied = async {
        fs::copy(source, &tmp).await?;
        fs::rename(&tmp, target).await?;
        Ok::<(), std::io::Error>(())
    }
    .await;
    if let Err(error) = copied {
        let _ = fs::remove_file(&tmp).await;
        return Err(GitError::Io(error));
    }
    Ok(())
}

fn is_missing_object(error: &GitError) -> bool {
    match error {
        GitError::Subprocess { stderr, .. } => {
            stderr.contains("Not a valid object name")
                || stderr.contains("does not exist")
                || stderr.contains("bad file")
                || stderr.contains("unable to read")
                || stderr.contains("could not get object info")
        }
        _ => false,
    }
}

fn validate_rev(rev: &str) -> Result<(), GitError> {
    let bad = rev.is_empty()
        || rev.len() > 1024
        || rev.contains('\0')
        || rev.starts_with('-')
        || rev.contains(char::is_control);
    if bad {
        Err(GitError::InvalidInput(format!("invalid revision {rev:?}")))
    } else {
        Ok(())
    }
}

fn validate_tree_path(path: &str) -> Result<(), GitError> {
    let bad = path.is_empty()
        || path.len() > 4096
        || path.starts_with('/')
        || path.contains('\0')
        || path.contains(char::is_control)
        || path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..");
    if bad {
        Err(GitError::InvalidInput(format!(
            "invalid repository path {path:?}"
        )))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::git::ingest::fixture::*;
    use crate::git::ingest::{ingest_pack, IngestOptions};

    fn set_ref(name: &str, old: Option<&str>, new: &str) -> RefUpdate {
        RefUpdate::set(name, old.map(str::to_string), new.to_string())
    }

    async fn seeded_repo(format: ObjectFormat) -> (tempfile::TempDir, LocalRepo, String, String) {
        let (dir, work) = work_repo(format);
        write(&work, "a.txt", "hello\n");
        let first = commit_all(&work, "one");
        write(&work, "a.txt", "goodbye\n");
        let second = commit_all(&work, "two");
        let bare_path = bare_repo(dir.path(), format);
        let repo = LocalRepo::open(&bare_path).expect("open");
        let pack = pack_all(&work);
        let ingested = ingest_pack(&bare_path, &pack, &IngestOptions::default())
            .await
            .expect("ingest")
            .expect("pack");
        repo.install_ingested(&ingested).await.expect("install");
        (dir, repo, first, second)
    }

    #[tokio::test]
    async fn open_and_init_validate_the_directory() {
        let dir = tempfile::tempdir().unwrap();
        let bare = dir.path().join("bare.git");
        let cfg = WalConfig::new(dir.path(), crate::config::Layout::default());
        let repo = LocalRepo::init(&bare, &cfg).await.expect("init");
        assert_eq!(repo.path(), bare);
        assert!(!repo.git_dir().unwrap().is_empty());
        assert!(repo.packs().await.expect("packs").is_empty());
        assert!(!repo.has_object(&"0".repeat(40)).await.expect("has object"));
        assert_eq!(repo.count_objects().await.expect("count"), 0);
        assert_eq!(
            repo.symbolic_head().await.expect("head"),
            Some("refs/heads/main".into())
        );

        let not_repo = dir.path().join("nope");
        std::fs::create_dir_all(&not_repo).unwrap();
        assert!(matches!(
            LocalRepo::open(&not_repo),
            Err(GitError::InvalidInput(_))
        ));
    }

    #[test]
    fn open_refuses_non_utf8_paths() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;
        let path = PathBuf::from(OsString::from_vec(vec![b'/', 0xff, b'x']));
        match LocalRepo::open(path) {
            Err(GitError::InvalidInput(message)) => assert!(message.contains("UTF-8")),
            other => panic!("expected InvalidInput, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn ref_transactions_are_atomic_and_leave_no_partial_state() {
        let (_dir, repo, first, second) = seeded_repo(ObjectFormat::Sha1).await;
        repo.apply_ref_transaction(&[set_ref("refs/heads/main", None, &first)])
            .await
            .expect("create main");
        assert_eq!(
            repo.head_of_ref("refs/heads/main").await.expect("head"),
            Some(first.clone())
        );

        let failed = repo
            .apply_ref_transaction(&[
                set_ref("refs/heads/feat", None, &second),
                // Wrong expected old value: the whole transaction must fail.
                set_ref("refs/heads/main", Some(&"a".repeat(40)), &second),
            ])
            .await;
        assert!(failed.is_err());
        assert_eq!(
            repo.head_of_ref("refs/heads/feat").await.expect("feat"),
            None
        );
        assert_eq!(
            repo.head_of_ref("refs/heads/main").await.expect("main"),
            Some(first)
        );
    }

    #[tokio::test]
    async fn rollback_restores_the_snapshot() {
        let (_dir, repo, first, second) = seeded_repo(ObjectFormat::Sha1).await;
        repo.apply_ref_transaction(&[set_ref("refs/heads/main", None, &first)])
            .await
            .expect("create main");
        let snapshot = repo.ref_snapshot(&[]).await.expect("snapshot");

        // Move the ref behind the snapshot's back, then restore.
        let change = [set_ref("refs/heads/main", Some(&first), &second)];
        repo.apply_ref_transaction(&change).await.expect("move");
        assert_eq!(
            repo.head_of_ref("refs/heads/main").await.expect("moved"),
            Some(second)
        );
        repo.restore_snapshot(&snapshot, &change)
            .await
            .expect("restore");
        assert_eq!(
            repo.head_of_ref("refs/heads/main").await.expect("restored"),
            Some(first.clone())
        );

        // Deleting a ref that existed in the snapshot is also restored.
        let delete = [RefUpdate::delete("refs/heads/main", Some(first.clone()))];
        repo.apply_ref_transaction(&delete).await.expect("delete");
        assert_eq!(
            repo.head_of_ref("refs/heads/main").await.expect("gone"),
            None
        );
        repo.restore_snapshot(&snapshot, &delete)
            .await
            .expect("restore");
        assert!(repo
            .head_of_ref("refs/heads/main")
            .await
            .expect("back")
            .is_some());
    }

    #[tokio::test]
    async fn snapshot_reports_head_and_peeled_tags() {
        let (dir, work) = work_repo(ObjectFormat::Sha1);
        write(&work, "a.txt", "hello\n");
        let first = commit_all(&work, "one");
        git(Some(&work), &["tag", "-a", "v1", "-m", "release"]);
        let bare_path = bare_repo(dir.path(), ObjectFormat::Sha1);
        let repo = LocalRepo::open(&bare_path).expect("open");
        let pack = pack_revs(&work, &["HEAD", "refs/tags/v1"]);
        let ingested = ingest_pack(&bare_path, &pack, &IngestOptions::default())
            .await
            .expect("ingest")
            .expect("pack");
        repo.install_ingested(&ingested).await.expect("install");
        let tag_oid = rev(&work, "v1");
        repo.apply_ref_transaction(&[
            set_ref("refs/heads/main", None, &first),
            set_ref("refs/tags/v1", None, &tag_oid),
        ])
        .await
        .expect("refs");

        let snapshot = repo.ref_snapshot(&[]).await.expect("snapshot");
        assert_eq!(snapshot.head.as_deref(), Some("refs/heads/main"));
        assert_eq!(snapshot.refs.get("refs/heads/main"), Some(&first));
        assert_eq!(snapshot.refs.get("refs/tags/v1"), Some(&tag_oid));
        assert_eq!(snapshot.peeled.get("refs/tags/v1"), Some(&first));
        assert!(repo
            .refs()
            .await
            .expect("refs")
            .contains_key("refs/tags/v1"));
    }

    #[tokio::test]
    async fn install_list_and_remove_packs() {
        let (dir, repo, first, _second) = seeded_repo(ObjectFormat::Sha1).await;
        let packs = repo.packs().await.expect("packs");
        assert_eq!(packs.len(), 1);
        let pack = &packs[0];
        assert!(pack.pack_path.exists());
        assert!(pack.idx_path.exists());
        assert!(pack.pack_size > 0 && pack.idx_size > 0);

        // Installing the same pack again is a no-op.
        let source = PackSource {
            checksum: &pack.checksum,
            pack_path: &pack.pack_path,
            idx_path: &pack.idx_path,
            rev_path: pack.rev_path.as_deref(),
        };
        let again = repo.install_pack(&source).await.expect("reinstall");
        assert_eq!(&again, pack);

        let other = dir.path().join("other.git");
        init_bare_repo(&other, ObjectFormat::Sha1);
        let target = LocalRepo::open(&other).expect("other");
        let installed = target.install_pack(&source).await.expect("install");
        assert_eq!(installed.checksum, pack.checksum);
        assert_eq!(target.packs().await.expect("list").len(), 1);

        assert!(!repo.remove_pack(&"0".repeat(40)).await.expect("absent"));
        assert!(repo.remove_pack(&pack.checksum).await.expect("removed"));
        assert!(repo.packs().await.expect("empty").is_empty());
        assert!(!repo.remove_pack(&pack.checksum).await.expect("idempotent"));
        assert!(!first.is_empty());
    }

    #[tokio::test]
    async fn install_rejects_unsafe_checksums() {
        let (_dir, repo, _first, _second) = seeded_repo(ObjectFormat::Sha1).await;
        let packs = repo.packs().await.expect("packs");
        let pack = &packs[0];
        let source = PackSource {
            checksum: "../../etc/passwd",
            pack_path: &pack.pack_path,
            idx_path: &pack.idx_path,
            rev_path: None,
        };
        assert!(matches!(
            repo.install_pack(&source).await,
            Err(GitError::InvalidInput(_))
        ));
    }

    #[tokio::test]
    async fn checkout_free_reads_work() {
        let (_dir, repo, first, second) = seeded_repo(ObjectFormat::Sha1).await;
        repo.apply_ref_transaction(&[set_ref("refs/heads/main", None, &second)])
            .await
            .expect("refs");

        assert_eq!(
            repo.object_type(&first).await.expect("type"),
            Some("commit".into())
        );
        assert!(repo.object_size(&first).await.expect("size").unwrap() > 0);
        assert!(repo
            .object_type(&"0".repeat(40))
            .await
            .expect("missing")
            .is_none());
        assert_eq!(
            repo.blob_at("refs/heads/main", "a.txt")
                .await
                .expect("blob"),
            Some(b"goodbye\n".to_vec())
        );
        assert!(repo
            .blob_at("refs/heads/main", "missing.txt")
            .await
            .expect("missing blob")
            .is_none());
        assert!(matches!(
            repo.blob_at("refs/heads/main", "../etc/passwd").await,
            Err(GitError::InvalidInput(_))
        ));
        let blob = rev_blob(&repo, &second).await;
        assert_eq!(
            repo.cat_blob(&blob).await.expect("cat blob"),
            b"goodbye\n".to_vec()
        );
        assert_eq!(
            repo.resolve("refs/heads/main").await.expect("resolve"),
            Some(second)
        );
        assert!(
            repo.is_ancestor(
                &first,
                &repo.resolve("refs/heads/main").await.unwrap().unwrap()
            )
            .await
        );
        assert!(repo.count_objects().await.expect("count") >= 6);
        repo.pack_refs().await.expect("pack refs");
        assert!(repo
            .ref_snapshot(&[])
            .await
            .expect("after pack-refs")
            .refs
            .contains_key("refs/heads/main"));
        repo.fsck(false).await.expect("fsck");
    }

    async fn rev_blob(repo: &LocalRepo, commit: &str) -> String {
        let git_dir = repo.git_dir().unwrap();
        let spec = format!("{commit}:a.txt");
        let argv = [git_dir.as_str(), "rev-parse", spec.as_str()];
        let out = run_git(&argv, &[], QUICK_TIMEOUT).await.expect("rev-parse");
        out.trim().to_string()
    }
}
