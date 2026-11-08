//! Incoming-pack ingestion and connectivity checks.
//!
//! Everything here is content addressed: a pack is identified by the SHA-1 or
//! SHA-256 trailer it carries, and `git index-pack` writes it under
//! `objects/pack/pack-<checksum>.{pack,idx,rev}`. Re-ingesting the same bytes
//! is a no-op because the destination names are identical. Nothing in this
//! module moves a ref: the caller's manifest write is the only commit point.

use std::path::{Path, PathBuf};

use sha2::{Digest as _, Sha256};

use crate::config::ObjectFormat;
use crate::error::GitError;
use crate::git::{
    has_object, is_full_sha, run_git, run_git_stdin, PROTOCOL_TIMEOUT, QUICK_TIMEOUT,
};

#[derive(Debug, Clone)]
pub struct IngestOptions {
    /// Run `git index-pack --strict` (fsck every object).
    pub fsck: bool,
    /// Refuse packs larger than this many bytes.
    pub max_bytes: Option<u64>,
    /// Run `git index-pack --fix-thin` so deltas against resident objects
    /// resolve.
    pub thin: bool,
}

impl Default for IngestOptions {
    fn default() -> Self {
        Self {
            fsck: true,
            max_bytes: None,
            thin: true,
        }
    }
}

/// One pack now resident in the repository's object database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IngestedPack {
    pub checksum: String,
    pub pack_path: PathBuf,
    pub idx_path: PathBuf,
    pub rev_path: Option<PathBuf>,
    pub pack_size: u64,
    pub idx_size: u64,
    pub object_count: u64,
}

/// The repository's object format, read from `$GIT_DIR/config`.
///
/// Git writes `[extensions] objectformat = sha256` for SHA-256 repositories;
/// an absent extension means SHA-1. Reading the file avoids a subprocess and
/// keeps the answer deterministic even when the repository is being written by
/// another process.
pub(crate) async fn repository_format(bare: &Path) -> Result<ObjectFormat, GitError> {
    let config = bare.join("config");
    let text = tokio::fs::read_to_string(&config)
        .await
        .map_err(GitError::Io)?;
    let mut in_extensions = false;
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') {
            let name = line
                .trim_start_matches('[')
                .split(']')
                .next()
                .unwrap_or_default()
                .split_whitespace()
                .next()
                .unwrap_or_default();
            in_extensions = name.eq_ignore_ascii_case("extensions");
            continue;
        }
        if !in_extensions {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if key.trim().eq_ignore_ascii_case("objectformat") {
            let value = value.trim().to_ascii_lowercase();
            return ObjectFormat::parse(&value)
                .ok_or_else(|| GitError::Protocol(format!("unknown object format {value:?}")));
        }
    }
    Ok(ObjectFormat::Sha1)
}

fn hash_len(format: ObjectFormat) -> usize {
    match format {
        ObjectFormat::Sha1 => 20,
        ObjectFormat::Sha256 => 32,
    }
}

/// SHA-1 of `data`, used only to check a packfile trailer.
///
/// `sha2` 0.11 dropped SHA-1 and this crate has no `sha1` dependency; the
/// alternative would be trusting `index-pack` to reject corrupt uploads only
/// after reading them. Pack trailers are integrity checks, not a security
/// boundary, so the compact FIPS 180-1 transform below is sufficient. Vectors
/// and a cross-check against git's reported pack hash are covered by tests.
fn sha1_digest(data: &[u8]) -> [u8; 20] {
    fn compress(state: &mut [u32; 5], chunk: &[u8]) {
        let mut w = [0u32; 80];
        for (i, word) in w.iter_mut().take(16).enumerate() {
            let at = i * 4;
            *word = u32::from_be_bytes([chunk[at], chunk[at + 1], chunk[at + 2], chunk[at + 3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let [mut a, mut b, mut c, mut d, mut e] = *state;
        for (i, word) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | (!b & d), 0x5a82_7999),
                20..=39 => (b ^ c ^ d, 0x6ed9_eba1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1b_bcdc),
                _ => (b ^ c ^ d, 0xca62_c1d6),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(*word);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
    }

    let mut state = [
        0x6745_2301u32,
        0xefcd_ab89,
        0x98ba_dcfe,
        0x1032_5476,
        0xc3d2_e1f0,
    ];
    let mut chunks = data.chunks_exact(64);
    for chunk in &mut chunks {
        compress(&mut state, chunk);
    }
    let remainder = chunks.remainder();
    let mut tail = [0u8; 128];
    tail[..remainder.len()].copy_from_slice(remainder);
    tail[remainder.len()] = 0x80;
    let tail_len = if remainder.len() < 56 { 64 } else { 128 };
    let bit_len = (data.len() as u64).wrapping_mul(8);
    tail[tail_len - 8..tail_len].copy_from_slice(&bit_len.to_be_bytes());
    for chunk in tail[..tail_len].chunks_exact(64) {
        compress(&mut state, chunk);
    }
    let mut out = [0u8; 20];
    for (i, word) in state.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

/// Validate the pack header and trailer checksum, returning the pack hash.
///
/// The trailer is the checksum of every preceding byte, so this rejects
/// truncated or corrupted uploads before git ever sees them.
fn validate_pack(pack: &[u8], format: ObjectFormat) -> Result<String, GitError> {
    let hash_len = hash_len(format);
    if pack.len() < 12 + hash_len {
        return Err(GitError::Pack(format!(
            "pack is {} bytes, smaller than the minimum {}",
            pack.len(),
            12 + hash_len
        )));
    }
    if &pack[..4] != b"PACK" {
        return Err(GitError::Pack("pack does not start with PACK".into()));
    }
    let version = u32::from_be_bytes([pack[4], pack[5], pack[6], pack[7]]);
    if version != 2 && version != 3 {
        return Err(GitError::Pack(format!(
            "unsupported pack version {version}"
        )));
    }
    let (body, trailer) = pack.split_at(pack.len() - hash_len);
    let computed = match format {
        ObjectFormat::Sha1 => hex::encode(sha1_digest(body)),
        ObjectFormat::Sha256 => hex::encode(Sha256::digest(body)),
    };
    if computed.as_bytes() != hex::encode(trailer).as_bytes() {
        return Err(GitError::Pack(format!(
            "pack checksum mismatch: trailer is {}, content hashes to {computed}",
            hex::encode(trailer)
        )));
    }
    Ok(computed)
}

/// Parse the pack hash from `git index-pack`'s stdout.
///
/// `index-pack --stdin` prints `<kind>\t<hash>` where `<kind>` is `pack` or
/// `keep` (the latter when `--keep` created the marker on this run).
fn parse_index_pack_hash(stdout: &[u8], format: ObjectFormat) -> Result<String, GitError> {
    let text = std::str::from_utf8(stdout)
        .map_err(|_| GitError::Pack("index-pack printed non-UTF-8 output".into()))?;
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        let (Some(kind), Some(hash)) = (parts.next(), parts.next()) else {
            continue;
        };
        if parts.next().is_some() {
            continue;
        }
        if kind != "pack" && kind != "keep" {
            continue;
        }
        let hash = hash.to_ascii_lowercase();
        if is_full_sha(&hash, format) {
            return Ok(hash);
        }
    }
    Err(GitError::Pack(format!(
        "index-pack did not report a pack hash: {:?}",
        text.trim()
    )))
}

/// Object count encoded in the index header.
///
/// Index v2 (magic `\xfftOc`) stores the fanout table after the magic and
/// version; its last entry is the object count. Index v1 starts with the
/// fanout table directly.
fn idx_header_count(idx: &[u8]) -> Result<u64, GitError> {
    let truncated = || GitError::Pack("pack index is truncated".into());
    if idx.starts_with(&[0xff, 0x74, 0x4f, 0x63]) {
        if idx.len() < 8 + 256 * 4 {
            return Err(truncated());
        }
        let version = u32::from_be_bytes([idx[4], idx[5], idx[6], idx[7]]);
        if version != 2 {
            return Err(GitError::Pack(format!(
                "unsupported pack index version {version}"
            )));
        }
        let at = 8 + 255 * 4;
        Ok(u32::from_be_bytes([idx[at], idx[at + 1], idx[at + 2], idx[at + 3]]) as u64)
    } else {
        if idx.len() < 256 * 4 {
            return Err(truncated());
        }
        let at = 255 * 4;
        Ok(u32::from_be_bytes([idx[at], idx[at + 1], idx[at + 2], idx[at + 3]]) as u64)
    }
}

/// Verify the index and count its objects with `git show-index`.
async fn count_idx_objects(idx_path: &Path, format: ObjectFormat) -> Result<u64, GitError> {
    let bytes = tokio::fs::read(idx_path).await.map_err(GitError::Io)?;
    let header = idx_header_count(&bytes)?;
    let listing = run_git_stdin(
        &["show-index", &format!("--object-format={format}")],
        &bytes,
        &[],
        QUICK_TIMEOUT,
    )
    .await?;
    let shown = listing
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .count() as u64;
    if shown != header {
        return Err(GitError::Pack(format!(
            "pack index for {} reports {header} objects but show-index listed {shown}",
            idx_path.display()
        )));
    }
    Ok(shown)
}

async fn pack_sizes(pack_path: &Path, idx_path: &Path) -> Result<(u64, u64), GitError> {
    let pack = tokio::fs::metadata(pack_path).await.map_err(GitError::Io)?;
    let idx = tokio::fs::metadata(idx_path).await.map_err(GitError::Io)?;
    Ok((pack.len(), idx.len()))
}

async fn build_ingested(
    pack_dir: &Path,
    checksum: String,
    format: ObjectFormat,
) -> Result<IngestedPack, GitError> {
    let pack_path = pack_dir.join(format!("pack-{checksum}.pack"));
    let idx_path = pack_dir.join(format!("pack-{checksum}.idx"));
    let rev_path = pack_dir.join(format!("pack-{checksum}.rev"));
    let (pack_size, idx_size) = match pack_sizes(&pack_path, &idx_path).await {
        Ok(sizes) => sizes,
        Err(GitError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(GitError::Pack(format!(
                "index-pack did not leave pack-{checksum} in {}",
                pack_dir.display()
            )));
        }
        Err(error) => return Err(error),
    };
    let rev_path = if tokio::fs::metadata(&rev_path).await.is_ok() {
        Some(rev_path)
    } else {
        None
    };
    let object_count = count_idx_objects(&idx_path, format).await?;
    Ok(IngestedPack {
        checksum,
        pack_path,
        idx_path,
        rev_path,
        pack_size,
        idx_size,
        object_count,
    })
}

/// Index an incoming pack into the bare mirror. `git index-pack --fix-thin`
/// resolves deltas against objects already present; nothing is referenced
/// until the caller publishes the ref transaction.
///
/// Returns `Ok(None)` for an empty body (a delete-only push). A pack whose
/// destination files already exist is returned as-is, so retried pushes and
/// replayed requests are idempotent.
pub async fn ingest_pack(
    bare: &Path,
    pack: &[u8],
    opts: &IngestOptions,
) -> Result<Option<IngestedPack>, GitError> {
    if pack.is_empty() {
        return Ok(None);
    }
    if let Some(max) = opts.max_bytes {
        if pack.len() as u64 > max {
            return Err(GitError::InvalidInput(format!(
                "pack is {} bytes, limit is {max}",
                pack.len()
            )));
        }
    }
    let format = repository_format(bare).await?;
    let incoming = validate_pack(pack, format)?;

    let pack_dir = bare.join("objects").join("pack");
    tokio::fs::create_dir_all(&pack_dir)
        .await
        .map_err(GitError::Io)?;

    // A complete pack keeps its name across ingestion. For thin packs the
    // fixed pack has a different hash, so this lookup simply misses and git
    // below assigns the final name.
    let candidate_pack = pack_dir.join(format!("pack-{incoming}.pack"));
    let candidate_idx = pack_dir.join(format!("pack-{incoming}.idx"));
    if tokio::fs::metadata(&candidate_pack).await.is_ok()
        && tokio::fs::metadata(&candidate_idx).await.is_ok()
    {
        return Ok(Some(build_ingested(&pack_dir, incoming, format).await?));
    }

    let git_dir = format!(
        "--git-dir={}",
        bare.to_str()
            .ok_or_else(|| GitError::InvalidInput("bare path is not UTF-8".into()))?
    );
    let mut args = vec![
        git_dir.as_str(),
        "index-pack",
        "--stdin",
        "--keep",
        "--rev-index",
        "--threads=0",
    ];
    if opts.thin {
        args.push("--fix-thin");
    }
    if opts.fsck {
        args.push("--strict");
    }
    let output = run_git_stdin(&args, pack, &[], PROTOCOL_TIMEOUT).await?;
    let checksum = parse_index_pack_hash(&output, format)?;
    if !opts.thin && checksum != incoming {
        return Err(GitError::Pack(format!(
            "index-pack named pack-{checksum} but the input hashes to {incoming}"
        )));
    }
    Ok(Some(build_ingested(&pack_dir, checksum, format).await?))
}

/// Every object reachable from `tips` exists. With `stop_at_existing_refs`,
/// objects already reachable from current refs are not walked.
pub async fn check_connectivity(
    bare: &Path,
    tips: &[String],
    stop_at_existing_refs: bool,
) -> Result<(), GitError> {
    if tips.is_empty() {
        return Ok(());
    }
    let format = repository_format(bare).await?;
    let mut normalized = Vec::with_capacity(tips.len());
    for tip in tips {
        let tip = tip.to_ascii_lowercase();
        if !is_full_sha(&tip, format) {
            return Err(GitError::InvalidInput(format!(
                "tip {tip:?} is not a full {} object id",
                format
            )));
        }
        if !has_object(bare, &tip).await? {
            return Err(GitError::MissingObject { oid: tip });
        }
        normalized.push(tip);
    }
    let git_dir = format!(
        "--git-dir={}",
        bare.to_str()
            .ok_or_else(|| GitError::InvalidInput("bare path is not UTF-8".into()))?
    );
    let mut args = vec![git_dir.as_str(), "rev-list", "--objects", "--missing=print"];
    for tip in &normalized {
        args.push(tip.as_str());
    }
    if stop_at_existing_refs {
        args.push("--not");
        args.push("--all");
    }
    let output = run_git(&args, &[], PROTOCOL_TIMEOUT).await?;
    for line in output.lines() {
        let Some(rest) = line.strip_prefix('?') else {
            continue;
        };
        let oid = rest.split_whitespace().next().unwrap_or_default();
        return Err(GitError::MissingObject {
            oid: oid.trim().to_lowercase(),
        });
    }
    Ok(())
}

/// Real-git fixtures shared by the `git` module's tests.
///
/// The environment matches [`crate::git::run_git`]: no user/system config, a
/// fixed identity and fixed timestamps, so generated commit ids are stable
/// across machines.
#[cfg(test)]
pub(crate) mod fixture {
    use std::io::Write as _;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};

    use tempfile::TempDir;

    use crate::config::ObjectFormat;

    fn command(cwd: Option<&Path>) -> Command {
        let mut cmd = Command::new("git");
        cmd.env_clear()
            .env("PATH", "/usr/local/bin:/usr/bin:/bin")
            .env("LANG", "C.UTF-8")
            .env("HOME", "/nonexistent")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .env("GIT_AUTHOR_NAME", "fixture")
            .env("GIT_AUTHOR_EMAIL", "fixture@example.invalid")
            .env("GIT_COMMITTER_NAME", "fixture")
            .env("GIT_COMMITTER_EMAIL", "fixture@example.invalid")
            .env("GIT_AUTHOR_DATE", "2000-01-01T00:00:00 +0000")
            .env("GIT_COMMITTER_DATE", "2000-01-01T00:00:00 +0000");
        if let Some(cwd) = cwd {
            cmd.arg("-C").arg(cwd);
        }
        cmd
    }

    /// Run git, returning stdout; panics with stderr on failure.
    pub(crate) fn git(cwd: Option<&Path>, args: &[&str]) -> Vec<u8> {
        let output = command(cwd)
            .args(args)
            .stdin(Stdio::null())
            .output()
            .expect("spawn git");
        assert!(
            output.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output.stdout
    }

    /// Run git with stdin bytes, returning stdout.
    pub(crate) fn git_stdin(cwd: Option<&Path>, args: &[&str], input: &[u8]) -> Vec<u8> {
        let mut child = command(cwd)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn git");
        child
            .stdin
            .take()
            .expect("stdin")
            .write_all(input)
            .expect("write stdin");
        let output = child.wait_with_output().expect("wait git");
        assert!(
            output.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output.stdout
    }

    /// `git init -q --bare [--object-format=...] <path>`.
    pub(crate) fn init_bare_repo(path: &Path, format: ObjectFormat) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("create parent");
        }
        let format_arg = format!("--object-format={format}");
        git(
            None,
            &[
                "init",
                "-q",
                "--bare",
                "--initial-branch=main",
                &format_arg,
                path.to_str().unwrap(),
            ],
        );
    }

    /// A work tree with a deterministic initial branch and identity.
    pub(crate) fn work_repo(format: ObjectFormat) -> (TempDir, PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let work = dir.path().join("work");
        let format_arg = format!("--object-format={format}");
        git(
            None,
            &[
                "init",
                "-q",
                "--initial-branch=main",
                &format_arg,
                work.to_str().unwrap(),
            ],
        );
        (dir, work)
    }

    /// A bare repository inside `dir`.
    pub(crate) fn bare_repo(dir: &Path, format: ObjectFormat) -> PathBuf {
        let bare = dir.join("bare.git");
        init_bare_repo(&bare, format);
        bare
    }

    pub(crate) fn write(work: &Path, name: &str, contents: &str) {
        let path = work.join(name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("create parent");
        }
        std::fs::write(path, contents).expect("write file");
    }

    /// Stage and commit everything, returning the new commit id.
    pub(crate) fn commit_all(work: &Path, message: &str) -> String {
        git(Some(work), &["add", "-A"]);
        git(Some(work), &["commit", "-qm", message]);
        rev(work, "HEAD")
    }

    pub(crate) fn rev(work: &Path, rev: &str) -> String {
        String::from_utf8(git(Some(work), &["rev-parse", rev]))
            .expect("utf8 rev")
            .trim()
            .to_string()
    }

    /// Pack the given revisions (rev-list syntax) to a standalone pack.
    pub(crate) fn pack_revs(work: &Path, specs: &[&str]) -> Vec<u8> {
        let mut input = Vec::new();
        for spec in specs {
            input.extend_from_slice(spec.as_bytes());
            input.push(b'\n');
        }
        git_stdin(Some(work), &["pack-objects", "--stdout", "--revs"], &input)
    }

    pub(crate) fn pack_all(work: &Path) -> Vec<u8> {
        pack_revs(work, &["HEAD"])
    }

    /// Write a commit object into a repository without touching any ref.
    ///
    /// Used to build object graphs with deliberate holes: the commit's parent
    /// may name an object that exists nowhere.
    pub(crate) fn write_synthetic_commit(bare: &Path, tree: &str, parent: &str) -> String {
        let content = format!(
            "tree {tree}\nparent {parent}\n\
             author fixture <fixture@example.invalid> 946684800 +0000\n\
             committer fixture <fixture@example.invalid> 946684800 +0000\n\
             \nsynthetic\n"
        );
        let git_dir = format!("--git-dir={}", bare.to_str().expect("utf8 path"));
        let out = git_stdin(
            None,
            &[&git_dir, "hash-object", "-t", "commit", "-w", "--stdin"],
            content.as_bytes(),
        );
        String::from_utf8(out).expect("utf8 oid").trim().to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::fixture::*;
    use super::*;

    fn flip_last(pack: &[u8]) -> Vec<u8> {
        let mut corrupted = pack.to_vec();
        let last = corrupted.len() - 1;
        corrupted[last] ^= 0xff;
        corrupted
    }

    #[tokio::test]
    async fn ingests_a_complete_pack_and_is_idempotent() {
        let (dir, work) = work_repo(ObjectFormat::Sha1);
        write(&work, "a.txt", "hello\n");
        commit_all(&work, "one");
        write(&work, "b.txt", "world\n");
        let tip = commit_all(&work, "two");
        let bare = bare_repo(dir.path(), ObjectFormat::Sha1);
        let pack = pack_all(&work);

        let first = ingest_pack(&bare, &pack, &IngestOptions::default())
            .await
            .expect("ingest")
            .expect("non-empty");
        assert_eq!(first.checksum.len(), 40);
        assert_eq!(
            first.pack_path.file_name().unwrap().to_str().unwrap(),
            format!("pack-{}.pack", first.checksum)
        );
        assert!(first.pack_path.exists());
        assert!(first.idx_path.exists());
        assert!(first.rev_path.as_ref().is_some_and(|path| path.exists()));
        assert!(first.pack_size > 0);
        assert!(first.idx_size > 0);
        // two commits, two trees, two blobs
        assert_eq!(first.object_count, 6);

        let second = ingest_pack(&bare, &pack, &IngestOptions::default())
            .await
            .expect("re-ingest")
            .expect("non-empty");
        assert_eq!(second, first);

        check_connectivity(&bare, std::slice::from_ref(&tip), false)
            .await
            .expect("connectivity");
        check_connectivity(&bare, std::slice::from_ref(&tip), true)
            .await
            .expect("connectivity stopping at refs");
    }

    #[tokio::test]
    async fn non_thin_mode_accepts_complete_packs() {
        let (dir, work) = work_repo(ObjectFormat::Sha1);
        write(&work, "a.txt", "hello\n");
        commit_all(&work, "one");
        let bare = bare_repo(dir.path(), ObjectFormat::Sha1);
        let pack = pack_all(&work);
        let opts = IngestOptions {
            thin: false,
            ..IngestOptions::default()
        };
        let ingested = ingest_pack(&bare, &pack, &opts)
            .await
            .expect("ingest")
            .expect("non-empty");
        assert_eq!(ingested.object_count, 3);
    }

    #[tokio::test]
    async fn connectivity_reports_the_missing_parent() {
        let (dir, work) = work_repo(ObjectFormat::Sha1);
        write(&work, "a.txt", "one\n");
        let first = commit_all(&work, "one");
        let tree = rev(&work, "HEAD^{tree}");
        let bare = bare_repo(dir.path(), ObjectFormat::Sha1);
        let pack = pack_all(&work);
        ingest_pack(&bare, &pack, &IngestOptions::default())
            .await
            .expect("ingest")
            .expect("non-empty");
        check_connectivity(&bare, std::slice::from_ref(&first), false)
            .await
            .expect("complete history");

        // A commit whose parent does not exist anywhere: reachable from the
        // tip, so connectivity must walk into the hole.
        let parent = "f".repeat(40);
        let tip = write_synthetic_commit(&bare, &tree, &parent);
        assert!(has_object(&bare, &tip).await.expect("has tip"));
        let error = check_connectivity(&bare, std::slice::from_ref(&tip), false)
            .await
            .expect_err("hole must be detected");
        match error {
            GitError::MissingObject { oid } => assert_eq!(oid, parent),
            other => panic!("expected MissingObject, got {other:?}"),
        }
        let error = check_connectivity(&bare, &[tip], true)
            .await
            .expect_err("stop-at-existing-refs does not hide an unreferenced tip");
        assert!(matches!(error, GitError::MissingObject { .. }));
    }

    #[tokio::test]
    async fn connectivity_rejects_non_object_ids() {
        let (dir, _work) = work_repo(ObjectFormat::Sha1);
        let bare = bare_repo(dir.path(), ObjectFormat::Sha1);
        let error = check_connectivity(&bare, &["deadbeef".to_string()], false)
            .await
            .expect_err("short oid");
        assert!(matches!(error, GitError::InvalidInput(_)));
        assert!(check_connectivity(&bare, &[], false).await.is_ok());
    }

    #[tokio::test]
    async fn empty_and_oversized_packs_are_refused() {
        let (dir, _work) = work_repo(ObjectFormat::Sha1);
        let bare = bare_repo(dir.path(), ObjectFormat::Sha1);
        assert!(ingest_pack(&bare, &[], &IngestOptions::default())
            .await
            .expect("empty")
            .is_none());

        let pack = {
            let (_inner, work) = work_repo(ObjectFormat::Sha1);
            write(&work, "a", "a\n");
            commit_all(&work, "one");
            pack_all(&work)
        };
        let opts = IngestOptions {
            max_bytes: Some(pack.len() as u64 - 1),
            ..IngestOptions::default()
        };
        let error = ingest_pack(&bare, &pack, &opts)
            .await
            .expect_err("oversized");
        assert!(matches!(error, GitError::InvalidInput(_)));
        assert!(!bare.join("objects/pack").read_dir().unwrap().any(|_| true));
    }

    #[tokio::test]
    async fn corrupt_packs_are_refused_before_git_runs() {
        let (dir, work) = work_repo(ObjectFormat::Sha1);
        write(&work, "a", "a\n");
        commit_all(&work, "one");
        let bare = bare_repo(dir.path(), ObjectFormat::Sha1);
        let pack = pack_all(&work);

        let error = ingest_pack(&bare, &flip_last(&pack), &IngestOptions::default())
            .await
            .expect_err("corrupt trailer");
        assert!(matches!(error, GitError::Pack(_)));

        // A valid checksum over a bogus header is still refused.
        let body = {
            let mut body = b"JUNK....".to_vec();
            body.extend_from_slice(&[2, 0, 0, 0]);
            let digest = sha1_digest(&body);
            body.extend_from_slice(&digest);
            body
        };
        let error = ingest_pack(&bare, &body, &IngestOptions::default())
            .await
            .expect_err("bad magic");
        assert!(matches!(error, GitError::Pack(_)));
    }

    #[tokio::test]
    async fn sha256_repositories_ingest_sha256_packs() {
        let (dir, work) = work_repo(ObjectFormat::Sha256);
        write(&work, "a.txt", "hello\n");
        let tip = commit_all(&work, "one");
        let bare = bare_repo(dir.path(), ObjectFormat::Sha256);
        assert_eq!(
            repository_format(&bare).await.expect("format"),
            ObjectFormat::Sha256
        );
        let pack = pack_all(&work);
        let ingested = ingest_pack(&bare, &pack, &IngestOptions::default())
            .await
            .expect("ingest")
            .expect("non-empty");
        assert_eq!(ingested.checksum.len(), 64);
        assert_eq!(ingested.object_count, 3);
        check_connectivity(&bare, &[tip], false)
            .await
            .expect("connectivity");
    }

    #[test]
    fn idx_header_counts_follow_the_index_version() {
        // v1: fanout table first, count in the last entry.
        let mut v1 = vec![0u8; 256 * 4];
        v1[255 * 4 + 3] = 7;
        assert_eq!(idx_header_count(&v1).unwrap(), 7);
        // v2: magic + version before the fanout table.
        let mut v2 = Vec::new();
        v2.extend_from_slice(&[0xff, 0x74, 0x4f, 0x63]);
        v2.extend_from_slice(&2u32.to_be_bytes());
        v2.extend_from_slice(&[0u8; 256 * 4]);
        let at = 8 + 255 * 4;
        v2[at + 2] = 0x01;
        v2[at + 3] = 0x23;
        assert_eq!(idx_header_count(&v2).unwrap(), 0x123);
        assert!(idx_header_count(&[]).is_err());
    }

    #[test]
    fn sha1_matches_published_vectors() {
        assert_eq!(
            hex::encode(sha1_digest(b"")),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );
        assert_eq!(
            hex::encode(sha1_digest(b"abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(
            hex::encode(sha1_digest(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
        );
        // Spanning the 56-byte padding boundary and multiple blocks.
        let long = vec![b'a'; 1000];
        assert_eq!(sha1_digest(&long).len(), 20);
        assert_ne!(sha1_digest(&long), sha1_digest(&long[..999]));
        let mut split = vec![b'a'; 55];
        assert_eq!(sha1_digest(&split).len(), 20);
        split.push(b'b');
        assert_eq!(sha1_digest(&split).len(), 20);
    }

    #[test]
    fn index_pack_output_parser_is_strict() {
        let sha = "a".repeat(40);
        assert_eq!(
            parse_index_pack_hash(format!("keep\t{sha}\n").as_bytes(), ObjectFormat::Sha1).unwrap(),
            sha
        );
        assert_eq!(
            parse_index_pack_hash(format!("pack\t{sha}\n").as_bytes(), ObjectFormat::Sha1).unwrap(),
            sha
        );
        assert!(parse_index_pack_hash(b"", ObjectFormat::Sha1).is_err());
        assert!(parse_index_pack_hash(b"keep\tdeadbeef\n", ObjectFormat::Sha1).is_err());
        assert!(
            parse_index_pack_hash(format!("unknown\t{sha}\n").as_bytes(), ObjectFormat::Sha1)
                .is_err()
        );
        assert!(
            parse_index_pack_hash(format!("pack\t{sha}\n").as_bytes(), ObjectFormat::Sha256)
                .is_err()
        );
    }
}
