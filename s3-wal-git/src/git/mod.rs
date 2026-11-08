//! Git plumbing: process execution, bare mirrors, refs and object-format rules.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use crate::config::{ObjectFormat, WalConfig};
use crate::error::GitError;

pub mod ingest;
pub mod local;
pub mod protocol;
pub mod receive;

pub use ingest::{check_connectivity, ingest_pack, IngestOptions, IngestedPack};
pub use protocol::{Protocol, Service};
pub use receive::{parse_receive, ReceiveCaps, ReceiveRequest};

/// Fast read-only git work.
pub const QUICK_TIMEOUT: Duration = Duration::from_secs(15);
/// Bundle creation or fetch.
pub const BUNDLE_TIMEOUT: Duration = Duration::from_secs(120);
/// Long protocol work.
pub const PROTOCOL_TIMEOUT: Duration = Duration::from_secs(300);
/// Longest repository slug.
pub const MAX_SLUG_LEN: usize = 128;

/// `owner/name` or a single slug, validated before it becomes a path or key.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RepoId {
    owner: String,
    name: String,
}

impl RepoId {
    /// Parse `owner/name`, `owner/name.git`, or a single segment.
    pub fn parse(value: &str) -> Result<Self, GitError> {
        let value = value.trim().trim_matches('/');
        let value = value.strip_suffix(".git").unwrap_or(value);
        let (owner, name) = match value.split_once('/') {
            Some((owner, name)) => (owner, name),
            None => ("", value),
        };
        if owner.is_empty() {
            validate_segment(value)?;
            return Ok(Self {
                owner: String::new(),
                name: value.to_string(),
            });
        }
        validate_segment(owner)?;
        validate_segment(name)?;
        Ok(Self {
            owner: owner.to_string(),
            name: name.to_string(),
        })
    }

    pub fn owner(&self) -> &str {
        &self.owner
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// Store/path form: `owner/name`, or `name` for a flat slug.
    pub fn slug(&self) -> String {
        if self.owner.is_empty() {
            self.name.clone()
        } else {
            format!("{}/{}", self.owner, self.name)
        }
    }

    /// Local directory name (`owner/name.git` or `name.git`).
    pub fn local_dir(&self, root: &Path) -> PathBuf {
        if self.owner.is_empty() {
            root.join(format!("{}.git", self.name))
        } else {
            root.join(&self.owner).join(format!("{}.git", self.name))
        }
    }
}

impl fmt::Display for RepoId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.slug())
    }
}

fn validate_segment(segment: &str) -> Result<(), GitError> {
    let ok = !segment.is_empty()
        && segment.len() <= 100
        && segment
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-')
        && !segment.starts_with('.')
        && segment != "..";
    if ok {
        Ok(())
    } else {
        Err(GitError::InvalidRepoId(segment.to_string()))
    }
}

/// Validate a repository path (one optional `owner/` segment).
pub fn validate_slug(slug: &str) -> Result<(), GitError> {
    RepoId::parse(slug).map(|_| ())?;
    if slug.len() > MAX_SLUG_LEN {
        return Err(GitError::InvalidRepoId(format!(
            "slug exceeds {MAX_SLUG_LEN} bytes"
        )));
    }
    Ok(())
}

/// Validate a full ref name before it reaches a key or git argv.
pub fn validate_refname(refname: &str) -> Result<(), GitError> {
    let bad = refname.is_empty()
        || refname.len() > 1024
        || refname.starts_with('/')
        || refname.ends_with('/')
        || refname.contains("//")
        || refname.contains("..")
        || refname.contains(char::is_control)
        || refname.contains(' ')
        || refname.contains('\\')
        || refname.ends_with(".lock")
        || !(refname.starts_with("refs/") || refname == "HEAD");
    if bad {
        Err(GitError::InvalidInput(format!(
            "invalid refname {refname:?}"
        )))
    } else {
        Ok(())
    }
}

/// A full object id for the given format.
pub fn is_full_sha(sha: &str, format: ObjectFormat) -> bool {
    sha.len() == format.hex_len() && sha.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Run git with an explicit environment and timeout; returns stdout.
pub async fn run_git(
    args: &[&str],
    env: &[(&str, &str)],
    timeout: Duration,
) -> Result<String, GitError> {
    Ok(String::from_utf8_lossy(&run_git_inner(args, None, env, timeout).await?).into_owned())
}

/// [`run_git`] with raw stdout.
pub async fn run_git_raw(
    args: &[&str],
    env: &[(&str, &str)],
    timeout: Duration,
) -> Result<Vec<u8>, GitError> {
    run_git_inner(args, None, env, timeout).await
}

/// [`run_git`] with stdin bytes.
pub async fn run_git_stdin(
    args: &[&str],
    stdin: &[u8],
    env: &[(&str, &str)],
    timeout: Duration,
) -> Result<Vec<u8>, GitError> {
    run_git_inner(args, Some(stdin.to_vec()), env, timeout).await
}

async fn run_git_inner(
    args: &[&str],
    stdin: Option<Vec<u8>>,
    env: &[(&str, &str)],
    timeout: Duration,
) -> Result<Vec<u8>, GitError> {
    let output = run_git_output(args, stdin, env, timeout).await?;
    if !output.status.success() {
        return Err(GitError::Subprocess {
            command: format!("{args:?}"),
            status: output.status.to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        });
    }
    Ok(output.stdout)
}

/// Spawn git with a piped stdin/stdout for streaming responses. The caller
/// owns the child and must keep it alive until the stdout stream ends; the
/// process group is killed when the child is dropped.
pub async fn spawn_git_stdin(
    args: &[&str],
    stdin: Vec<u8>,
    env: &[(&str, &str)],
) -> Result<(tokio::process::Child, tokio::process::ChildStdout), GitError> {
    use std::os::unix::process::CommandExt;
    use tokio::io::AsyncWriteExt as _;

    let mut cmd = tokio::process::Command::new("git");
    cmd.args(args)
        .env_clear()
        .env("PATH", "/usr/local/bin:/usr/bin:/bin")
        .env("LANG", "C.UTF-8")
        .env("HOME", "/nonexistent")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    for (key, value) in env {
        cmd.env(key, value);
    }
    cmd.as_std_mut().process_group(0);
    let mut child = cmd.spawn().map_err(|error| GitError::Other(error.into()))?;
    if let Some(mut pipe) = child.stdin.take() {
        tokio::spawn(async move {
            let _ = pipe.write_all(&stdin).await;
            let _ = pipe.shutdown().await;
        });
    }
    if let Some(mut stderr) = child.stderr.take() {
        tokio::spawn(async move {
            let _ = tokio::io::copy(&mut stderr, &mut tokio::io::sink()).await;
        });
    }
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| GitError::Other(anyhow::anyhow!("git stdout was not piped")))?;
    Ok((child, stdout))
}

/// Run git and return its raw output even when the exit status is non-zero.
/// Callers that parse diagnostics (fsck) must not lose stdout on failure.
pub async fn run_git_output(
    args: &[&str],
    stdin: Option<Vec<u8>>,
    env: &[(&str, &str)],
    timeout: Duration,
) -> Result<std::process::Output, GitError> {
    use std::os::unix::process::CommandExt;

    fn kill_group(pid: u32) {
        unsafe {
            let _ = libc::kill(-(pid as libc::pid_t), libc::SIGKILL);
        }
    }

    let mut cmd = tokio::process::Command::new("git");
    cmd.args(args)
        .env_clear()
        .env("PATH", "/usr/local/bin:/usr/bin:/bin")
        .env("LANG", "C.UTF-8")
        .env("HOME", "/nonexistent")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    for (key, value) in env {
        cmd.env(key, value);
    }
    cmd.as_std_mut().process_group(0);
    let mut child = cmd.spawn().map_err(|error| GitError::Other(error.into()))?;
    let pid = child.id();
    let writer = match child.stdin.take() {
        Some(mut pipe) => {
            let input = stdin.unwrap_or_default();
            Some(tokio::spawn(async move {
                use tokio::io::AsyncWriteExt as _;
                let _ = pipe.write_all(&input).await;
                let _ = pipe.shutdown().await;
            }))
        }
        None => None,
    };
    let result = tokio::time::timeout(timeout, child.wait_with_output()).await;
    if let Some(pid) = pid {
        kill_group(pid);
    }
    let output = match result {
        Err(_) => return Err(GitError::Timeout(format!("{args:?}"))),
        Ok(Ok(output)) => output,
        Ok(Err(error)) => return Err(GitError::Other(error.into())),
    };
    if let Some(writer) = writer {
        let _ = writer.await;
    }
    Ok(output)
}

/// Initialise a bare mirror and hide the configured refs.
pub async fn init_bare(cfg: &WalConfig, bare: &Path) -> Result<(), GitError> {
    if let Some(parent) = bare.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(GitError::Io)?;
    }
    let Some(path) = bare.to_str() else {
        return Err(GitError::InvalidInput("bare path is not UTF-8".into()));
    };
    let format = format!("--object-format={}", cfg.object_format);
    run_git(
        &[
            "init",
            "--bare",
            &format!("--initial-branch={}", cfg.default_branch),
            &format,
            path,
        ],
        &[],
        QUICK_TIMEOUT,
    )
    .await?;
    let git_dir = format!("--git-dir={}", bare.display());
    for hide in &cfg.hide_refs {
        for key in ["uploadpack.hideRefs", "transfer.hideRefs"] {
            let _ = run_git(
                &[&git_dir, "config", "--add", key, hide],
                &[],
                QUICK_TIMEOUT,
            )
            .await;
        }
    }
    Ok(())
}

/// The head of `refname`, or `None` when absent.
pub async fn head_of_ref(bare: &Path, refname: &str) -> Result<Option<String>, GitError> {
    if !bare.join("HEAD").exists() {
        return Ok(None);
    }
    validate_refname(refname)?;
    let git_dir = format!("--git-dir={}", bare.display());
    match run_git(
        &[&git_dir, "rev-parse", "--verify", refname],
        &[],
        QUICK_TIMEOUT,
    )
    .await
    {
        Ok(out) => Ok(Some(out.trim().to_string())),
        Err(_) => Ok(None),
    }
}

/// Symbolic HEAD target (`refs/heads/main`), if any.
pub async fn symbolic_head(bare: &Path) -> Result<Option<String>, GitError> {
    if !bare.join("HEAD").exists() {
        return Ok(None);
    }
    let text = tokio::fs::read_to_string(bare.join("HEAD"))
        .await
        .map_err(GitError::Io)?;
    Ok(text
        .lines()
        .next()
        .and_then(|line| line.strip_prefix("ref: "))
        .map(|value| value.trim().to_string()))
}

/// All branches and tags, plus `extra_prefixes`, plus symbolic HEAD and
/// peeled tag targets.
#[derive(Debug, Clone, Default)]
pub struct RefSnapshot {
    pub refs: BTreeMap<String, String>,
    pub head: Option<String>,
    pub peeled: BTreeMap<String, String>,
}

/// Every tracked ref in the mirror.
pub async fn snapshot_refs(
    bare: &Path,
    extra_prefixes: &[String],
) -> Result<RefSnapshot, GitError> {
    let git_dir = format!("--git-dir={}", bare.display());
    // `show-ref` exits 1 when the repository has no refs, which is
    // indistinguishable from a real failure through `run_git`. `for-each-ref`
    // exits 0 for an empty repository and lets genuine failures propagate.
    let out = run_git(
        &[
            &git_dir,
            "for-each-ref",
            "--format=%(objectname) %(refname)",
            "refs/heads",
            "refs/tags",
        ],
        &[],
        QUICK_TIMEOUT,
    )
    .await?;
    let mut refs = BTreeMap::new();
    for line in out.lines() {
        if let Some((sha, name)) = line.split_once(' ') {
            refs.insert(name.trim().to_string(), sha.trim().to_lowercase());
        }
    }
    for prefix in extra_prefixes {
        let listed = run_git(
            &[
                &git_dir,
                "for-each-ref",
                "--format=%(objectname) %(refname)",
                prefix,
            ],
            &[],
            QUICK_TIMEOUT,
        )
        .await?;
        for line in listed.lines() {
            if let Some((sha, name)) = line.split_once(' ') {
                refs.insert(name.trim().to_string(), sha.trim().to_lowercase());
            }
        }
    }
    let mut peeled = BTreeMap::new();
    let peeled_out = run_git(
        &[
            &git_dir,
            "for-each-ref",
            "--format=%(objectname) %(*objectname) %(refname)",
            "refs/tags/",
        ],
        &[],
        QUICK_TIMEOUT,
    )
    .await
    .unwrap_or_default();
    for line in peeled_out.lines() {
        let mut parts = line.splitn(3, ' ');
        if let (Some(_tag), Some(target), Some(name)) = (parts.next(), parts.next(), parts.next()) {
            if !target.trim().is_empty() {
                peeled.insert(name.trim().to_string(), target.trim().to_string());
            }
        }
    }
    let head = symbolic_head(bare).await?;
    Ok(RefSnapshot { refs, head, peeled })
}

/// Backwards-compatible map view.
pub async fn list_refs(
    bare: &Path,
    extra_prefixes: &[String],
) -> Result<BTreeMap<String, String>, GitError> {
    Ok(snapshot_refs(bare, extra_prefixes).await?.refs)
}

/// Set (`Some`) or delete (`None`) one ref.
pub async fn set_ref(bare: &Path, refname: &str, sha: Option<&str>) -> Result<(), GitError> {
    validate_refname(refname)?;
    let git_dir = format!("--git-dir={}", bare.display());
    match sha {
        Some(sha) => {
            run_git(&[&git_dir, "update-ref", refname, sha], &[], QUICK_TIMEOUT).await?;
        }
        None => {
            run_git(&[&git_dir, "update-ref", "-d", refname], &[], QUICK_TIMEOUT).await?;
        }
    }
    Ok(())
}

/// Compare-and-swap one ref. Distinguishes "tip moved" from a git failure.
pub async fn cas_update(
    bare: &Path,
    refname: &str,
    expected_old: Option<&str>,
    new_sha: &str,
) -> Result<(), GitError> {
    validate_refname(refname)?;
    let git_dir = format!("--git-dir={}", bare.display());
    let args = [
        git_dir.as_str(),
        "update-ref",
        refname,
        new_sha,
        expected_old.unwrap_or(""),
    ];
    if let Err(error) = run_git(&args, &[], QUICK_TIMEOUT).await {
        let now = head_of_ref(bare, refname).await.unwrap_or(None);
        if now.as_deref() != expected_old {
            return Err(GitError::RefConflict {
                name: refname.to_string(),
                expected: expected_old.map(str::to_string),
                actual: now,
            });
        }
        return Err(error);
    }
    Ok(())
}

/// Number of commits reachable from `to` but not from `from`.
pub async fn count_commits(bare: &Path, from: &str, to: &str) -> Result<u64, GitError> {
    let git_dir = format!("--git-dir={}", bare.display());
    let out = run_git(
        &[&git_dir, "rev-list", "--count", &format!("{from}..{to}")],
        &[],
        QUICK_TIMEOUT,
    )
    .await?;
    out.trim()
        .parse()
        .map_err(|error| GitError::Other(anyhow::anyhow!("rev-list count: {error}")))
}

/// Atomic multi-ref update (`git update-ref --stdin`).
pub async fn apply_ref_transaction(bare: &Path, updates: &[RefUpdate]) -> Result<(), GitError> {
    if updates.is_empty() {
        return Ok(());
    }
    let mut body = String::from("start\n");
    for update in updates {
        validate_refname(&update.refname)?;
        match &update.new_sha {
            Some(new) => {
                body.push_str(&format!(
                    "update {} {} {}\n",
                    update.refname,
                    new,
                    update.expected_old.as_deref().unwrap_or("")
                ));
            }
            None => match update.expected_old.as_deref() {
                Some(old) => body.push_str(&format!("delete {} {old}\n", update.refname)),
                // An empty old OID means "must not exist", which would make
                // an unconditional delete impossible. Omit the field.
                None => body.push_str(&format!("delete {}\n", update.refname)),
            },
        }
    }
    body.push_str("prepare\ncommit\n");
    let git_dir = format!("--git-dir={}", bare.display());
    run_git_stdin(
        &[&git_dir, "update-ref", "--stdin"],
        body.as_bytes(),
        &[],
        QUICK_TIMEOUT,
    )
    .await?;
    Ok(())
}

/// One conditional ref update: `new` replaces `expected`, or deletes the ref
/// when `new` is `None`. An empty `expected` means the ref must not exist.
pub async fn update_ref_cas(
    bare: &Path,
    refname: &str,
    new: Option<&str>,
    expected: Option<&str>,
) -> Result<(), GitError> {
    validate_refname(refname)?;
    let git_dir = format!("--git-dir={}", bare.display());
    let expected = expected.unwrap_or("");
    match new {
        Some(new) => {
            run_git(
                &[&git_dir, "update-ref", refname, new, expected],
                &[],
                QUICK_TIMEOUT,
            )
            .await?
        }
        None => {
            run_git(
                &[&git_dir, "update-ref", "-d", refname, expected],
                &[],
                QUICK_TIMEOUT,
            )
            .await?
        }
    };
    Ok(())
}

/// One ref change inside a transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
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

/// Whether `old` is an ancestor of `new` (fast-forward).
pub async fn is_ancestor(bare: &Path, old: &str, new: &str) -> bool {
    run_git(
        &[
            &format!("--git-dir={}", bare.display()),
            "merge-base",
            "--is-ancestor",
            old,
            new,
        ],
        &[],
        QUICK_TIMEOUT,
    )
    .await
    .is_ok()
}

/// Resolve a revision to a full object id.
pub async fn resolve_oid(bare: &Path, rev: &str) -> Result<Option<String>, GitError> {
    let git_dir = format!("--git-dir={}", bare.display());
    match run_git(
        &[&git_dir, "rev-parse", "--verify", rev],
        &[],
        QUICK_TIMEOUT,
    )
    .await
    {
        Ok(out) => Ok(Some(out.trim().to_string())),
        Err(_) => Ok(None),
    }
}

/// Whether an object exists in the mirror.
pub async fn has_object(bare: &Path, oid: &str) -> Result<bool, GitError> {
    let git_dir = format!("--git-dir={}", bare.display());
    Ok(
        run_git(&[&git_dir, "cat-file", "-e", oid], &[], QUICK_TIMEOUT)
            .await
            .is_ok(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repo_ids_accept_namespaces_and_refuse_escapes() {
        let id = RepoId::parse("acme/app.git").unwrap();
        assert_eq!(id.slug(), "acme/app");
        assert_eq!(RepoId::parse("app").unwrap().slug(), "app");
        for bad in ["", "..", "../x", "a/../b", ".hidden", "a/b/c", "a b"] {
            assert!(RepoId::parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn refnames_are_validated() {
        for good in ["refs/heads/main", "refs/tags/v1", "HEAD"] {
            assert!(validate_refname(good).is_ok(), "{good}");
        }
        for bad in ["", "main", "refs/../x", "refs/heads/a b", "/refs/heads/x"] {
            assert!(validate_refname(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn sha_length_follows_object_format() {
        assert!(is_full_sha(&"a".repeat(40), ObjectFormat::Sha1));
        assert!(!is_full_sha(&"a".repeat(40), ObjectFormat::Sha256));
        assert!(is_full_sha(&"a".repeat(64), ObjectFormat::Sha256));
    }
}
