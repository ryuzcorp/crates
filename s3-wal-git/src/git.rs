//! Git plumbing: process execution, bare mirrors and ref updates.
//!
//! Every git invocation clears the environment (no user config can change
//! behavior), runs in its own process group so a timeout kills grandchildren,
//! and is bounded by a timeout.

use std::collections::BTreeMap;
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use anyhow::Context as _;

use crate::config::WalConfig;

/// Default timeout for a read-only git command.
pub const QUICK_TIMEOUT: Duration = Duration::from_secs(15);
/// Timeout for bundle creation or fetch, which can move a whole repository.
pub const BUNDLE_TIMEOUT: Duration = Duration::from_secs(120);
/// Longest accepted slug. Slugs become local directory names and bucket keys.
pub const MAX_SLUG_LEN: usize = 64;

/// Slugs are `[A-Za-z0-9_-]`, must not be empty, start or end with `-`, and
/// fit [`MAX_SLUG_LEN`].
pub fn validate_slug(slug: &str) -> anyhow::Result<()> {
    let ok = !slug.is_empty()
        && slug.len() <= MAX_SLUG_LEN
        && slug
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        && !slug.starts_with('-')
        && !slug.ends_with('-');
    if ok {
        Ok(())
    } else {
        anyhow::bail!("bad slug {slug:?}")
    }
}

/// A full (40 hex) commit id, as required for a published tip.
pub fn is_full_sha(sha: &str) -> bool {
    sha.len() == 40 && sha.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Run git with an explicit environment and timeout; returns stdout.
pub async fn run_git(
    args: &[&str],
    env: &[(&str, &str)],
    timeout: Duration,
) -> anyhow::Result<String> {
    Ok(String::from_utf8_lossy(&run_git_inner(args, None, env, timeout).await?).into_owned())
}

/// [`run_git`] with raw stdout (blob bytes are not UTF-8).
pub async fn run_git_raw(
    args: &[&str],
    env: &[(&str, &str)],
    timeout: Duration,
) -> anyhow::Result<Vec<u8>> {
    run_git_inner(args, None, env, timeout).await
}

/// [`run_git`] with stdin bytes; returns raw stdout.
pub async fn run_git_stdin(
    args: &[&str],
    stdin: &[u8],
    env: &[(&str, &str)],
    timeout: Duration,
) -> anyhow::Result<Vec<u8>> {
    run_git_inner(args, Some(stdin.to_vec()), env, timeout).await
}

async fn run_git_inner(
    args: &[&str],
    stdin: Option<Vec<u8>>,
    env: &[(&str, &str)],
    timeout: Duration,
) -> anyhow::Result<Vec<u8>> {
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
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.as_std_mut().process_group(0);
    let mut child = cmd.spawn().context("spawn git")?;
    let pid = child.id();
    let writer = match child.stdin.take() {
        Some(mut pipe) => {
            let input = stdin.unwrap_or_default();
            Some(tokio::spawn(async move {
                use tokio::io::AsyncWriteExt;
                let _ = pipe.write_all(&input).await;
                let _ = pipe.shutdown().await;
            }))
        }
        None => None,
    };
    let result = tokio::time::timeout(timeout, child.wait_with_output()).await;
    #[cfg(unix)]
    if let Some(pid) = pid {
        kill_group(pid);
    }
    let output = result
        .map_err(|_| anyhow::anyhow!("git {args:?} timed out"))?
        .context("wait git")?;
    if let Some(writer) = writer {
        let _ = writer.await;
    }
    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("git {args:?} exit {:?}\n{err}", output.status.code());
    }
    Ok(output.stdout)
}

/// Initialise a bare mirror with HEAD at the configured default branch and
/// hide the configured ref prefixes from advertisement.
pub async fn init_bare(cfg: &WalConfig, bare: &Path) -> anyhow::Result<()> {
    if let Some(parent) = bare.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let Some(path) = bare.to_str() else {
        anyhow::bail!("bare mirror path is not valid UTF-8: {}", bare.display());
    };
    run_git(
        &[
            "init",
            "--bare",
            &format!("--initial-branch={}", cfg.default_branch),
            path,
        ],
        &[],
        QUICK_TIMEOUT,
    )
    .await?;
    let git_dir = format!("--git-dir={}", bare.display());
    for hide in &cfg.hide_refs {
        for key in ["uploadpack.hideRefs", "transfer.hideRefs"] {
            // Best effort per key: an older git without transfer.hideRefs must
            // not fail the init.
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

/// The head of `refname`, or `None` when the mirror is empty or the ref does
/// not exist.
pub async fn head_of_ref(bare: &Path, refname: &str) -> anyhow::Result<Option<String>> {
    if !bare.join("HEAD").exists() {
        return Ok(None);
    }
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

/// Every branch and tag in the mirror, plus every ref under
/// `extra_prefixes` (misses there are not failures).
pub async fn list_refs(
    bare: &Path,
    extra_prefixes: &[String],
) -> anyhow::Result<BTreeMap<String, String>> {
    let git_dir = format!("--git-dir={}", bare.display());
    let out = run_git(
        &[&git_dir, "show-ref", "--heads", "--tags"],
        &[],
        QUICK_TIMEOUT,
    )
    .await
    .unwrap_or_default();
    let mut refs = BTreeMap::new();
    for line in out.lines() {
        if let Some((sha, name)) = line.split_once(' ') {
            refs.insert(name.trim().to_string(), sha.trim().to_lowercase());
        }
    }
    for prefix in extra_prefixes {
        // `for-each-ref` exits 0 with empty output when nothing matches,
        // unlike `show-ref <pattern>`.
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
        .await
        .unwrap_or_default();
        for line in listed.lines() {
            if let Some((sha, name)) = line.split_once(' ') {
                refs.insert(name.trim().to_string(), sha.trim().to_lowercase());
            }
        }
    }
    Ok(refs)
}

/// Set (`Some`) or delete (`None`) one ref.
pub async fn set_ref(bare: &Path, refname: &str, sha: Option<&str>) -> anyhow::Result<()> {
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

/// Compare-and-swap one ref. An error is reported as "tip moved under this
/// update" when a re-read shows the ref is no longer at `expected_old`;
/// otherwise the git failure is returned.
pub async fn cas_update(
    bare: &Path,
    refname: &str,
    expected_old: Option<&str>,
    new_sha: &str,
) -> anyhow::Result<()> {
    let git_dir = format!("--git-dir={}", bare.display());
    // An empty old value is git's "the ref must not exist yet".
    let args = [
        git_dir.as_str(),
        "update-ref",
        refname,
        new_sha,
        expected_old.unwrap_or(""),
    ];
    if let Err(e) = run_git(&args, &[], QUICK_TIMEOUT).await {
        let now = head_of_ref(bare, refname).await.unwrap_or(None);
        if now.as_deref() != expected_old {
            anyhow::bail!(
                "tip moved under this update: {refname} is {}",
                now.as_deref().unwrap_or("<absent>")
            );
        }
        return Err(e.context("update-ref"));
    }
    Ok(())
}

/// Whether `old` is an ancestor of `new` (a fast-forward update).
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slug_rules_match_the_public_contract() {
        for slug in ["demo", "a", "a-b_c", "0"] {
            assert!(validate_slug(slug).is_ok(), "{slug}");
        }
        for slug in ["", "-a", "a-", "a b", "a/b", "a.b", &"a".repeat(65)] {
            assert!(validate_slug(slug).is_err(), "{slug}");
        }
    }

    #[test]
    fn full_sha_requires_40_hex_digits() {
        assert!(is_full_sha(&"a".repeat(40)));
        assert!(!is_full_sha(&"a".repeat(39)));
        assert!(!is_full_sha(&"g".repeat(40)));
    }
}
