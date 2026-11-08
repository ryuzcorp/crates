//! Repository layout, object format and all tunable limits.

use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use crate::error::ConfigError;

type BundleKeyFn = dyn Fn(&str, &str, &str, &str) -> String + Send + Sync;

/// Hash used by the repository.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ObjectFormat {
    #[default]
    Sha1,
    Sha256,
}

impl ObjectFormat {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sha1 => "sha1",
            Self::Sha256 => "sha256",
        }
    }

    /// Hex length of a full object id.
    pub fn hex_len(self) -> usize {
        match self {
            Self::Sha1 => 40,
            Self::Sha256 => 64,
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "sha1" => Some(Self::Sha1),
            "sha256" => Some(Self::Sha256),
            _ => None,
        }
    }
}

impl fmt::Display for ObjectFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How one repository's objects are stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StorageMode {
    /// One immutable full-history bundle per tip. Simple; uploads O(repo).
    #[default]
    Bundle,
    /// Immutable incoming packs plus the manifest pack set. Uploads O(push).
    Pack,
}

impl StorageMode {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "bundle" => Some(Self::Bundle),
            "pack" => Some(Self::Pack),
            _ => None,
        }
    }
}

/// Where a repository's manifest and tip bundles live.
#[derive(Clone)]
pub struct Layout {
    prefix: String,
    manifest_name: String,
    bundle_key: Arc<BundleKeyFn>,
}

impl fmt::Debug for Layout {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Layout")
            .field("prefix", &self.prefix)
            .field("manifest_name", &self.manifest_name)
            .finish_non_exhaustive()
    }
}

impl Default for Layout {
    fn default() -> Self {
        Self::new("git")
    }
}

impl Layout {
    pub fn new(prefix: impl Into<String>) -> Self {
        Self {
            prefix: prefix.into(),
            manifest_name: "MANIFEST.json".to_string(),
            bundle_key: Arc::new(|prefix, slug, refname, sha| {
                format!("{prefix}/{slug}/{refname}/{sha}.bundle")
            }),
        }
    }

    pub fn with_bundle_key<F>(mut self, key: F) -> Self
    where
        F: Fn(&str, &str, &str) -> String + Send + Sync + 'static,
    {
        self.bundle_key = Arc::new(move |_, slug, refname, sha| key(slug, refname, sha));
        self
    }

    pub fn with_manifest_name(mut self, name: impl Into<String>) -> Self {
        self.manifest_name = name.into();
        self
    }

    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    pub fn manifest_key(&self, slug: &str) -> String {
        format!("{}/{slug}/{}", self.prefix, self.manifest_name)
    }

    pub fn repo_prefix(&self, slug: &str) -> String {
        format!("{}/{slug}/", self.prefix)
    }

    pub fn bundle_key(&self, slug: &str, refname: &str, sha: &str) -> String {
        (self.bundle_key)(&self.prefix, slug, refname, sha)
    }

    pub fn bundle_prefix<'k>(&self, key: &'k str) -> Option<&'k str> {
        key.strip_suffix(".bundle")?
            .rsplit_once('/')
            .map(|(p, _)| p)
    }

    /// Object keys shared by both storage modes.
    pub fn log_key(&self, slug: &str, first_seq: u64) -> String {
        format!("{}/{slug}/log/{:016x}.json", self.prefix, first_seq)
    }

    pub fn checkpoint_key(&self, slug: &str, seq: u64) -> String {
        format!(
            "{}/{slug}/checkpoints/{:016x}/checkpoint.json",
            self.prefix, seq
        )
    }

    pub fn checkpoint_refs_key(&self, slug: &str, seq: u64) -> String {
        format!("{}/{slug}/checkpoints/{:016x}/refs.json", self.prefix, seq)
    }

    pub fn pack_key(&self, slug: &str, checksum: &str, extension: &str) -> String {
        format!("{}/{slug}/wal/{checksum}.{extension}", self.prefix)
    }

    pub fn lease_key(&self, slug: &str, name: &str) -> String {
        format!("{}/{slug}/leases/{name}.json", self.prefix)
    }

    pub fn policy_key(&self, slug: &str) -> String {
        format!("{}/{slug}/policy.json", self.prefix)
    }

    pub fn event_cursor_key(&self, slug: &str) -> String {
        format!("{}/{slug}/events/cursor.json", self.prefix)
    }

    pub fn fsck_key(&self, slug: &str) -> String {
        format!("{}/{slug}/fsck.json", self.prefix)
    }

    pub fn lfs_object_key(&self, slug: &str, oid: &str) -> String {
        let (a, b) = oid.split_at(oid.len().min(2));
        let rest = oid.get(a.len()..).unwrap_or("");
        format!("{}/{slug}/lfs/objects/{a}/{b}{rest}", self.prefix)
    }
}

/// Resource ceilings. `0` means unlimited where noted.
#[derive(Debug, Clone)]
pub struct Limits {
    /// Largest accepted smart-HTTP request body.
    pub max_body_bytes: u64,
    /// Largest accepted push pack.
    pub max_push_bytes: u64,
    /// Largest bundle uploaded in bundle mode.
    pub max_bundle_bytes: u64,
    /// Largest repository (live packs + bundles); 0 = unlimited.
    pub max_repo_bytes: u64,
    /// Most refs a repository may advertise.
    pub max_refs: usize,
    /// Most refs one push may update.
    pub max_push_refs: usize,
    /// Concurrent pushes per repository.
    pub max_concurrent_pushes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_body_bytes: 512 * 1024 * 1024,
            max_push_bytes: 512 * 1024 * 1024,
            max_bundle_bytes: 1024 * 1024 * 1024,
            max_repo_bytes: 0,
            max_refs: 100_000,
            max_push_refs: 10_000,
            max_concurrent_pushes: 2,
        }
    }
}

/// Local state and object layout for one process's repositories.
#[derive(Debug, Clone)]
pub struct WalConfig {
    pub repos_dir: PathBuf,
    pub layout: Layout,
    pub default_branch: String,
    pub hide_refs: Vec<String>,
    pub extra_ref_prefixes: Vec<String>,
    pub only_refs: Vec<String>,
    pub storage: StorageMode,
    /// In bundle mode, switch a repository to packs when its last bundle
    /// exceeded this size. 0 disables the hint.
    pub pack_threshold_bytes: u64,
    pub object_format: ObjectFormat,
    pub limits: Limits,
    /// Conditional-GET freshness window. ZERO always checks.
    pub freshness_ttl: Duration,
    pub publish_retries: u32,
    pub publish_retry_base: Duration,
    pub publish_retry_max: Duration,
    /// Coalesce concurrent publishes for this window.
    pub batch_window: Duration,
    pub max_batch: usize,
    pub checkpoint_every_entries: u64,
    pub checkpoint_interval: Duration,
    pub checkpoint_tail_bytes: u64,
    pub lease_ttl: Duration,
    pub fsck_interval: Duration,
    /// Grace before an unreachable object is collected.
    pub retention_grace: Duration,
}

impl WalConfig {
    pub fn new(repos_dir: impl Into<PathBuf>, layout: Layout) -> Self {
        Self {
            repos_dir: repos_dir.into(),
            layout,
            default_branch: "main".to_string(),
            hide_refs: Vec::new(),
            extra_ref_prefixes: Vec::new(),
            only_refs: Vec::new(),
            storage: StorageMode::Bundle,
            pack_threshold_bytes: 1024 * 1024,
            object_format: ObjectFormat::Sha1,
            limits: Limits::default(),
            freshness_ttl: Duration::ZERO,
            publish_retries: 6,
            publish_retry_base: Duration::from_millis(20),
            publish_retry_max: Duration::from_secs(2),
            batch_window: Duration::from_millis(5),
            max_batch: 32,
            checkpoint_every_entries: 256,
            checkpoint_interval: Duration::from_secs(60 * 60),
            checkpoint_tail_bytes: 8 * 1024 * 1024,
            lease_ttl: Duration::from_secs(60),
            fsck_interval: Duration::from_secs(7 * 24 * 60 * 60),
            retention_grace: Duration::from_secs(7 * 24 * 60 * 60),
        }
    }

    pub fn with_hidden_refs(mut self, prefixes: impl IntoIterator<Item = String>) -> Self {
        self.hide_refs.extend(prefixes);
        self
    }

    pub fn with_extra_ref_prefixes(mut self, prefixes: impl IntoIterator<Item = String>) -> Self {
        self.extra_ref_prefixes.extend(prefixes);
        self
    }

    pub fn with_only_refs(mut self, refs: impl IntoIterator<Item = String>) -> Self {
        self.only_refs.extend(refs);
        self
    }

    pub fn with_storage(mut self, storage: StorageMode) -> Self {
        self.storage = storage;
        self
    }

    pub fn with_object_format(mut self, format: ObjectFormat) -> Self {
        self.object_format = format;
        self
    }

    pub fn mirror_path(&self, slug: &str) -> PathBuf {
        self.repos_dir.join(format!("{slug}.git"))
    }

    pub(crate) fn filter_refs(&self, refs: BTreeMap<String, String>) -> BTreeMap<String, String> {
        if self.only_refs.is_empty() {
            return refs;
        }
        refs.into_iter()
            .filter(|(refname, _)| self.only_refs.iter().any(|only| only == refname))
            .collect()
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        let mut problems = Vec::new();
        if self.repos_dir.as_os_str().is_empty() {
            problems.push("repos_dir must not be empty".to_string());
        }
        if self.default_branch.is_empty()
            || self.default_branch.contains(char::is_whitespace)
            || self.default_branch.contains("..")
        {
            problems.push(format!(
                "default_branch {:?} is not a valid branch name",
                self.default_branch
            ));
        }
        if self.publish_retries == 0 {
            problems.push("publish_retries must be at least 1".to_string());
        }
        if self.max_batch == 0 {
            problems.push("max_batch must be at least 1".to_string());
        }
        if self.limits.max_refs == 0 {
            problems.push("limits.max_refs must be at least 1".to_string());
        }
        if self.limits.max_body_bytes == 0 {
            problems.push("limits.max_body_bytes must be at least 1".to_string());
        }
        if self.lease_ttl < Duration::from_secs(1) {
            problems.push("lease_ttl must be at least 1s".to_string());
        }
        for refname in &self.only_refs {
            if !refname.starts_with("refs/") {
                problems.push(format!("only_refs entry {refname:?} must start with refs/"));
            }
        }
        if problems.is_empty() {
            Ok(())
        } else {
            Err(ConfigError::new(problems))
        }
    }
}

/// Temp path unique to this call.
pub(crate) fn tmp_path(prefix: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    // Slugs may be `owner/name`; keep every temp path a single file name.
    let safe: String = prefix
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
                ch
            } else {
                '_'
            }
        })
        .collect();
    std::env::temp_dir().join(format!("s3-wal-git-{safe}-{}-{n}", std::process::id()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_keys_are_stable() {
        let layout = Layout::new("git");
        assert_eq!(layout.manifest_key("demo"), "git/demo/MANIFEST.json");
        assert_eq!(
            layout.bundle_key("demo", "refs/heads/main", "abc"),
            "git/demo/refs/heads/main/abc.bundle"
        );
        assert_eq!(
            layout.log_key("demo", 7),
            "git/demo/log/0000000000000007.json"
        );
        assert_eq!(
            layout.pack_key("demo", "abc", "pack"),
            "git/demo/wal/abc.pack"
        );
    }

    #[test]
    fn custom_bundle_layout_is_honoured() {
        let layout = Layout::new("git").with_bundle_key(|slug, refname, sha| {
            let prefix = if refname.ends_with("/preview") {
                "preview"
            } else {
                "main"
            };
            format!("git/{slug}/{prefix}/{sha}.bundle")
        });
        assert_eq!(
            layout.bundle_key("demo", "refs/heads/preview", "sha"),
            "git/demo/preview/sha.bundle"
        );
        assert_eq!(
            layout.bundle_key("demo", "refs/heads/main", "sha"),
            "git/demo/main/sha.bundle"
        );
    }

    #[test]
    fn validation_reports_all_problems() {
        let mut config = WalConfig::new("/tmp/git", Layout::new("git"));
        config.publish_retries = 0;
        config.max_batch = 0;
        config.only_refs.push("main".into());
        let error = config.validate().unwrap_err();
        assert!(error.problems.len() >= 3, "{:?}", error.problems);
    }
}
