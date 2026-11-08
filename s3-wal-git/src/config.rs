//! Repository key layout and local-mirror settings.

use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;

type BundleKeyFn = dyn Fn(&str, &str, &str, &str) -> String + Send + Sync;

/// Where a repository's manifest and tip bundles live.
///
/// The default bundle key is `{prefix}/{slug}/{refname}/{sha}.bundle` (the
/// refname keeps its slashes), and the manifest is
/// `{prefix}/{slug}/MANIFEST.json`. Applications with a different layout pass
/// their own key function to [`Layout::with_bundle_key`].
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
    /// Layout under `prefix` (usually `"git"`).
    pub fn new(prefix: impl Into<String>) -> Self {
        Self {
            prefix: prefix.into(),
            manifest_name: "MANIFEST.json".to_string(),
            bundle_key: Arc::new(|prefix_default, slug, refname, sha| {
                format!("{prefix_default}/{slug}/{refname}/{sha}.bundle")
            }),
        }
    }

    /// Replace the bundle-key function: `(slug, refname, sha) -> key`.
    pub fn with_bundle_key<F>(mut self, key: F) -> Self
    where
        F: Fn(&str, &str, &str) -> String + Send + Sync + 'static,
    {
        self.bundle_key = Arc::new(move |_, slug, refname, sha| key(slug, refname, sha));
        self
    }

    /// Override the manifest object's file name (default `MANIFEST.json`).
    pub fn with_manifest_name(mut self, name: impl Into<String>) -> Self {
        self.manifest_name = name.into();
        self
    }

    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    /// `{prefix}/{slug}/MANIFEST.json`
    pub fn manifest_key(&self, slug: &str) -> String {
        format!("{}/{slug}/{}", self.prefix, self.manifest_name)
    }

    /// `{prefix}/{slug}/` — the whole repository scope.
    pub fn repo_prefix(&self, slug: &str) -> String {
        format!("{}/{slug}/", self.prefix)
    }

    /// The bundle key for one ref tip.
    pub fn bundle_key(&self, slug: &str, refname: &str, sha: &str) -> String {
        (self.bundle_key)(&self.prefix, slug, refname, sha)
    }

    /// The key prefix holding one ref's tip bundles, derived from a bundle
    /// key. `None` when the key does not end in `.bundle`.
    pub fn bundle_prefix<'k>(&self, key: &'k str) -> Option<&'k str> {
        key.strip_suffix(".bundle")?
            .rsplit_once('/')
            .map(|(p, _)| p)
    }
}

/// Local state and object layout for one process's repositories.
///
/// `repos_dir` hosts the bare mirrors (`{repos_dir}/{slug}.git`); the mirrors
/// are caches and can be deleted at any time.
#[derive(Debug, Clone)]
pub struct WalConfig {
    /// Local bare mirrors live here.
    pub repos_dir: PathBuf,
    /// Bucket key layout.
    pub layout: Layout,
    /// Branch a fresh bare mirror points HEAD at (default `main`).
    pub default_branch: String,
    /// Ref prefixes hidden from advertisement (`uploadpack.hideRefs` and
    /// `transfer.hideRefs`), for refs git clients must not see.
    pub hide_refs: Vec<String>,
    /// Extra ref prefixes [`crate::git::list_refs`] reads besides heads and
    /// tags (for example hidden preview refs).
    pub extra_ref_prefixes: Vec<String>,
    /// When non-empty, only these refs are recorded in the manifest. Empty
    /// records every ref [`crate::git::list_refs`] returns.
    pub only_refs: Vec<String>,
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

    /// `{repos_dir}/{slug}.git`
    pub fn mirror_path(&self, slug: &str) -> PathBuf {
        self.repos_dir.join(format!("{slug}.git"))
    }

    /// Keep only the configured refs (all refs when `only_refs` is empty).
    pub(crate) fn filter_refs(
        &self,
        refs: std::collections::BTreeMap<String, String>,
    ) -> std::collections::BTreeMap<String, String> {
        if self.only_refs.is_empty() {
            return refs;
        }
        refs.into_iter()
            .filter(|(refname, _)| self.only_refs.iter().any(|only| only == refname))
            .collect()
    }
}

/// Temp path unique to this call, used for bundles and manifests.
pub(crate) fn tmp_path(prefix: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("s3-wal-git-{prefix}-{}-{n}", std::process::id()))
}
