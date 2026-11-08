//! The object-store seam.
//!
//! The WAL needs seven operations from a bucket. Implement [`ObjectStore`] for
//! the application's store client; [`MemoryStore`] is a complete in-process
//! implementation for tests and local development.

use std::collections::BTreeMap;
use std::future::Future;
use std::path::Path;
use std::sync::{Arc, Mutex};

use anyhow::Context as _;

/// The subset of an S3-compatible bucket a repository WAL uses.
///
/// Contract, shared by every implementation:
/// - `get`/`get_to_file` report a missing key as `None`/`false`, never an
///   error.
/// - `delete` treats a missing key as success.
/// - `list` returns keys in sort order; `delete_prefix` matches a plain key
///   prefix and refuses unsafe prefixes ([`check_delete_prefix`]).
pub trait ObjectStore: Send + Sync {
    /// Whole-object read. `None` means the key does not exist.
    fn get<'a>(
        &'a self,
        key: &'a str,
    ) -> impl Future<Output = anyhow::Result<Option<Vec<u8>>>> + Send + 'a;

    /// Upload a small object (the manifest).
    fn put<'a>(
        &'a self,
        key: &'a str,
        body: Vec<u8>,
    ) -> impl Future<Output = anyhow::Result<()>> + Send + 'a;

    /// Streaming upload for large objects (bundles). The default reads the
    /// file and calls [`ObjectStore::put`]; backends that stream override it.
    fn put_file<'a>(
        &'a self,
        key: &'a str,
        path: &'a Path,
    ) -> impl Future<Output = anyhow::Result<()>> + Send + 'a {
        async move {
            let body = tokio::fs::read(path)
                .await
                .with_context(|| format!("reading {} for upload", path.display()))?;
            self.put(key, body).await
        }
    }

    /// Download to `dest`. `false` means the key does not exist; no partial
    /// file is left behind in that case.
    fn get_to_file<'a>(
        &'a self,
        key: &'a str,
        dest: &'a Path,
    ) -> impl Future<Output = anyhow::Result<bool>> + Send + 'a {
        async move {
            let Some(body) = self.get(key).await? else {
                return Ok(false);
            };
            if let Some(parent) = dest.parent() {
                tokio::fs::create_dir_all(parent).await?;
            }
            tokio::fs::write(dest, body).await?;
            Ok(true)
        }
    }

    /// Delete one key. A missing key is success.
    fn delete<'a>(&'a self, key: &'a str) -> impl Future<Output = anyhow::Result<()>> + Send + 'a;

    /// All keys under `prefix`, in sort order.
    fn list<'a>(
        &'a self,
        prefix: &'a str,
    ) -> impl Future<Output = anyhow::Result<Vec<String>>> + Send + 'a;

    /// Delete every key under `prefix`, which must be a whole slug scope.
    fn delete_prefix<'a>(
        &'a self,
        prefix: &'a str,
    ) -> impl Future<Output = anyhow::Result<()>> + Send + 'a;
}

/// Guard for prefix deletes: prefixes are whole slug scopes, so an empty
/// prefix or one without a trailing `/` names a wider scope than intended and
/// is refused instead of deleted.
pub fn check_delete_prefix(prefix: &str) -> anyhow::Result<()> {
    if prefix.is_empty() {
        anyhow::bail!("refusing to delete the empty store prefix");
    }
    if !prefix.ends_with('/') {
        anyhow::bail!("refusing to delete store prefix without a trailing slash: {prefix:?}");
    }
    Ok(())
}

/// In-memory [`ObjectStore`] for tests and local development.
#[derive(Clone, Default)]
pub struct MemoryStore {
    inner: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
    #[cfg(test)]
    faults: Arc<Mutex<Vec<String>>>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Test-only: fail the next `n` operations with `message` (FIFO). Clones
    /// share the queue.
    #[cfg(test)]
    pub fn fail_next(&self, n: usize, message: &str) {
        let mut faults = lock(&self.faults);
        faults.extend(std::iter::repeat_n(message.to_string(), n));
    }

    #[cfg(test)]
    fn take_fault(&self) -> Option<String> {
        let mut faults = lock(&self.faults);
        if faults.is_empty() {
            None
        } else {
            Some(faults.remove(0))
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

#[allow(clippy::manual_async_fn)]
impl ObjectStore for MemoryStore {
    fn get<'a>(
        &'a self,
        key: &'a str,
    ) -> impl Future<Output = anyhow::Result<Option<Vec<u8>>>> + Send + 'a {
        async move {
            #[cfg(test)]
            if let Some(message) = self.take_fault() {
                return Err(anyhow::anyhow!(message));
            }
            Ok(lock(&self.inner).get(key).cloned())
        }
    }

    fn put<'a>(
        &'a self,
        key: &'a str,
        body: Vec<u8>,
    ) -> impl Future<Output = anyhow::Result<()>> + Send + 'a {
        async move {
            #[cfg(test)]
            if let Some(message) = self.take_fault() {
                return Err(anyhow::anyhow!(message));
            }
            lock(&self.inner).insert(key.to_string(), body);
            Ok(())
        }
    }

    fn put_file<'a>(
        &'a self,
        key: &'a str,
        path: &'a Path,
    ) -> impl Future<Output = anyhow::Result<()>> + Send + 'a {
        async move {
            #[cfg(test)]
            if let Some(message) = self.take_fault() {
                return Err(anyhow::anyhow!(message));
            }
            let bytes = tokio::fs::read(path).await?;
            lock(&self.inner).insert(key.to_string(), bytes);
            Ok(())
        }
    }

    fn get_to_file<'a>(
        &'a self,
        key: &'a str,
        dest: &'a Path,
    ) -> impl Future<Output = anyhow::Result<bool>> + Send + 'a {
        async move {
            #[cfg(test)]
            if let Some(message) = self.take_fault() {
                return Err(anyhow::anyhow!(message));
            }
            let bytes = lock(&self.inner).get(key).cloned();
            let Some(bytes) = bytes else {
                return Ok(false);
            };
            if let Some(parent) = dest.parent() {
                tokio::fs::create_dir_all(parent).await?;
            }
            tokio::fs::write(dest, bytes).await?;
            Ok(true)
        }
    }

    fn delete<'a>(&'a self, key: &'a str) -> impl Future<Output = anyhow::Result<()>> + Send + 'a {
        async move {
            #[cfg(test)]
            if let Some(message) = self.take_fault() {
                return Err(anyhow::anyhow!(message));
            }
            lock(&self.inner).remove(key);
            Ok(())
        }
    }

    fn list<'a>(
        &'a self,
        prefix: &'a str,
    ) -> impl Future<Output = anyhow::Result<Vec<String>>> + Send + 'a {
        async move {
            #[cfg(test)]
            if let Some(message) = self.take_fault() {
                return Err(anyhow::anyhow!(message));
            }
            Ok(lock(&self.inner)
                .keys()
                .filter(|key| key.starts_with(prefix))
                .cloned()
                .collect())
        }
    }

    fn delete_prefix<'a>(
        &'a self,
        prefix: &'a str,
    ) -> impl Future<Output = anyhow::Result<()>> + Send + 'a {
        async move {
            #[cfg(test)]
            if let Some(message) = self.take_fault() {
                return Err(anyhow::anyhow!(message));
            }
            check_delete_prefix(prefix)?;
            lock(&self.inner).retain(|key, _| !key.starts_with(prefix));
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn memory_put_get_roundtrip_overwrites() {
        let store = MemoryStore::new();
        assert_eq!(store.get("git/demo/MANIFEST.json").await.unwrap(), None);
        store
            .put("git/demo/MANIFEST.json", b"{}".to_vec())
            .await
            .unwrap();
        store
            .put("git/demo/MANIFEST.json", b"{\"a\":1}".to_vec())
            .await
            .unwrap();
        assert_eq!(
            store.get("git/demo/MANIFEST.json").await.unwrap(),
            Some(b"{\"a\":1}".to_vec())
        );
    }

    #[tokio::test]
    async fn memory_delete_missing_is_ok() {
        let store = MemoryStore::new();
        store.delete("no/such/key").await.unwrap();
        store.put("k", b"v".to_vec()).await.unwrap();
        store.delete("k").await.unwrap();
        store.delete("k").await.unwrap();
        assert_eq!(store.get("k").await.unwrap(), None);
    }

    #[tokio::test]
    async fn memory_list_and_prefix_delete_match_by_plain_prefix() {
        let store = MemoryStore::new();
        for key in [
            "git/b/MANIFEST.json",
            "git/a/MANIFEST.json",
            "fleets/a/image.tar",
        ] {
            store.put(key, b"x".to_vec()).await.unwrap();
        }
        assert_eq!(
            store.list("git/a/").await.unwrap(),
            vec!["git/a/MANIFEST.json"]
        );
        assert_eq!(store.list("").await.unwrap().len(), 3);
        for prefix in ["", "git", "git/a"] {
            assert!(store.delete_prefix(prefix).await.is_err(), "{prefix:?}");
        }
        store.delete_prefix("git/a/").await.unwrap();
        store.delete_prefix("git/a/").await.unwrap();
        assert_eq!(store.list("git/a/").await.unwrap(), Vec::<String>::new());
    }

    #[tokio::test]
    async fn memory_file_roundtrip_and_missing_key() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("up.bundle");
        let dest = dir.path().join("down.bundle");
        tokio::fs::write(&src, vec![7u8; 100_000]).await.unwrap();
        let store = MemoryStore::new();
        store.put_file("git/a/x.bundle", &src).await.unwrap();
        assert!(store.get_to_file("git/a/x.bundle", &dest).await.unwrap());
        assert_eq!(tokio::fs::read(&dest).await.unwrap(), vec![7u8; 100_000]);
        assert!(!store.get_to_file("git/a/missing", &dest).await.unwrap());
    }
}
