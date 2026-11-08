//! Filesystem-backed [`ObjectStore`] for local development and tests.
//!
//! The store is a directory tree; keys become paths after validation. Writes
//! are atomic (tmp + rename) and conditional writes are serialized by one
//! process-wide-per-store mutex. Versions are content digests, so a
//! conditional update can never apply on top of different bytes.

use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use sha2::{Digest as _, Sha256};

use super::{
    BoxStream, GetOptions, GetResult, ObjectMeta, ObjectStore, PutBody, PutMode, PutOptions,
    StoreError, Version,
};

/// Reserved staging directory for atomic writes. Keys may not use it.
const TEMP_DIR: &str = ".walgit-tmp";

/// A directory holding one object per key.
#[derive(Clone)]
pub struct FsStore {
    root: Arc<PathBuf>,
    lock: Arc<tokio::sync::Mutex<()>>,
}

impl FsStore {
    pub async fn open(root: impl Into<PathBuf>) -> Result<Self, StoreError> {
        let root = root.into();
        tokio::fs::create_dir_all(&root).await?;
        tokio::fs::create_dir_all(root.join(TEMP_DIR)).await?;
        Ok(Self {
            root: Arc::new(root),
            lock: Arc::new(tokio::sync::Mutex::new(())),
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn path(&self, key: &str) -> Result<PathBuf, StoreError> {
        let relative = Path::new(key);
        if relative.is_absolute() {
            return Err(StoreError::invalid(format!("absolute key {key:?}")));
        }
        let mut out = self.root.as_ref().clone();
        let mut saw_component = false;
        for component in relative.components() {
            match component {
                Component::Normal(part) => {
                    if part.to_str() == Some(TEMP_DIR) {
                        return Err(StoreError::invalid(format!(
                            "reserved key component {TEMP_DIR:?} in {key:?}"
                        )));
                    }
                    saw_component = true;
                    out.push(part);
                }
                _ => {
                    return Err(StoreError::invalid(format!(
                        "unsafe key component in {key:?}"
                    )));
                }
            }
        }
        if !saw_component {
            return Err(StoreError::invalid("empty key"));
        }
        Ok(out)
    }

    fn version_of(bytes: &[u8]) -> Version {
        Version::new(hex::encode(Sha256::digest(bytes)))
    }

    async fn current(&self, key: &str) -> Result<Option<(Bytes, Version)>, StoreError> {
        let path = self.path(key)?;
        match tokio::fs::read(&path).await {
            Ok(bytes) => {
                let version = Self::version_of(&bytes);
                Ok(Some((Bytes::from(bytes), version)))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(StoreError::Other(error.into())),
        }
    }

    fn meta(key: &str, bytes: &[u8]) -> ObjectMeta {
        ObjectMeta {
            key: key.to_string(),
            size: bytes.len() as u64,
            version: Self::version_of(bytes),
            checksum: Some(hex::encode(Sha256::digest(bytes))),
        }
    }

    async fn write_atomic(&self, key: &str, bytes: &[u8]) -> Result<ObjectMeta, StoreError> {
        let path = self.path(key)?;
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let staging = self.root.join(TEMP_DIR);
        tokio::fs::create_dir_all(&staging).await?;
        let tmp = staging.join(format!("{}-{}", std::process::id(), rand::random::<u64>()));
        let write = async {
            use tokio::io::AsyncWriteExt as _;
            let mut file = tokio::fs::File::create(&tmp).await?;
            file.write_all(bytes).await?;
            file.flush().await?;
            file.sync_all().await?;
            drop(file);
            tokio::fs::rename(&tmp, &path).await?;
            Ok::<(), StoreError>(())
        }
        .await;
        if let Err(error) = write {
            let _ = tokio::fs::remove_file(&tmp).await;
            return Err(error);
        }
        Ok(Self::meta(key, bytes))
    }
}

#[async_trait]
impl ObjectStore for FsStore {
    fn backend(&self) -> &'static str {
        "fs"
    }

    async fn get(&self, key: &str, opts: GetOptions) -> Result<GetResult, StoreError> {
        let Some((bytes, version)) = self.current(key).await? else {
            return Err(StoreError::not_found(key));
        };
        if opts.if_none_match.as_ref() == Some(&version) {
            return Ok(GetResult::NotModified { version });
        }
        if let Some(expected) = &opts.if_match {
            if expected != &version {
                return Err(StoreError::precondition(key, Some(version.to_string())));
            }
        }
        let meta = Self::meta(key, &bytes);
        let body = if let Some(range) = opts.range {
            let start =
                usize::try_from(range.start).map_err(|_| StoreError::invalid("range start"))?;
            let end = usize::try_from(range.end).map_err(|_| StoreError::invalid("range end"))?;
            if start > end || end > bytes.len() {
                return Err(StoreError::invalid("range out of bounds"));
            }
            bytes.slice(start..end)
        } else {
            bytes
        };
        Ok(GetResult::Object {
            meta,
            body: Box::pin(futures::stream::once(async move { Ok(body) })),
        })
    }

    async fn head(&self, key: &str) -> Result<Option<ObjectMeta>, StoreError> {
        Ok(self
            .current(key)
            .await?
            .map(|(bytes, _)| Self::meta(key, &bytes)))
    }

    async fn put(
        &self,
        key: &str,
        body: PutBody,
        opts: PutOptions,
    ) -> Result<ObjectMeta, StoreError> {
        let bytes = match body {
            PutBody::Bytes(bytes) => bytes,
            PutBody::File(path) => Bytes::from(
                tokio::fs::read(path)
                    .await
                    .map_err(|error| StoreError::Other(error.into()))?,
            ),
            PutBody::Stream { len, mut stream } => {
                use futures::StreamExt as _;
                let hint = usize::try_from(len.min(8 * 1024 * 1024)).unwrap_or(0);
                let mut out = Vec::with_capacity(hint);
                while let Some(chunk) = stream.next().await {
                    let chunk = chunk?;
                    out.extend_from_slice(&chunk);
                    if out.len() as u64 > len {
                        return Err(StoreError::invalid(format!(
                            "stream body exceeds declared length {len}"
                        )));
                    }
                }
                if out.len() as u64 != len {
                    return Err(StoreError::invalid(format!(
                        "stream length {len} disagrees with body {}",
                        out.len()
                    )));
                }
                Bytes::from(out)
            }
        };
        let _guard = self.lock.lock().await;
        let current = self.current(key).await?;
        match &opts.mode {
            PutMode::Overwrite => {}
            PutMode::Create => {
                if current.is_some() {
                    return Err(StoreError::precondition(
                        key,
                        current.map(|(_, version)| version.to_string()),
                    ));
                }
            }
            PutMode::Update(expected) => match &current {
                Some((_, version)) if version == expected => {}
                Some((_, version)) => {
                    return Err(StoreError::precondition(key, Some(version.to_string())));
                }
                None => return Err(StoreError::precondition(key, None)),
            },
        }
        self.write_atomic(key, &bytes).await
    }

    async fn delete(&self, key: &str, if_version: Option<Version>) -> Result<(), StoreError> {
        let _guard = self.lock.lock().await;
        let path = self.path(key)?;
        if let Some(expected) = if_version {
            let Some((_, version)) = self.current(key).await? else {
                return Err(StoreError::not_found(key));
            };
            if expected != version {
                return Err(StoreError::precondition(key, Some(version.to_string())));
            }
        }
        match tokio::fs::remove_file(&path).await {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(StoreError::Other(error.into())),
        }
    }

    fn list(
        &self,
        prefix: &str,
        start_after: Option<&str>,
    ) -> BoxStream<'static, Result<ObjectMeta, StoreError>> {
        fn walk_sync(dir: &Path, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
            let entries = match std::fs::read_dir(dir) {
                Ok(entries) => entries,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                Err(error) => return Err(error),
            };
            for entry in entries {
                let entry = entry?;
                let path = entry.path();
                if entry.file_name().to_str() == Some(TEMP_DIR) {
                    continue;
                }
                let ty = entry.file_type()?;
                if ty.is_dir() {
                    walk_sync(&path, out)?;
                } else if ty.is_file() {
                    out.push(path);
                }
            }
            Ok(())
        }
        let mut paths = Vec::new();
        let base = if prefix.is_empty() {
            self.root.as_ref().clone()
        } else {
            match self.path(prefix) {
                Ok(path) => path,
                Err(error) => return Box::pin(futures::stream::once(async move { Err(error) })),
            }
        };
        if base.is_file() {
            paths.push(base);
        } else if let Err(error) = walk_sync(&base, &mut paths) {
            return Box::pin(futures::stream::once(async move {
                Err(StoreError::Other(error.into()))
            }));
        }
        let mut keys: Vec<String> = paths
            .into_iter()
            .filter_map(|path| {
                let relative = path.strip_prefix(self.root.as_ref()).ok()?;
                Some(relative.to_string_lossy().replace('\\', "/"))
            })
            .filter(|key| key.starts_with(prefix))
            .filter(|key| start_after.is_none_or(|start| key.as_str() > start))
            .collect();
        keys.sort();
        let root = self.root.clone();
        let items: Vec<Result<ObjectMeta, StoreError>> = keys
            .into_iter()
            .map(|key| match std::fs::read(root.as_ref().join(&key)) {
                Ok(bytes) => Ok(Self::meta(&key, &bytes)),
                Err(error) => Err(StoreError::Other(error.into())),
            })
            .collect();
        Box::pin(futures::stream::iter(items))
    }

    async fn list_prefixes(&self, prefix: &str) -> Result<Vec<String>, StoreError> {
        let base = if prefix.is_empty() {
            self.root.as_ref().clone()
        } else {
            self.path(prefix)?
        };
        let mut out = Vec::new();
        let mut entries = match tokio::fs::read_dir(&base).await {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(out),
            Err(error) => return Err(StoreError::Other(error.into())),
        };
        while let Some(entry) = entries.next_entry().await? {
            if entry.file_name().to_str() == Some(TEMP_DIR) {
                continue;
            }
            if entry.file_type().await?.is_dir() {
                let name = entry.file_name().to_string_lossy().into_owned();
                out.push(format!("{prefix}{name}/"));
            }
        }
        out.sort();
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::contract;
    use futures::StreamExt as _;

    #[tokio::test]
    async fn passes_the_contract() {
        let dir = tempfile::tempdir().unwrap();
        let store = FsStore::open(dir.path()).await.unwrap();
        contract::run(&store, "contract/").await;
    }

    #[tokio::test]
    async fn staging_dir_is_never_listed_and_clean_after_writes() {
        let dir = tempfile::tempdir().unwrap();
        let store = FsStore::open(dir.path()).await.unwrap();
        store
            .put(
                "dir/object",
                Bytes::from_static(b"value").into(),
                PutOptions::default(),
            )
            .await
            .unwrap();
        let keys: Vec<String> = store
            .list("", None)
            .map(|item| item.unwrap().key)
            .collect()
            .await;
        assert_eq!(keys, vec!["dir/object".to_string()]);
        assert_eq!(
            store.list_prefixes("").await.unwrap(),
            vec!["dir/".to_string()]
        );
        let staging = std::fs::read_dir(store.root().join(TEMP_DIR)).unwrap();
        assert_eq!(staging.count(), 0, "temporary files must be renamed away");
    }

    #[tokio::test]
    async fn reserved_staging_keys_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let store = FsStore::open(dir.path()).await.unwrap();
        let error = store
            .put(
                &format!("{TEMP_DIR}/x"),
                Bytes::from_static(b"x").into(),
                PutOptions::default(),
            )
            .await
            .unwrap_err();
        assert!(matches!(error, StoreError::InvalidArgument(_)));
    }
}
