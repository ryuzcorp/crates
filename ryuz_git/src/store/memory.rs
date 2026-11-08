//! In-memory [`ObjectStore`] for tests and local development.

use std::collections::BTreeMap;
use std::ops::Range;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use sha2::{Digest as _, Sha256};

use super::{
    BoxStream, ByteStream, GetOptions, GetResult, ObjectMeta, ObjectStore, PutBody, PutMode,
    PutOptions, StoreError, Version,
};

#[derive(Clone)]
struct Stored {
    bytes: Bytes,
    version: u64,
}

/// In-process store. Conditional writes, ranges, listing and versioned reads
/// behave exactly like a bucket; failures are never simulated here.
#[derive(Clone, Default)]
pub struct MemoryStore {
    inner: Arc<Mutex<BTreeMap<String, Stored>>>,
    counter: Arc<Mutex<u64>>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        lock(&self.inner).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn next_version(&self) -> u64 {
        let mut counter = lock(&self.counter);
        *counter += 1;
        *counter
    }

    fn meta(key: &str, stored: &Stored) -> ObjectMeta {
        ObjectMeta {
            key: key.to_string(),
            size: stored.bytes.len() as u64,
            version: Version::new(stored.version.to_string()),
            checksum: Some(hex::encode(Sha256::digest(&stored.bytes))),
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|error| error.into_inner())
}

async fn body_bytes(body: PutBody) -> Result<Bytes, StoreError> {
    match body {
        PutBody::Bytes(bytes) => Ok(bytes),
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
            Ok(Bytes::from(out))
        }
        PutBody::File(path) => std::fs::read(path)
            .map(Bytes::from)
            .map_err(|error| StoreError::Other(error.into())),
    }
}

fn slice_range(bytes: Bytes, range: Option<Range<u64>>) -> Result<Bytes, StoreError> {
    let Some(range) = range else {
        return Ok(bytes);
    };
    let start = usize::try_from(range.start).map_err(|_| StoreError::invalid("range start"))?;
    let end = usize::try_from(range.end).map_err(|_| StoreError::invalid("range end"))?;
    if start > end || end > bytes.len() {
        return Err(StoreError::invalid(format!(
            "range {}..{} is outside 0..{}",
            start,
            end,
            bytes.len()
        )));
    }
    Ok(bytes.slice(start..end))
}

fn stream_of(bytes: Bytes) -> ByteStream {
    Box::pin(futures::stream::once(async move { Ok(bytes) }))
}

#[async_trait]
impl ObjectStore for MemoryStore {
    fn backend(&self) -> &'static str {
        "memory"
    }

    async fn get(&self, key: &str, opts: GetOptions) -> Result<GetResult, StoreError> {
        let stored = lock(&self.inner).get(key).cloned();
        let Some(stored) = stored else {
            return Err(StoreError::not_found(key));
        };
        let current = Version::new(stored.version.to_string());
        if opts.if_none_match.as_ref() == Some(&current) {
            return Ok(GetResult::NotModified { version: current });
        }
        if let Some(expected) = &opts.if_match {
            if expected != &current {
                return Err(StoreError::precondition(key, Some(current.to_string())));
            }
        }
        let body = slice_range(stored.bytes.clone(), opts.range)?;
        Ok(GetResult::Object {
            meta: Self::meta(key, &stored),
            body: stream_of(body),
        })
    }

    async fn head(&self, key: &str) -> Result<Option<ObjectMeta>, StoreError> {
        Ok(lock(&self.inner)
            .get(key)
            .map(|stored| Self::meta(key, stored)))
    }

    async fn put(
        &self,
        key: &str,
        body: PutBody,
        opts: PutOptions,
    ) -> Result<ObjectMeta, StoreError> {
        let bytes = body_bytes(body).await?;
        let mut map = lock(&self.inner);
        let current = map.get(key).cloned();
        match &opts.mode {
            PutMode::Overwrite => {}
            PutMode::Create => {
                if current.is_some() {
                    return Err(StoreError::precondition(
                        key,
                        current.map(|stored| stored.version.to_string()),
                    ));
                }
            }
            PutMode::Update(expected) => match &current {
                Some(stored) if *expected == Version::new(stored.version.to_string()) => {}
                Some(stored) => {
                    return Err(StoreError::precondition(
                        key,
                        Some(stored.version.to_string()),
                    ));
                }
                None => {
                    return Err(StoreError::precondition(key, None));
                }
            },
        }
        let version = self.next_version();
        let stored = Stored { bytes, version };
        let meta = Self::meta(key, &stored);
        map.insert(key.to_string(), stored);
        Ok(meta)
    }

    async fn delete(&self, key: &str, if_version: Option<Version>) -> Result<(), StoreError> {
        let mut map = lock(&self.inner);
        match if_version {
            Some(expected) => match map.get(key) {
                Some(stored) if Version::new(stored.version.to_string()) == expected => {
                    map.remove(key);
                    Ok(())
                }
                Some(stored) => Err(StoreError::precondition(
                    key,
                    Some(stored.version.to_string()),
                )),
                None => Err(StoreError::not_found(key)),
            },
            None => {
                map.remove(key);
                Ok(())
            }
        }
    }

    fn list(
        &self,
        prefix: &str,
        start_after: Option<&str>,
    ) -> BoxStream<'static, Result<ObjectMeta, StoreError>> {
        let mut entries: Vec<ObjectMeta> = lock(&self.inner)
            .iter()
            .filter(|(key, _)| key.starts_with(prefix))
            .filter(|(key, _)| start_after.is_none_or(|start| key.as_str() > start))
            .map(|(key, stored)| Self::meta(key, stored))
            .collect();
        entries.sort_by(|a, b| a.key.cmp(&b.key));
        Box::pin(futures::stream::iter(entries.into_iter().map(Ok)))
    }

    async fn list_prefixes(&self, prefix: &str) -> Result<Vec<String>, StoreError> {
        let mut out = Vec::new();
        for key in lock(&self.inner).keys() {
            let Some(rest) = key.strip_prefix(prefix) else {
                continue;
            };
            let Some((segment, _)) = rest.split_once('/') else {
                continue;
            };
            let child = format!("{prefix}{segment}/");
            if !out.contains(&child) {
                out.push(child);
            }
        }
        out.sort();
        Ok(out)
    }

    async fn signed_get_url(
        &self,
        key: &str,
        _ttl: Duration,
    ) -> Result<Option<String>, StoreError> {
        Ok(Some(format!("memory://{key}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::StreamExt as _;

    #[tokio::test]
    async fn versions_and_conditional_writes() {
        let store = MemoryStore::new();
        let meta = store
            .put("k", b"one".to_vec().into(), PutOptions::create())
            .await
            .unwrap();
        let err = store
            .put("k", b"two".to_vec().into(), PutOptions::create())
            .await
            .unwrap_err();
        assert!(err.is_precondition_failed());
        let updated = store
            .put(
                "k",
                b"two".to_vec().into(),
                PutOptions::update(meta.version.clone()),
            )
            .await
            .unwrap();
        assert_ne!(meta.version, updated.version);
        let stale = store
            .put(
                "k",
                b"three".to_vec().into(),
                PutOptions::update(meta.version),
            )
            .await
            .unwrap_err();
        assert!(stale.is_precondition_failed());
    }

    #[tokio::test]
    async fn get_if_none_match_and_range() {
        let store = MemoryStore::new();
        let meta = store
            .put("k", b"abcdef".to_vec().into(), PutOptions::default())
            .await
            .unwrap();
        let unchanged = store
            .get(
                "k",
                GetOptions {
                    if_none_match: Some(meta.version.clone()),
                    ..GetOptions::default()
                },
            )
            .await
            .unwrap();
        assert!(matches!(unchanged, GetResult::NotModified { .. }));
        let part = store
            .get(
                "k",
                GetOptions {
                    range: Some(2..5),
                    ..GetOptions::default()
                },
            )
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap()
            .unwrap();
        assert_eq!(part.1, Bytes::from_static(b"cde"));
        assert_eq!(part.0.size, 6);
    }

    #[tokio::test]
    async fn passes_the_contract() {
        let store = MemoryStore::new();
        crate::store::contract::run(&store, "contract/").await;
    }

    #[tokio::test]
    async fn listing_and_prefixes() {
        let store = MemoryStore::new();
        for key in ["a/1", "a/2", "b/1", "c/x/y"] {
            store
                .put(key, b"x".to_vec().into(), PutOptions::default())
                .await
                .unwrap();
        }
        let keys: Vec<String> = store
            .list("a/", None)
            .map(|meta| meta.unwrap().key)
            .collect()
            .await;
        assert_eq!(keys, vec!["a/1", "a/2"]);
        let after: Vec<String> = store
            .list("a/", Some("a/1"))
            .map(|meta| meta.unwrap().key)
            .collect()
            .await;
        assert_eq!(after, vec!["a/2"]);
        assert_eq!(
            store.list_prefixes("").await.unwrap(),
            vec!["a/", "b/", "c/"]
        );
        assert_eq!(
            store.list_prefixes("a/").await.unwrap(),
            Vec::<String>::new()
        );
    }
}
