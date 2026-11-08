//! Fault-injecting store wrapper for deterministic failure tests.
//!
//! Supports three failure shapes the WAL must handle:
//!
//! - a plain error before the operation reaches the backend,
//! - a *lost response*: the backend applies the operation but the caller sees
//!   an error (ambiguous write, resolved by re-reading),
//! - an injected `PreconditionFailed` carrying the current version.
//!
//! Faults can be scoped to one exact key, to a key prefix, or to every key,
//! and apply for a fixed number of matching operations. Counters expose how
//! many calls of each kind reached the wrapper.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use async_trait::async_trait;

use super::{
    AccelTarget, BoxStream, DynStore, GetOptions, GetResult, ObjectMeta, ObjectStore, PutBody,
    PutOptions, StoreError, Version,
};

#[derive(Debug, Clone)]
enum FaultKey {
    Exact(String),
    Prefix(String),
}

impl FaultKey {
    fn matches(&self, key: &str) -> bool {
        match self {
            Self::Exact(expected) => key == expected,
            Self::Prefix(prefix) => key.starts_with(prefix),
        }
    }
}

#[derive(Debug, Clone)]
enum FaultMode {
    Error {
        message: String,
        retryable: bool,
    },
    /// The operation is delegated (and can take effect) but the caller gets
    /// this error instead of the response.
    LostResponse {
        message: String,
    },
    Precondition {
        current: Option<String>,
    },
}

#[derive(Debug, Clone)]
struct Fault {
    key: Option<FaultKey>,
    mode: FaultMode,
    remaining: usize,
}

enum FaultAction {
    Error(StoreError),
    Lost(StoreError),
}

/// Counters for every delegated operation.
#[derive(Debug, Default)]
pub struct StoreStats {
    pub get: AtomicU64,
    pub head: AtomicU64,
    pub put: AtomicU64,
    pub delete: AtomicU64,
    pub list: AtomicU64,
    pub list_prefixes: AtomicU64,
    pub signed_get_url: AtomicU64,
    pub accel_target: AtomicU64,
    pub faults: AtomicU64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StatsSnapshot {
    pub get: u64,
    pub head: u64,
    pub put: u64,
    pub delete: u64,
    pub list: u64,
    pub list_prefixes: u64,
    pub signed_get_url: u64,
    pub accel_target: u64,
    pub faults: u64,
}

impl StoreStats {
    pub fn snapshot(&self) -> StatsSnapshot {
        StatsSnapshot {
            get: self.get.load(Ordering::Relaxed),
            head: self.head.load(Ordering::Relaxed),
            put: self.put.load(Ordering::Relaxed),
            delete: self.delete.load(Ordering::Relaxed),
            list: self.list.load(Ordering::Relaxed),
            list_prefixes: self.list_prefixes.load(Ordering::Relaxed),
            signed_get_url: self.signed_get_url.load(Ordering::Relaxed),
            accel_target: self.accel_target.load(Ordering::Relaxed),
            faults: self.faults.load(Ordering::Relaxed),
        }
    }
}

/// Wraps another store and fails chosen operations.
#[derive(Clone)]
pub struct FaultStore {
    inner: DynStore,
    faults: Arc<Mutex<VecDeque<Fault>>>,
    stats: Arc<StoreStats>,
}

impl FaultStore {
    pub fn new(inner: DynStore) -> Self {
        Self {
            inner,
            faults: Arc::new(Mutex::new(VecDeque::new())),
            stats: Arc::new(StoreStats::default()),
        }
    }

    pub fn arc(inner: DynStore) -> DynStore {
        Arc::new(Self::new(inner))
    }

    pub fn stats(&self) -> StatsSnapshot {
        self.stats.snapshot()
    }

    /// Remove every pending fault.
    pub fn clear(&self) {
        lock(&self.faults).clear();
    }

    /// Fail the next `n` operations on every key with a non-retryable error.
    pub fn fail_next(&self, n: usize, message: impl Into<String>) {
        self.push(
            None,
            FaultMode::Error {
                message: message.into(),
                retryable: false,
            },
            n,
        );
    }

    pub fn fail_next_retryable(&self, n: usize, message: impl Into<String>) {
        self.push(
            None,
            FaultMode::Error {
                message: message.into(),
                retryable: true,
            },
            n,
        );
    }

    /// Delegated operation succeeds, caller sees a non-retryable error.
    pub fn fail_next_lost_response(&self, n: usize, message: impl Into<String>) {
        self.push(
            None,
            FaultMode::LostResponse {
                message: message.into(),
            },
            n,
        );
    }

    /// Fail the next `n` operations with `PreconditionFailed` naming `current`.
    pub fn fail_next_precondition(&self, n: usize, current: Option<Version>) {
        self.push(
            None,
            FaultMode::Precondition {
                current: current.map(|version| version.to_string()),
            },
            n,
        );
    }

    pub fn fail_key(&self, key: impl Into<String>, n: usize, message: impl Into<String>) {
        self.push(
            Some(FaultKey::Exact(key.into())),
            FaultMode::Error {
                message: message.into(),
                retryable: false,
            },
            n,
        );
    }

    pub fn fail_key_retryable(&self, key: impl Into<String>, n: usize, message: impl Into<String>) {
        self.push(
            Some(FaultKey::Exact(key.into())),
            FaultMode::Error {
                message: message.into(),
                retryable: true,
            },
            n,
        );
    }

    pub fn fail_key_lost_response(
        &self,
        key: impl Into<String>,
        n: usize,
        message: impl Into<String>,
    ) {
        self.push(
            Some(FaultKey::Exact(key.into())),
            FaultMode::LostResponse {
                message: message.into(),
            },
            n,
        );
    }

    pub fn fail_key_precondition(
        &self,
        key: impl Into<String>,
        n: usize,
        current: Option<Version>,
    ) {
        self.push(
            Some(FaultKey::Exact(key.into())),
            FaultMode::Precondition {
                current: current.map(|version| version.to_string()),
            },
            n,
        );
    }

    pub fn fail_prefix(&self, prefix: impl Into<String>, n: usize, message: impl Into<String>) {
        self.push(
            Some(FaultKey::Prefix(prefix.into())),
            FaultMode::Error {
                message: message.into(),
                retryable: false,
            },
            n,
        );
    }

    pub fn fail_prefix_retryable(
        &self,
        prefix: impl Into<String>,
        n: usize,
        message: impl Into<String>,
    ) {
        self.push(
            Some(FaultKey::Prefix(prefix.into())),
            FaultMode::Error {
                message: message.into(),
                retryable: true,
            },
            n,
        );
    }

    pub fn fail_prefix_lost_response(
        &self,
        prefix: impl Into<String>,
        n: usize,
        message: impl Into<String>,
    ) {
        self.push(
            Some(FaultKey::Prefix(prefix.into())),
            FaultMode::LostResponse {
                message: message.into(),
            },
            n,
        );
    }

    pub fn fail_prefix_precondition(
        &self,
        prefix: impl Into<String>,
        n: usize,
        current: Option<Version>,
    ) {
        self.push(
            Some(FaultKey::Prefix(prefix.into())),
            FaultMode::Precondition {
                current: current.map(|version| version.to_string()),
            },
            n,
        );
    }

    fn push(&self, key: Option<FaultKey>, mode: FaultMode, n: usize) {
        if n == 0 {
            return;
        }
        lock(&self.faults).push_back(Fault {
            key,
            mode,
            remaining: n,
        });
    }

    fn check(&self, key: &str) -> Option<FaultAction> {
        let mut faults = lock(&self.faults);
        let index = faults.iter().position(|fault| {
            fault.remaining > 0
                && fault
                    .key
                    .as_ref()
                    .is_none_or(|pattern| pattern.matches(key))
        })?;
        self.stats.faults.fetch_add(1, Ordering::Relaxed);
        let fault = &mut faults[index];
        fault.remaining -= 1;
        let remove = fault.remaining == 0;
        let mode = fault.mode.clone();
        if remove {
            faults.remove(index);
        }
        Some(match mode {
            FaultMode::Error { message, retryable } => {
                let error = anyhow::anyhow!("{message}");
                FaultAction::Error(if retryable {
                    StoreError::retryable(error)
                } else {
                    StoreError::Other(error)
                })
            }
            FaultMode::LostResponse { message } => FaultAction::Lost(StoreError::Other(
                anyhow::anyhow!("lost response: {message}"),
            )),
            FaultMode::Precondition { current } => {
                FaultAction::Error(StoreError::precondition(key, current))
            }
        })
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|error| error.into_inner())
}

#[async_trait]
impl ObjectStore for FaultStore {
    fn backend(&self) -> &'static str {
        self.inner.backend()
    }

    async fn get(&self, key: &str, opts: GetOptions) -> Result<GetResult, StoreError> {
        self.stats.get.fetch_add(1, Ordering::Relaxed);
        match self.check(key) {
            Some(FaultAction::Error(error)) => Err(error),
            Some(FaultAction::Lost(error)) => {
                let _ = self.inner.get(key, opts).await;
                Err(error)
            }
            None => self.inner.get(key, opts).await,
        }
    }

    async fn head(&self, key: &str) -> Result<Option<ObjectMeta>, StoreError> {
        self.stats.head.fetch_add(1, Ordering::Relaxed);
        match self.check(key) {
            Some(FaultAction::Error(error)) => Err(error),
            Some(FaultAction::Lost(error)) => {
                let _ = self.inner.head(key).await;
                Err(error)
            }
            None => self.inner.head(key).await,
        }
    }

    async fn put(
        &self,
        key: &str,
        body: PutBody,
        opts: PutOptions,
    ) -> Result<ObjectMeta, StoreError> {
        self.stats.put.fetch_add(1, Ordering::Relaxed);
        match self.check(key) {
            Some(FaultAction::Error(error)) => Err(error),
            Some(FaultAction::Lost(error)) => {
                let _ = self.inner.put(key, body, opts).await;
                Err(error)
            }
            None => self.inner.put(key, body, opts).await,
        }
    }

    async fn delete(&self, key: &str, if_version: Option<Version>) -> Result<(), StoreError> {
        self.stats.delete.fetch_add(1, Ordering::Relaxed);
        match self.check(key) {
            Some(FaultAction::Error(error)) => Err(error),
            Some(FaultAction::Lost(error)) => {
                let _ = self.inner.delete(key, if_version).await;
                Err(error)
            }
            None => self.inner.delete(key, if_version).await,
        }
    }

    fn list(
        &self,
        prefix: &str,
        start_after: Option<&str>,
    ) -> BoxStream<'static, Result<ObjectMeta, StoreError>> {
        self.stats.list.fetch_add(1, Ordering::Relaxed);
        match self.check(prefix) {
            Some(FaultAction::Error(error)) => {
                Box::pin(futures::stream::once(async move { Err(error) }))
            }
            Some(FaultAction::Lost(error)) => {
                use futures::StreamExt as _;
                let inner = self.inner.list(prefix, start_after);
                Box::pin(inner.chain(futures::stream::once(async move { Err(error) })))
            }
            None => self.inner.list(prefix, start_after),
        }
    }

    async fn list_prefixes(&self, prefix: &str) -> Result<Vec<String>, StoreError> {
        self.stats.list_prefixes.fetch_add(1, Ordering::Relaxed);
        match self.check(prefix) {
            Some(FaultAction::Error(error)) => Err(error),
            Some(FaultAction::Lost(error)) => {
                let _ = self.inner.list_prefixes(prefix).await;
                Err(error)
            }
            None => self.inner.list_prefixes(prefix).await,
        }
    }

    async fn signed_get_url(&self, key: &str, ttl: Duration) -> Result<Option<String>, StoreError> {
        self.stats.signed_get_url.fetch_add(1, Ordering::Relaxed);
        match self.check(key) {
            Some(FaultAction::Error(error)) => Err(error),
            Some(FaultAction::Lost(error)) => {
                let _ = self.inner.signed_get_url(key, ttl).await;
                Err(error)
            }
            None => self.inner.signed_get_url(key, ttl).await,
        }
    }

    async fn accel_target(&self, key: &str) -> Result<Option<AccelTarget>, StoreError> {
        self.stats.accel_target.fetch_add(1, Ordering::Relaxed);
        match self.check(key) {
            Some(FaultAction::Error(error)) => Err(error),
            Some(FaultAction::Lost(error)) => {
                let _ = self.inner.accel_target(key).await;
                Err(error)
            }
            None => self.inner.accel_target(key).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{MemoryStore, ObjectStoreExt};
    use bytes::Bytes;
    use std::sync::Arc;

    #[tokio::test]
    async fn key_scoped_failures_are_exact() {
        let inner = Arc::new(MemoryStore::new());
        let store = FaultStore::new(inner);
        store
            .put(
                "a/1",
                Bytes::from_static(b"x").into(),
                PutOptions::default(),
            )
            .await
            .unwrap();
        store.fail_key("a/1", 1, "boom");
        assert!(store.head("a/1").await.is_err());
        assert!(store.head("a/1").await.unwrap().is_some());
        assert_eq!(store.stats().head, 2);
        assert_eq!(store.stats().faults, 1);
    }

    #[tokio::test]
    async fn prefix_scoped_retryable_and_precondition() {
        let inner = Arc::new(MemoryStore::new());
        let store = FaultStore::new(inner);
        let created = store
            .put(
                "a/1",
                Bytes::from_static(b"x").into(),
                PutOptions::default(),
            )
            .await
            .unwrap();
        store.fail_prefix_retryable("a/", 1, "slow down");
        let error = store.get_bytes("a/1").await.unwrap_err();
        assert!(error.is_retryable());
        store.fail_prefix_precondition("a/", 1, Some(created.version.clone()));
        let error = store
            .put(
                "a/1",
                Bytes::from_static(b"y").into(),
                PutOptions::default(),
            )
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            StoreError::PreconditionFailed { ref current, .. }
                if current.as_deref() == Some(created.version.as_str())
        ));
    }

    #[tokio::test]
    async fn lost_response_takes_effect_but_returns_error() {
        let inner = Arc::new(MemoryStore::new());
        let store = FaultStore::new(inner);
        store.fail_next_lost_response(1, "connection reset");
        let error = store
            .put(
                "k",
                Bytes::from_static(b"value").into(),
                PutOptions::create(),
            )
            .await
            .unwrap_err();
        assert!(!error.is_retryable());
        let meta = store.head("k").await.unwrap().expect("write took effect");
        let conflict = store
            .put(
                "k",
                Bytes::from_static(b"again").into(),
                PutOptions::create(),
            )
            .await
            .unwrap_err();
        assert!(conflict.is_precondition_failed());
        assert_eq!(meta.size, 5);
    }

    #[tokio::test]
    async fn lost_list_response_yields_every_item_then_error() {
        use futures::StreamExt as _;

        let inner = Arc::new(MemoryStore::new());
        let store = FaultStore::new(inner);
        store
            .put("k", Bytes::from_static(b"x").into(), PutOptions::default())
            .await
            .unwrap();
        store.fail_next_lost_response(1, "reset");
        let mut stream = store.list("", None);
        assert_eq!(stream.next().await.unwrap().unwrap().key, "k");
        assert!(stream.next().await.unwrap().is_err());
        assert!(stream.next().await.is_none());
    }

    #[tokio::test]
    async fn delegates_the_contract() {
        let store = FaultStore::new(Arc::new(MemoryStore::new()));
        crate::store::contract::run(&store, "contract/").await;
    }

    #[tokio::test]
    async fn zero_count_faults_are_ignored() {
        let inner = Arc::new(MemoryStore::new());
        let store = FaultStore::new(inner);
        store.fail_next(0, "never");
        assert!(store.head("k").await.unwrap().is_none());
        assert_eq!(store.stats().faults, 0);
    }
}
