//! Object-store abstraction with compare-and-swap semantics.
//!
//! Every backend exposes the primitives needed to build linearizable
//! coordination on a bucket:
//!
//! - versioned reads (`If-None-Match` → `NotModified`, the cheap freshness
//!   check),
//! - conditional writes (`Create` = if-absent, `Update(v)` = CAS),
//! - conditional deletes, range reads, streaming bodies, paginated listing and
//!   prefix listing.
//!
//! [`Version`] is opaque: GCS generation, S3/R2 ETag, or a counter in
//! [`memory::MemoryStore`]. Callers must never parse it.

use std::fmt;
use std::ops::Range;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use futures::Stream;
use tokio::io::AsyncWriteExt as _;

pub mod contract;
pub mod fault;
pub mod fs;
#[cfg(feature = "gcs")]
pub mod gcs;
pub mod memory;
#[cfg(feature = "s3")]
pub mod s3;

pub use crate::error::StoreError;
pub use fault::FaultStore;
pub use fs::FsStore;
pub use memory::MemoryStore;

pub type BoxStream<'a, T> = Pin<Box<dyn Stream<Item = T> + Send + 'a>>;
pub type ByteStream = BoxStream<'static, Result<Bytes, StoreError>>;
pub type DynStore = Arc<dyn ObjectStore>;

/// Opaque object version. Compare only for equality.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Version(Arc<str>);

impl Version {
    pub fn new(value: impl Into<Arc<str>>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "v{:?}", &*self.0)
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Metadata for one object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectMeta {
    pub key: String,
    /// Whole-object size, also for range reads.
    pub size: u64,
    pub version: Version,
    pub checksum: Option<String>,
}

/// What a trusted edge needs to fetch an object itself.
#[derive(Debug, Clone)]
pub struct AccelTarget {
    pub url: String,
    pub authorization: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct GetOptions {
    /// Return [`GetResult::NotModified`] when the current version equals this.
    pub if_none_match: Option<Version>,
    /// Fail with `PreconditionFailed` when the current version differs.
    pub if_match: Option<Version>,
    /// Half-open byte range; `None` reads the whole object.
    pub range: Option<Range<u64>>,
}

pub enum GetResult {
    NotModified { version: Version },
    Object { meta: ObjectMeta, body: ByteStream },
}

impl std::fmt::Debug for GetResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotModified { version } => f
                .debug_struct("NotModified")
                .field("version", version)
                .finish(),
            Self::Object { meta, .. } => f
                .debug_struct("Object")
                .field("meta", meta)
                .finish_non_exhaustive(),
        }
    }
}

impl GetResult {
    pub async fn bytes(self) -> Result<Option<(ObjectMeta, Bytes)>, StoreError> {
        match self {
            Self::NotModified { .. } => Ok(None),
            Self::Object { meta, body } => {
                let bytes = collect(body, usize::try_from(meta.size).unwrap_or(usize::MAX)).await?;
                Ok(Some((meta, bytes)))
            }
        }
    }

    pub fn version(&self) -> &Version {
        match self {
            Self::NotModified { version } => version,
            Self::Object { meta, .. } => &meta.version,
        }
    }
}

/// Conditional write mode.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum PutMode {
    #[default]
    Overwrite,
    /// Only if the object does not exist.
    Create,
    /// Only if the current version is exactly this one.
    Update(Version),
}

impl From<PutMode> for PutOptions {
    fn from(mode: PutMode) -> Self {
        Self {
            mode,
            ..Self::default()
        }
    }
}

/// Request body for one upload. Streams must carry a known length.
pub enum PutBody {
    Bytes(Bytes),
    Stream { len: u64, stream: ByteStream },
    File(std::path::PathBuf),
}

impl From<Bytes> for PutBody {
    fn from(body: Bytes) -> Self {
        Self::Bytes(body)
    }
}

impl From<Vec<u8>> for PutBody {
    fn from(body: Vec<u8>) -> Self {
        Self::Bytes(Bytes::from(body))
    }
}

impl From<&[u8]> for PutBody {
    fn from(body: &[u8]) -> Self {
        Self::Bytes(Bytes::copy_from_slice(body))
    }
}

#[derive(Clone, Debug, Default)]
pub struct PutOptions {
    pub mode: PutMode,
    pub content_type: Option<&'static str>,
    /// Hint that the object never changes under this key.
    pub immutable: bool,
}

impl PutOptions {
    pub fn create() -> Self {
        PutMode::Create.into()
    }

    pub fn update(version: Version) -> Self {
        PutMode::Update(version).into()
    }

    pub fn immutable(mut self) -> Self {
        self.immutable = true;
        self
    }
}

/// The bucket seam. Implementations must honour the conditional modes and the
/// missing-key conventions (`get`/`head` report absence, unconditional
/// `delete` of a missing key is success).
#[async_trait]
pub trait ObjectStore: Send + Sync + 'static {
    /// Human-readable backend id for logs and metrics.
    fn backend(&self) -> &'static str;

    async fn get(&self, key: &str, opts: GetOptions) -> Result<GetResult, StoreError>;

    /// Metadata only. `None` when absent.
    async fn head(&self, key: &str) -> Result<Option<ObjectMeta>, StoreError>;

    async fn put(
        &self,
        key: &str,
        body: PutBody,
        opts: PutOptions,
    ) -> Result<ObjectMeta, StoreError>;

    /// Delete one key. A missing key is success when unconditional and
    /// `NotFound` when conditional.
    async fn delete(&self, key: &str, if_version: Option<Version>) -> Result<(), StoreError>;

    /// Lexicographically ordered listing, starting after `start_after`.
    fn list(
        &self,
        prefix: &str,
        start_after: Option<&str>,
    ) -> BoxStream<'static, Result<ObjectMeta, StoreError>>;

    /// Direct child "directories" of `prefix` (delimited listing). `prefix`
    /// must end in `/` or be empty.
    async fn list_prefixes(&self, prefix: &str) -> Result<Vec<String>, StoreError>;

    /// Presigned/authenticated GET URL, when the backend supports it.
    async fn signed_get_url(
        &self,
        _key: &str,
        _ttl: Duration,
    ) -> Result<Option<String>, StoreError> {
        Ok(None)
    }

    /// How a trusted edge can fetch `key` itself.
    async fn accel_target(&self, _key: &str) -> Result<Option<AccelTarget>, StoreError> {
        Ok(None)
    }
}

/// Convenience methods shared by all backends.
#[async_trait]
pub trait ObjectStoreExt: ObjectStore {
    async fn get_bytes(&self, key: &str) -> Result<Option<(ObjectMeta, Bytes)>, StoreError> {
        match self.get(key, GetOptions::default()).await {
            Ok(result) => result.bytes().await,
            Err(StoreError::NotFound { .. }) => Ok(None),
            Err(error) => Err(error),
        }
    }

    async fn get_if_changed(
        &self,
        key: &str,
        known: &Version,
    ) -> Result<Option<(ObjectMeta, Bytes)>, StoreError> {
        let result = self
            .get(
                key,
                GetOptions {
                    if_none_match: Some(known.clone()),
                    ..GetOptions::default()
                },
            )
            .await?;
        result.bytes().await
    }

    async fn put_bytes(
        &self,
        key: &str,
        body: impl Into<Bytes> + Send,
        mode: PutMode,
    ) -> Result<ObjectMeta, StoreError> {
        self.put(key, PutBody::Bytes(body.into()), mode.into())
            .await
    }

    async fn exists(&self, key: &str) -> Result<bool, StoreError> {
        Ok(self.head(key).await?.is_some())
    }

    async fn put_file(
        &self,
        key: &str,
        path: &std::path::Path,
        mode: PutMode,
    ) -> Result<ObjectMeta, StoreError> {
        let bytes = tokio::fs::read(path).await?;
        self.put(key, bytes.into(), mode.into()).await
    }

    async fn delete_prefix(&self, prefix: &str) -> Result<(), StoreError> {
        check_delete_prefix(prefix)?;
        use futures::StreamExt as _;
        let mut stream = self.list(prefix, None);
        let mut keys = Vec::new();
        while let Some(item) = stream.next().await {
            keys.push(item?.key);
        }
        for key in keys {
            self.delete(&key, None).await?;
        }
        Ok(())
    }

    async fn get_to_file(&self, key: &str, dest: &std::path::Path) -> Result<bool, StoreError> {
        match self.get(key, GetOptions::default()).await {
            Ok(result) => {
                let (_, bytes) = match result.bytes().await? {
                    Some(value) => value,
                    None => return Ok(false),
                };
                if let Some(parent) = dest.parent() {
                    tokio::fs::create_dir_all(parent).await?;
                }
                tokio::fs::write(dest, bytes).await?;
                Ok(true)
            }
            Err(StoreError::NotFound { .. }) => Ok(false),
            Err(error) => Err(error),
        }
    }
}

impl<T: ObjectStore + ?Sized> ObjectStoreExt for T {}

/// A store scoped to one key prefix. Keys are relative to the prefix.
#[derive(Clone)]
pub struct Prefixed {
    inner: DynStore,
    prefix: Arc<str>,
}

impl Prefixed {
    pub fn new(inner: DynStore, prefix: impl Into<Arc<str>>) -> Self {
        let prefix = prefix.into();
        debug_assert!(prefix.is_empty() || prefix.ends_with('/'));
        Self { inner, prefix }
    }

    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    pub fn inner(&self) -> &DynStore {
        &self.inner
    }

    fn full(&self, key: &str) -> String {
        format!("{}{key}", self.prefix)
    }

    fn strip(&self, mut meta: ObjectMeta) -> ObjectMeta {
        if let Some(rest) = meta.key.strip_prefix(&*self.prefix) {
            meta.key = rest.to_string();
        }
        meta
    }

    fn strip_error(&self, error: StoreError) -> StoreError {
        match error {
            StoreError::NotFound { key } => StoreError::NotFound {
                key: key
                    .strip_prefix(&*self.prefix)
                    .map(str::to_string)
                    .unwrap_or(key),
            },
            StoreError::PreconditionFailed { key, current } => StoreError::PreconditionFailed {
                key: key
                    .strip_prefix(&*self.prefix)
                    .map(str::to_string)
                    .unwrap_or(key),
                current,
            },
            other => other,
        }
    }
}

#[async_trait]
impl ObjectStore for Prefixed {
    fn backend(&self) -> &'static str {
        self.inner.backend()
    }

    async fn get(&self, key: &str, opts: GetOptions) -> Result<GetResult, StoreError> {
        let key = self.full(key);
        match self.inner.get(&key, opts).await {
            Ok(GetResult::Object { meta, body }) => Ok(GetResult::Object {
                meta: self.strip(meta),
                body,
            }),
            Ok(other) => Ok(other),
            Err(error) => Err(self.strip_error(error)),
        }
    }

    async fn head(&self, key: &str) -> Result<Option<ObjectMeta>, StoreError> {
        let key = self.full(key);
        Ok(self.inner.head(&key).await?.map(|meta| self.strip(meta)))
    }

    async fn put(
        &self,
        key: &str,
        body: PutBody,
        opts: PutOptions,
    ) -> Result<ObjectMeta, StoreError> {
        let full = self.full(key);
        Ok(self.strip(self.inner.put(&full, body, opts).await?))
    }

    async fn delete(&self, key: &str, if_version: Option<Version>) -> Result<(), StoreError> {
        let full = self.full(key);
        self.inner.delete(&full, if_version).await
    }

    fn list(
        &self,
        prefix: &str,
        start_after: Option<&str>,
    ) -> BoxStream<'static, Result<ObjectMeta, StoreError>> {
        let full = self.full(prefix);
        let start = start_after.map(|key| self.full(key));
        let inner = self.inner.clone();
        let strip_prefix = self.prefix.clone();
        Box::pin(futures::stream::unfold(
            (inner.list(&full, start.as_deref()), strip_prefix),
            |(mut stream, strip_prefix)| async move {
                use futures::StreamExt as _;
                let item = stream.next().await?;
                let item = item.map(|mut meta| {
                    if let Some(rest) = meta.key.strip_prefix(&*strip_prefix) {
                        meta.key = rest.to_string();
                    }
                    meta
                });
                Some((item, (stream, strip_prefix)))
            },
        ))
    }

    async fn list_prefixes(&self, prefix: &str) -> Result<Vec<String>, StoreError> {
        let full = self.full(prefix);
        let prefixes = self.inner.list_prefixes(&full).await?;
        Ok(prefixes
            .into_iter()
            .map(|item| {
                item.strip_prefix(&*self.prefix)
                    .map(str::to_string)
                    .unwrap_or(item)
            })
            .collect())
    }

    async fn signed_get_url(&self, key: &str, ttl: Duration) -> Result<Option<String>, StoreError> {
        let full = self.full(key);
        self.inner.signed_get_url(&full, ttl).await
    }

    async fn accel_target(&self, key: &str) -> Result<Option<AccelTarget>, StoreError> {
        let full = self.full(key);
        self.inner.accel_target(&full).await
    }
}

/// Guard for prefix deletes: prefixes are whole slug scopes, so an empty
/// prefix or one without a trailing `/` names a wider scope than intended.
pub fn check_delete_prefix(prefix: &str) -> Result<(), StoreError> {
    if prefix.is_empty() {
        return Err(StoreError::invalid(
            "refusing to delete the empty store prefix",
        ));
    }
    if !prefix.ends_with('/') {
        return Err(StoreError::invalid(format!(
            "refusing to delete store prefix without a trailing slash: {prefix:?}"
        )));
    }
    Ok(())
}

/// Retry policy for transient store failures. CAS conflicts are never retried
/// here; the caller must re-read and revalidate.
#[derive(Clone, Debug)]
pub struct RetryPolicy {
    pub attempts: u32,
    pub base: Duration,
    pub max: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            attempts: 6,
            base: Duration::from_millis(40),
            max: Duration::from_secs(2),
        }
    }
}

impl RetryPolicy {
    /// Exponential backoff with full jitter for attempt `n` (0-based).
    pub fn delay(&self, n: u32) -> Duration {
        let exp = self.base.saturating_mul(1u32 << n.min(10));
        let cap = exp.min(self.max);
        let millis = cap.as_millis().max(1) as u64;
        let jitter = rand::random::<u64>() % millis.max(1);
        Duration::from_millis(jitter)
    }

    /// Run `f`, retrying only [`StoreError::Retryable`].
    pub async fn run<T, F, Fut>(&self, mut f: F) -> Result<T, StoreError>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = Result<T, StoreError>>,
    {
        let mut attempt = 0;
        loop {
            match f().await {
                Ok(value) => return Ok(value),
                Err(error) if error.is_retryable() && attempt + 1 < self.attempts => {
                    tokio::time::sleep(self.delay(attempt)).await;
                    attempt += 1;
                }
                Err(error) => return Err(error),
            }
        }
    }
}

/// Collect a byte stream into memory, refusing more than `cap` bytes.
pub async fn collect(mut stream: ByteStream, cap: usize) -> Result<Bytes, StoreError> {
    use futures::StreamExt as _;
    let mut out = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        if out.len().saturating_add(chunk.len()) > cap {
            return Err(StoreError::invalid(format!(
                "object body exceeds {cap} bytes"
            )));
        }
        out.extend_from_slice(&chunk);
    }
    Ok(Bytes::from(out))
}

/// Stream a local file as a [`ByteStream`].
pub fn file_stream(path: std::path::PathBuf) -> Result<(u64, ByteStream), StoreError> {
    let file = std::fs::File::open(&path)?;
    let len = file.metadata()?.len();
    let file = tokio::fs::File::from_std(file);
    let stream = futures::stream::try_unfold(Some(file), move |state| async move {
        let Some(mut file) = state else {
            return Ok(None);
        };
        let mut buf = vec![0u8; 64 * 1024];
        let n = {
            use tokio::io::AsyncReadExt as _;
            file.read(&mut buf).await?
        };
        if n == 0 {
            return Ok(None);
        }
        buf.truncate(n);
        Ok(Some((Bytes::from(buf), Some(file))))
    });
    Ok((len, Box::pin(stream)))
}

/// Write a byte stream to `dest` atomically (tmp + rename).
pub async fn write_stream_atomic(mut stream: ByteStream, dest: &Path) -> Result<u64, StoreError> {
    use futures::StreamExt as _;
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);

    if let Some(parent) = dest.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let tmp = loop {
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let candidate = dest.with_extension(format!("tmp-{}-{n}", std::process::id()));
        match tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
            .await
        {
            Ok(file) => break (candidate, file),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    };
    let (tmp, mut file) = tmp;
    let result = async {
        let mut written = 0u64;
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            file.write_all(&chunk).await?;
            written += chunk.len() as u64;
        }
        file.flush().await?;
        file.sync_all().await?;
        drop(file);
        tokio::fs::rename(&tmp, dest).await?;
        Ok::<u64, StoreError>(written)
    }
    .await;
    if result.is_err() {
        let _ = tokio::fs::remove_file(&tmp).await;
    }
    result
}
