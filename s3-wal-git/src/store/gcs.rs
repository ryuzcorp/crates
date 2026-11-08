//! Google Cloud Storage backend (feature `gcs`).
//!
//! [`GcsStore`] uses the generation number as [`Version`]. Conditional reads
//! and writes map to `ifGenerationMatch`/`ifGenerationNotMatch`, deletes are
//! generation-conditional, listing paginates with `start_after`, and GET URLs
//! are V4-signed when a signer is available.
//!
//! Missing keys follow the shared contract: `get`/`head` report `NotFound`,
//! unconditional `delete` of a missing key succeeds. Transport failures and
//! 408/409/429/5xx map to [`StoreError::Retryable`].

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use futures::StreamExt as _;
use google_cloud_storage::builder::storage::SignedUrlBuilder;
use google_cloud_storage::client::{Storage, StorageControl};
use google_cloud_storage::model::{Object, ObjectChecksums};
use google_cloud_storage::model_ext::ReadRange;
use google_cloud_storage::read_object::ReadObjectResponse;
use google_cloud_storage::streaming_source::{SizeHint, StreamingSource};
use google_cloud_storage::Error as GcsError;

use super::{
    BoxStream, ByteStream, GetOptions, GetResult, ObjectMeta, ObjectStore, PutBody, PutMode,
    PutOptions, StoreError, Version,
};

const MAX_PRESIGN: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// Configuration for [`GcsStore`].
#[derive(Clone, Debug)]
pub struct GcsConfig {
    /// Bucket name (`my-bucket`) or full resource (`projects/_/buckets/my-bucket`).
    pub bucket: String,
    /// Custom endpoint, e.g. a storage emulator.
    pub endpoint: Option<String>,
    /// Use anonymous credentials (public buckets, emulators).
    pub anonymous: bool,
    /// Payloads at least this large use resumable uploads.
    pub resumable_upload_threshold: Option<usize>,
}

impl GcsConfig {
    pub fn new(bucket: impl Into<String>) -> Self {
        Self {
            bucket: bucket.into(),
            endpoint: None,
            anonymous: false,
            resumable_upload_threshold: None,
        }
    }

    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = Some(endpoint.into());
        self
    }

    pub fn with_anonymous(mut self, anonymous: bool) -> Self {
        self.anonymous = anonymous;
        self
    }

    pub fn with_resumable_upload_threshold(mut self, bytes: usize) -> Self {
        self.resumable_upload_threshold = Some(bytes);
        self
    }
}

/// A Google Cloud Storage bucket.
#[derive(Clone)]
pub struct GcsStore {
    storage: Storage,
    control: StorageControl,
    bucket: Arc<str>,
    bucket_path: Arc<str>,
    signer: Option<google_cloud_auth::signer::Signer>,
}

impl GcsStore {
    pub async fn new(config: GcsConfig) -> Result<Self, StoreError> {
        let bucket = config.bucket.trim().to_string();
        if bucket.is_empty() {
            return Err(StoreError::invalid("gcs bucket must not be empty"));
        }
        let bucket_path = if bucket.starts_with("projects/") {
            bucket.clone()
        } else {
            format!("projects/_/buckets/{bucket}")
        };
        let anonymous = config
            .anonymous
            .then(|| google_cloud_auth::credentials::anonymous::Builder::new().build());

        let mut storage_builder = Storage::builder();
        if let Some(endpoint) = &config.endpoint {
            storage_builder = storage_builder.with_endpoint(endpoint.clone());
        }
        if let Some(credentials) = &anonymous {
            storage_builder = storage_builder.with_credentials(credentials.clone());
        }
        if let Some(threshold) = config.resumable_upload_threshold {
            storage_builder = storage_builder.with_resumable_upload_threshold(threshold);
        }
        let storage = storage_builder.build().await.map_err(|error| {
            StoreError::Other(anyhow::anyhow!("building gcs storage client: {error}"))
        })?;

        let mut control_builder = StorageControl::builder();
        if let Some(endpoint) = &config.endpoint {
            control_builder = control_builder.with_endpoint(endpoint.clone());
        }
        if let Some(credentials) = &anonymous {
            control_builder = control_builder.with_credentials(credentials.clone());
        }
        let control = control_builder.build().await.map_err(|error| {
            StoreError::Other(anyhow::anyhow!("building gcs control client: {error}"))
        })?;

        let signer = if config.anonymous {
            None
        } else {
            google_cloud_auth::credentials::Builder::default()
                .build_signer()
                .ok()
        };
        Ok(Self {
            storage,
            control,
            bucket: Arc::from(bucket),
            bucket_path: Arc::from(bucket_path),
            signer,
        })
    }

    /// Build from already configured clients; `signer` enables signed URLs.
    pub fn from_clients(
        bucket: impl Into<String>,
        storage: Storage,
        control: StorageControl,
        signer: Option<google_cloud_auth::signer::Signer>,
    ) -> Self {
        let bucket = bucket.into();
        let bucket_path = if bucket.starts_with("projects/") {
            bucket.clone()
        } else {
            format!("projects/_/buckets/{bucket}")
        };
        Self {
            storage,
            control,
            bucket: Arc::from(bucket),
            bucket_path: Arc::from(bucket_path),
            signer,
        }
    }

    pub fn bucket(&self) -> &str {
        &self.bucket
    }

    fn bucket_path(&self) -> &str {
        &self.bucket_path
    }

    async fn enrich_precondition(&self, key: &str, error: StoreError) -> StoreError {
        if let StoreError::PreconditionFailed { current: None, .. } = &error {
            if let Ok(Some(meta)) = self.head(key).await {
                return StoreError::precondition(key, Some(meta.version.to_string()));
            }
        }
        error
    }

    fn into_get_result(key: &str, response: ReadObjectResponse) -> GetResult {
        let highlights = response.object();
        let meta = ObjectMeta {
            key: key.to_string(),
            size: highlights.size.max(0) as u64,
            version: Version::new(highlights.generation.to_string()),
            checksum: checksum_of(highlights.checksums.as_ref()),
        };
        GetResult::Object {
            meta,
            body: gcs_body_stream(response, key.to_string()),
        }
    }

    async fn read_unconditional(
        &self,
        key: &str,
        range: Option<std::ops::Range<u64>>,
    ) -> Result<GetResult, StoreError> {
        let mut request = self.storage.read_object(self.bucket_path(), key);
        if let Some(range) = range {
            request =
                request.set_read_range(ReadRange::segment(range.start, range.end - range.start));
        }
        let response = request
            .send()
            .await
            .map_err(|error| map_gcs_error(key, error))?;
        Ok(Self::into_get_result(key, response))
    }
}

#[async_trait]
impl ObjectStore for GcsStore {
    fn backend(&self) -> &'static str {
        "gcs"
    }

    async fn get(&self, key: &str, opts: GetOptions) -> Result<GetResult, StoreError> {
        if let Some(range) = &opts.range {
            if range.start > range.end {
                return Err(StoreError::invalid(format!(
                    "range {}..{} is inverted",
                    range.start, range.end
                )));
            }
            if range.start == range.end {
                let Some(meta) = self.head(key).await? else {
                    return Err(StoreError::not_found(key));
                };
                if range.start > meta.size {
                    return Err(StoreError::invalid(format!(
                        "range {}..{} is outside 0..{}",
                        range.start, range.end, meta.size
                    )));
                }
                if opts.if_none_match.as_ref() == Some(&meta.version) {
                    return Ok(GetResult::NotModified {
                        version: meta.version,
                    });
                }
                if let Some(expected) = &opts.if_match {
                    if expected != &meta.version {
                        return Err(StoreError::precondition(
                            key,
                            Some(meta.version.to_string()),
                        ));
                    }
                }
                return Ok(GetResult::Object {
                    meta,
                    body: empty_stream(),
                });
            }
        }

        let mut request = self.storage.read_object(self.bucket_path(), key);
        if let Some(version) = &opts.if_none_match {
            request = request.set_if_generation_not_match(generation_of(key, version)?);
        }
        if let Some(version) = &opts.if_match {
            request = request.set_if_generation_match(generation_of(key, version)?);
        }
        if let Some(range) = &opts.range {
            request =
                request.set_read_range(ReadRange::segment(range.start, range.end - range.start));
        }
        match request.send().await {
            Ok(response) => Ok(Self::into_get_result(key, response)),
            Err(error) if error.http_status_code() == Some(412) => {
                if let Some(known) = opts.if_none_match.clone() {
                    match self.head(key).await? {
                        Some(meta) if meta.version == known => {
                            Ok(GetResult::NotModified { version: known })
                        }
                        Some(_) => self.read_unconditional(key, opts.range.clone()).await,
                        None => Err(StoreError::not_found(key)),
                    }
                } else {
                    match self.head(key).await? {
                        Some(meta) => Err(StoreError::precondition(
                            key,
                            Some(meta.version.to_string()),
                        )),
                        None => Err(StoreError::not_found(key)),
                    }
                }
            }
            Err(error) => Err(map_gcs_error(key, error)),
        }
    }

    async fn head(&self, key: &str) -> Result<Option<ObjectMeta>, StoreError> {
        match self
            .control
            .get_object()
            .set_bucket(self.bucket_path())
            .set_object(key)
            .send()
            .await
        {
            Ok(object) => Ok(Some(object_meta(key, &object))),
            Err(error) if error.http_status_code() == Some(404) => Ok(None),
            Err(error) => Err(map_gcs_error(key, error)),
        }
    }

    async fn put(
        &self,
        key: &str,
        body: PutBody,
        opts: PutOptions,
    ) -> Result<ObjectMeta, StoreError> {
        macro_rules! upload {
            ($payload:expr, $send:ident) => {{
                let mut request = self.storage.write_object(self.bucket_path(), key, $payload);
                if let Some(content_type) = opts.content_type {
                    request = request.set_content_type(content_type);
                }
                match &opts.mode {
                    PutMode::Overwrite => {}
                    PutMode::Create => request = request.set_if_generation_match(0i64),
                    PutMode::Update(version) => {
                        request = request.set_if_generation_match(generation_of(key, version)?)
                    }
                }
                let object = request
                    .$send()
                    .await
                    .map_err(|error| map_gcs_error(key, error))?;
                Ok::<ObjectMeta, StoreError>(object_meta(key, &object))
            }};
        }
        let result = match body {
            PutBody::Bytes(bytes) => upload!(bytes, send_unbuffered),
            PutBody::Stream { len, stream } => upload!(
                StoreStream {
                    stream: tokio::sync::Mutex::new(stream),
                    len,
                    produced: 0,
                    failed: false,
                },
                send_buffered
            ),
            PutBody::File(path) => {
                let file = tokio::fs::File::open(path)
                    .await
                    .map_err(|error| StoreError::Other(error.into()))?;
                upload!(file, send_unbuffered)
            }
        };
        match result {
            Ok(meta) => Ok(meta),
            Err(error) => Err(self.enrich_precondition(key, error).await),
        }
    }

    async fn delete(&self, key: &str, if_version: Option<Version>) -> Result<(), StoreError> {
        let mut request = self
            .control
            .delete_object()
            .set_bucket(self.bucket_path())
            .set_object(key);
        if let Some(version) = &if_version {
            request = request.set_if_generation_match(generation_of(key, version)?);
        }
        match request.send().await {
            Ok(()) => Ok(()),
            Err(error) if error.http_status_code() == Some(404) && if_version.is_none() => Ok(()),
            Err(error) if error.http_status_code() == Some(404) => Err(StoreError::not_found(key)),
            Err(error) => Err(self
                .enrich_precondition(key, map_gcs_error(key, error))
                .await),
        }
    }

    fn list(
        &self,
        prefix: &str,
        start_after: Option<&str>,
    ) -> BoxStream<'static, Result<ObjectMeta, StoreError>> {
        let state = ListState {
            control: self.control.clone(),
            bucket_path: self.bucket_path.clone(),
            prefix: prefix.to_string(),
            start_after: start_after.map(str::to_string),
            page_token: None,
            buffer: VecDeque::new(),
            done: false,
        };
        Box::pin(futures::stream::try_unfold(state, |mut state| async move {
            loop {
                if let Some(meta) = state.buffer.pop_front() {
                    if state
                        .start_after
                        .as_deref()
                        .is_some_and(|start| meta.key.as_str() <= start)
                    {
                        continue;
                    }
                    return Ok(Some((meta, state)));
                }
                if state.done {
                    return Ok(None);
                }
                let mut request = state
                    .control
                    .list_objects()
                    .set_parent(&*state.bucket_path)
                    .set_prefix(state.prefix.as_str())
                    .set_page_size(1000);
                if let Some(token) = state.page_token.take() {
                    request = request.set_page_token(token);
                } else if let Some(start) = &state.start_after {
                    request = request.set_lexicographic_start(start.as_str());
                }
                let output = request
                    .send()
                    .await
                    .map_err(|error| map_gcs_error(&state.prefix, error))?;
                let next = if output.next_page_token.is_empty() {
                    None
                } else {
                    Some(output.next_page_token.clone())
                };
                state.done = next.is_none();
                state.page_token = next;
                for object in &output.objects {
                    state.buffer.push_back(object_meta_from_list(object)?);
                }
            }
        }))
    }

    async fn list_prefixes(&self, prefix: &str) -> Result<Vec<String>, StoreError> {
        let mut out = Vec::new();
        let mut page_token: Option<String> = None;
        loop {
            let mut request = self
                .control
                .list_objects()
                .set_parent(self.bucket_path())
                .set_prefix(prefix)
                .set_delimiter("/")
                .set_page_size(1000);
            if let Some(token) = page_token.take() {
                request = request.set_page_token(token);
            }
            let output = request
                .send()
                .await
                .map_err(|error| map_gcs_error(prefix, error))?;
            out.extend(output.prefixes.iter().cloned());
            if output.next_page_token.is_empty() {
                break;
            }
            page_token = Some(output.next_page_token);
        }
        out.sort();
        out.dedup();
        Ok(out)
    }

    async fn signed_get_url(&self, key: &str, ttl: Duration) -> Result<Option<String>, StoreError> {
        let Some(signer) = &self.signer else {
            return Ok(None);
        };
        if ttl.is_zero() || ttl > MAX_PRESIGN {
            return Err(StoreError::invalid(
                "gcs signed URL lifetime must be between 1s and 7 days",
            ));
        }
        let url = SignedUrlBuilder::for_object(&*self.bucket_path, key)
            .with_expiration(ttl)
            .sign_with(signer)
            .await
            .map_err(|error| {
                StoreError::Other(anyhow::anyhow!("signing gcs URL failed: {error}"))
            })?;
        Ok(Some(url))
    }
}

/// Streams declared-length bodies and rejects mismatches at either end.
struct StoreStream {
    // The uploader requires `Sync` sources; a Tokio mutex keeps the
    // single-consumer stream safe to share behind the trait bound.
    stream: tokio::sync::Mutex<ByteStream>,
    len: u64,
    produced: u64,
    failed: bool,
}

impl StreamingSource for StoreStream {
    type Error = StoreError;

    async fn next(&mut self) -> Option<Result<Bytes, StoreError>> {
        if self.failed {
            return None;
        }
        let mut stream = self.stream.lock().await;
        match stream.next().await {
            None => {
                if self.produced != self.len {
                    self.failed = true;
                    Some(Err(StoreError::invalid(format!(
                        "body length {} disagrees with declared length {}",
                        self.produced, self.len
                    ))))
                } else {
                    None
                }
            }
            Some(Err(error)) => {
                self.failed = true;
                Some(Err(error))
            }
            Some(Ok(chunk)) => {
                self.produced = self.produced.saturating_add(chunk.len() as u64);
                if self.produced > self.len {
                    self.failed = true;
                    Some(Err(StoreError::invalid(format!(
                        "body exceeds declared length {}",
                        self.len
                    ))))
                } else {
                    Some(Ok(chunk))
                }
            }
        }
    }

    async fn size_hint(&self) -> Result<SizeHint, StoreError> {
        Ok(SizeHint::with_exact(self.len))
    }
}

fn empty_stream() -> ByteStream {
    Box::pin(futures::stream::once(async { Ok(Bytes::new()) }))
}

fn gcs_body_stream(response: ReadObjectResponse, key: String) -> ByteStream {
    Box::pin(futures::stream::unfold(
        Some((response, key)),
        |state| async move {
            let (mut response, key) = state?;
            match response.next().await {
                None => None,
                Some(Ok(chunk)) => Some((Ok(chunk), Some((response, key)))),
                Some(Err(error)) => Some((Err(map_gcs_error(&key, error)), None)),
            }
        },
    ))
}

fn checksum_of(checksums: Option<&ObjectChecksums>) -> Option<String> {
    let checksums = checksums?;
    if !checksums.md5_hash.is_empty() {
        Some(hex::encode(checksums.md5_hash.as_ref()))
    } else {
        checksums.crc32c.map(|value| format!("crc32c:{value:08x}"))
    }
}

fn object_meta(key: &str, object: &Object) -> ObjectMeta {
    ObjectMeta {
        key: key.to_string(),
        size: object.size.max(0) as u64,
        version: Version::new(object.generation.to_string()),
        checksum: checksum_of(object.checksums.as_ref()),
    }
}

fn object_meta_from_list(object: &Object) -> Result<ObjectMeta, StoreError> {
    if object.name.is_empty() {
        return Err(StoreError::Other(anyhow::anyhow!(
            "gcs listing entry has no name"
        )));
    }
    Ok(object_meta(&object.name, object))
}

fn generation_of(key: &str, version: &Version) -> Result<i64, StoreError> {
    version.as_str().parse::<i64>().map_err(|_| {
        StoreError::invalid(format!(
            "gcs version {:?} for {key} is not a generation number",
            version.as_str()
        ))
    })
}

fn map_gcs_error(key: &str, error: GcsError) -> StoreError {
    // The uploader wraps streaming-source errors as serialization errors; keep
    // our typed contract (notably `InvalidArgument` for length mismatches).
    if error.is_serialization() {
        if let Some(source) = std::error::Error::source(&error) {
            if let Some(store) = source.downcast_ref::<StoreError>() {
                return match store {
                    StoreError::InvalidArgument(message) => StoreError::invalid(message.clone()),
                    StoreError::NotFound { key } => StoreError::not_found(key.clone()),
                    StoreError::PreconditionFailed { key, current } => {
                        StoreError::precondition(key.clone(), current.clone())
                    }
                    StoreError::Retryable(_) => StoreError::retryable(anyhow::anyhow!("{store}")),
                    other => StoreError::Other(anyhow::anyhow!("{other}")),
                };
            }
        }
    }
    let status = error.http_status_code();
    let message = format!("gcs operation on {key} failed: {error}");
    match status {
        Some(404) => StoreError::not_found(key),
        Some(408) | Some(409) | Some(429) | Some(500) | Some(502) | Some(503) | Some(504) => {
            StoreError::retryable(anyhow::anyhow!(message))
        }
        Some(412) => StoreError::precondition(key, None),
        Some(416) => StoreError::invalid(format!("range not satisfiable for {key}")),
        None if error.is_io() || error.is_timeout() || error.is_connect() => {
            StoreError::retryable(anyhow::anyhow!(message))
        }
        _ => StoreError::Other(anyhow::anyhow!(message)),
    }
}

struct ListState {
    control: StorageControl,
    bucket_path: Arc<str>,
    prefix: String,
    start_after: Option<String>,
    page_token: Option<String>,
    buffer: VecDeque<ObjectMeta>,
    done: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::contract;

    async fn test_store() -> Option<GcsStore> {
        let bucket = std::env::var("WALGIT_GCS_BUCKET").ok()?;
        let mut config = GcsConfig::new(bucket);
        if let Ok(endpoint) = std::env::var("WALGIT_GCS_ENDPOINT") {
            config = config.with_endpoint(endpoint).with_anonymous(true);
        }
        Some(GcsStore::new(config).await.expect("gcs store"))
    }

    #[tokio::test]
    async fn gcs_passes_the_contract_when_configured() {
        let Some(store) = test_store().await else {
            eprintln!("WALGIT_GCS_BUCKET not set; skipping GCS contract");
            return;
        };
        contract::run(&store, "walgit-contract/").await;
    }

    #[tokio::test]
    async fn store_stream_enforces_declared_len() {
        let bytes: ByteStream = Box::pin(futures::stream::iter(vec![Ok(Bytes::from_static(
            b"abcdef",
        ))]));
        let mut source = StoreStream {
            stream: tokio::sync::Mutex::new(bytes),
            len: 6,
            produced: 0,
            failed: false,
        };
        assert_eq!(
            source.next().await.unwrap().unwrap(),
            Bytes::from_static(b"abcdef")
        );
        assert!(source.next().await.is_none());
        assert_eq!(source.size_hint().await.unwrap().exact(), Some(6));

        let short: ByteStream =
            Box::pin(futures::stream::iter(vec![Ok(Bytes::from_static(b"abc"))]));
        let mut source = StoreStream {
            stream: tokio::sync::Mutex::new(short),
            len: 6,
            produced: 0,
            failed: false,
        };
        assert!(source.next().await.unwrap().is_ok());
        assert!(source.next().await.unwrap().is_err());

        let long: ByteStream = Box::pin(futures::stream::iter(vec![Ok(Bytes::from_static(
            b"abcdefg",
        ))]));
        let mut source = StoreStream {
            stream: tokio::sync::Mutex::new(long),
            len: 6,
            produced: 0,
            failed: false,
        };
        assert!(source.next().await.unwrap().is_err());
    }

    #[test]
    fn versions_are_generations() {
        let version = Version::new("42");
        assert_eq!(generation_of("k", &version).unwrap(), 42);
        assert!(generation_of("k", &Version::new("etag")).is_err());
    }

    #[test]
    fn checksum_prefers_md5_then_crc32c() {
        let mut checksums = ObjectChecksums::new();
        checksums.crc32c = Some(0x1234_5678);
        assert_eq!(
            checksum_of(Some(&checksums)),
            Some("crc32c:12345678".to_string())
        );
        checksums.md5_hash = Bytes::from_static(&[0xab, 0xcd]);
        assert_eq!(checksum_of(Some(&checksums)), Some("abcd".to_string()));
    }
}
