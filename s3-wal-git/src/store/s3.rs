//! S3/R2/MinIO backend (feature `s3`).
//!
//! [`S3Store`] maps an object ETag to [`Version`], implements conditional
//! reads and writes with `If-Match`/`If-None-Match`, streams bodies with
//! multipart uploads above the configured threshold, paginates listings with
//! `start_after`, and presigns GET URLs.
//!
//! Missing keys follow the shared contract: `get`/`head` report `NotFound`,
//! unconditional `delete` of a missing key succeeds. Only genuinely transient
//! failures (429, 408, 409, 5xx, timeouts, dispatch errors) map to
//! [`StoreError::Retryable`]; everything else is terminal.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use aws_sdk_s3::error::SdkError;
use aws_sdk_s3::primitives::ByteStream as SdkByteStream;
use aws_sdk_s3::types::{CompletedMultipartUpload, CompletedPart};
use aws_sdk_s3::Client;
use bytes::Bytes;
use futures::StreamExt as _;

use super::{
    BoxStream, ByteStream, GetOptions, GetResult, ObjectMeta, ObjectStore, PutBody, PutMode,
    PutOptions, StoreError, Version,
};

const DEFAULT_MULTIPART_THRESHOLD: u64 = 8 * 1024 * 1024;
const MIN_PART_SIZE: u64 = 5 * 1024 * 1024;
const MAX_PARTS: u64 = 10_000;
const MAX_PRESIGN: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// Configuration for [`S3Store`].
#[derive(Clone, Debug)]
pub struct S3Config {
    /// Bucket name.
    pub bucket: String,
    /// Explicit region; defaults to the standard AWS provider chain.
    pub region: Option<String>,
    /// Custom endpoint for MinIO, R2, or an emulator.
    pub endpoint: Option<String>,
    /// Use path-style addressing (required by most MinIO deployments).
    pub force_path_style: bool,
    /// Static access key; when omitted the default credential chain is used.
    pub access_key_id: Option<String>,
    /// Static secret key; required when `access_key_id` is set.
    pub secret_access_key: Option<String>,
    /// Optional session token paired with the static credentials.
    pub session_token: Option<String>,
    /// Bodies strictly larger than this are uploaded with multipart.
    pub multipart_threshold: u64,
}

impl S3Config {
    pub fn new(bucket: impl Into<String>) -> Self {
        Self {
            bucket: bucket.into(),
            region: None,
            endpoint: None,
            force_path_style: false,
            access_key_id: None,
            secret_access_key: None,
            session_token: None,
            multipart_threshold: DEFAULT_MULTIPART_THRESHOLD,
        }
    }

    pub fn with_region(mut self, region: impl Into<String>) -> Self {
        self.region = Some(region.into());
        self
    }

    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = Some(endpoint.into());
        self
    }

    pub fn with_path_style(mut self, enabled: bool) -> Self {
        self.force_path_style = enabled;
        self
    }

    pub fn with_credentials(
        mut self,
        access_key_id: impl Into<String>,
        secret_access_key: impl Into<String>,
        session_token: Option<String>,
    ) -> Self {
        self.access_key_id = Some(access_key_id.into());
        self.secret_access_key = Some(secret_access_key.into());
        self.session_token = session_token;
        self
    }

    pub fn with_multipart_threshold(mut self, bytes: u64) -> Self {
        self.multipart_threshold = bytes;
        self
    }
}

/// An S3-compatible object store scoped to one bucket.
#[derive(Clone)]
pub struct S3Store {
    client: Client,
    bucket: Arc<str>,
    multipart_threshold: u64,
}

impl S3Store {
    pub async fn new(config: S3Config) -> Result<Self, StoreError> {
        let bucket = config.bucket.trim();
        if bucket.is_empty() {
            return Err(StoreError::invalid("s3 bucket must not be empty"));
        }
        if config.multipart_threshold == 0 {
            return Err(StoreError::invalid(
                "s3 multipart threshold must be positive",
            ));
        }
        let mut loader = aws_config::defaults(aws_config::BehaviorVersion::latest());
        if let Some(region) = &config.region {
            loader = loader.region(aws_config::Region::new(region.clone()));
        }
        if let Some(endpoint) = &config.endpoint {
            loader = loader.endpoint_url(endpoint.clone());
        }
        match (&config.access_key_id, &config.secret_access_key) {
            (Some(access_key_id), Some(secret_access_key)) => {
                let credentials = aws_sdk_s3::config::Credentials::new(
                    access_key_id.clone(),
                    secret_access_key.clone(),
                    config.session_token.clone(),
                    None,
                    "s3-wal-git",
                );
                loader = loader.credentials_provider(credentials);
            }
            (None, None) => {}
            _ => {
                return Err(StoreError::invalid(
                    "s3 static credentials need both access_key_id and secret_access_key",
                ))
            }
        }
        let shared = loader.load().await;
        let mut builder = aws_sdk_s3::config::Builder::from(&shared);
        if config.force_path_style {
            builder = builder.force_path_style(true);
        }
        Ok(Self {
            client: Client::from_conf(builder.build()),
            bucket: Arc::from(bucket),
            multipart_threshold: config.multipart_threshold,
        })
    }

    /// Build from an already configured client (tests, custom middleware).
    pub fn from_client(bucket: impl Into<String>, client: Client) -> Self {
        Self {
            client,
            bucket: Arc::from(bucket.into()),
            multipart_threshold: DEFAULT_MULTIPART_THRESHOLD,
        }
    }

    pub fn with_multipart_threshold(mut self, bytes: u64) -> Self {
        self.multipart_threshold = bytes.max(1);
        self
    }

    pub fn bucket(&self) -> &str {
        &self.bucket
    }

    async fn enrich_precondition(&self, key: &str, error: StoreError) -> StoreError {
        if let StoreError::PreconditionFailed { current: None, .. } = &error {
            if let Ok(Some(meta)) = self.head(key).await {
                return StoreError::precondition(key, Some(meta.version.to_string()));
            }
        }
        error
    }

    async fn put_single(
        &self,
        key: &str,
        body: PutBody,
        len: u64,
        opts: &PutOptions,
    ) -> Result<ObjectMeta, StoreError> {
        let max = usize::try_from(len)
            .map_err(|_| StoreError::invalid("object is too large for this platform"))?;
        let mut chunker = Chunker::new(body);
        let mut buffer = Vec::with_capacity(max.min(8 * 1024 * 1024));
        while let Some(chunk) = chunker.next_part(max).await? {
            buffer.extend_from_slice(&chunk);
            if buffer.len() as u64 > len {
                return Err(StoreError::invalid(format!(
                    "body exceeds declared length {len}"
                )));
            }
        }
        chunker.ensure_exhausted(len).await?;
        if buffer.len() as u64 != len {
            return Err(StoreError::invalid(format!(
                "body length {} disagrees with declared length {len}",
                buffer.len()
            )));
        }
        let mut request = self
            .client
            .put_object()
            .bucket(&*self.bucket)
            .key(key)
            .body(SdkByteStream::from(Bytes::from(buffer)));
        if let Some(content_type) = opts.content_type {
            request = request.content_type(content_type);
        }
        match &opts.mode {
            PutMode::Overwrite => {}
            PutMode::Create => request = request.if_none_match("*"),
            PutMode::Update(version) => request = request.if_match(version.as_str()),
        }
        let conditional = !matches!(opts.mode, PutMode::Overwrite);
        let output = request
            .send()
            .await
            .map_err(|error| map_sdk_error(key, error))
            .map_err(|error| ambiguous_conditional(key, error, conditional))?;
        let checksum = output.checksum_sha256().map(str::to_string);
        match output.e_tag() {
            Some(etag) => Ok(ObjectMeta {
                key: key.to_string(),
                size: len,
                version: Version::new(etag),
                checksum: checksum.or_else(|| Some(etag.to_string())),
            }),
            None => self
                .head(key)
                .await?
                .ok_or_else(|| StoreError::Other(anyhow::anyhow!("s3 put returned no ETag"))),
        }
    }

    async fn put_multipart(
        &self,
        key: &str,
        body: PutBody,
        len: u64,
        opts: &PutOptions,
    ) -> Result<ObjectMeta, StoreError> {
        let part_size = self.part_size(len)?;
        let mut create = self
            .client
            .create_multipart_upload()
            .bucket(&*self.bucket)
            .key(key);
        if let Some(content_type) = opts.content_type {
            create = create.content_type(content_type);
        }
        let upload_id = create
            .send()
            .await
            .map_err(|error| map_sdk_error(key, error))?
            .upload_id()
            .ok_or_else(|| {
                StoreError::Other(anyhow::anyhow!(
                    "s3 create_multipart_upload returned no upload id"
                ))
            })?
            .to_string();

        let result = self
            .complete_multipart(key, &upload_id, body, len, part_size, opts)
            .await;
        if result.is_err() {
            let _ = self
                .client
                .abort_multipart_upload()
                .bucket(&*self.bucket)
                .key(key)
                .upload_id(&upload_id)
                .send()
                .await;
        }
        result
    }

    async fn complete_multipart(
        &self,
        key: &str,
        upload_id: &str,
        body: PutBody,
        len: u64,
        part_size: usize,
        opts: &PutOptions,
    ) -> Result<ObjectMeta, StoreError> {
        let mut chunker = Chunker::new(body);
        let mut parts = Vec::new();
        let mut produced = 0u64;
        let mut part_number = 1i32;
        while produced < len {
            if part_number > i32::try_from(MAX_PARTS).expect("fits") {
                return Err(StoreError::invalid("multipart upload exceeds 10000 parts"));
            }
            let chunk = chunker.next_part(part_size).await?.ok_or_else(|| {
                StoreError::invalid(format!(
                    "body ended after {produced} bytes, declared length {len}"
                ))
            })?;
            produced += chunk.len() as u64;
            if produced > len {
                return Err(StoreError::invalid(format!(
                    "body exceeds declared length {len}"
                )));
            }
            let output = self
                .client
                .upload_part()
                .bucket(&*self.bucket)
                .key(key)
                .upload_id(upload_id)
                .part_number(part_number)
                .body(SdkByteStream::from(chunk))
                .send()
                .await
                .map_err(|error| map_sdk_error(key, error))?;
            let etag = output.e_tag().ok_or_else(|| {
                StoreError::Other(anyhow::anyhow!("s3 upload_part returned no ETag"))
            })?;
            parts.push(
                CompletedPart::builder()
                    .part_number(part_number)
                    .e_tag(etag)
                    .build(),
            );
            part_number += 1;
        }
        chunker.ensure_exhausted(len).await?;
        let upload = CompletedMultipartUpload::builder()
            .set_parts(Some(parts))
            .build();
        let mut complete = self
            .client
            .complete_multipart_upload()
            .bucket(&*self.bucket)
            .key(key)
            .upload_id(upload_id)
            .multipart_upload(upload);
        match &opts.mode {
            PutMode::Overwrite => {}
            PutMode::Create => complete = complete.if_none_match("*"),
            PutMode::Update(version) => complete = complete.if_match(version.as_str()),
        }
        let conditional = !matches!(opts.mode, PutMode::Overwrite);
        let output = complete
            .send()
            .await
            .map_err(|error| map_sdk_error(key, error))
            .map_err(|error| ambiguous_conditional(key, error, conditional))?;
        let checksum = output.checksum_sha256().map(str::to_string);
        // CompleteMultipartUpload can answer 200 with an XML error body and no
        // ETag; never report that as success.
        let etag = output.e_tag().ok_or_else(|| {
            StoreError::Other(anyhow::anyhow!(
                "s3 multipart put returned no ETag (completion may have failed)"
            ))
        })?;
        Ok(ObjectMeta {
            key: key.to_string(),
            size: len,
            version: Version::new(etag),
            checksum: checksum.or_else(|| Some(etag.to_string())),
        })
    }

    fn part_size(&self, len: u64) -> Result<usize, StoreError> {
        multipart_part_size(self.multipart_threshold, len)
    }
}

#[async_trait]
impl ObjectStore for S3Store {
    fn backend(&self) -> &'static str {
        "s3"
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

        let mut request = self.client.get_object().bucket(&*self.bucket).key(key);
        if let Some(version) = &opts.if_none_match {
            request = request.if_none_match(version.as_str());
        }
        if let Some(version) = &opts.if_match {
            request = request.if_match(version.as_str());
        }
        if let Some(range) = &opts.range {
            request = request.range(format!("bytes={}-{}", range.start, range.end - 1));
        }

        let output = match request.send().await {
            Ok(output) => output,
            Err(error) if error_status(&error) == Some(304) => {
                let Some(known) = opts.if_none_match else {
                    return Err(map_sdk_error(key, error));
                };
                return Ok(GetResult::NotModified { version: known });
            }
            Err(error) => {
                return Err(self
                    .enrich_precondition(key, map_sdk_error(key, error))
                    .await)
            }
        };

        let full_size = output
            .content_range()
            .and_then(total_from_content_range)
            .or_else(|| output.content_length().map(|value| value.max(0) as u64))
            .unwrap_or(0);
        let etag = output
            .e_tag()
            .ok_or_else(|| StoreError::Other(anyhow::anyhow!("s3 get_object returned no ETag")))?;
        let checksum = output.checksum_sha256().map(str::to_string);
        let meta = ObjectMeta {
            key: key.to_string(),
            size: full_size,
            version: Version::new(etag),
            checksum: checksum.or_else(|| Some(etag.to_string())),
        };
        Ok(GetResult::Object {
            meta,
            body: sdk_body_stream(output.body),
        })
    }

    async fn head(&self, key: &str) -> Result<Option<ObjectMeta>, StoreError> {
        match self
            .client
            .head_object()
            .bucket(&*self.bucket)
            .key(key)
            .send()
            .await
        {
            Ok(output) => {
                let size = output.content_length().unwrap_or(0).max(0) as u64;
                let etag = output.e_tag().ok_or_else(|| {
                    StoreError::Other(anyhow::anyhow!("s3 head_object returned no ETag"))
                })?;
                let checksum = output.checksum_sha256().map(str::to_string);
                Ok(Some(ObjectMeta {
                    key: key.to_string(),
                    size,
                    version: Version::new(etag),
                    checksum: checksum.or_else(|| Some(etag.to_string())),
                }))
            }
            Err(error) if error_status(&error) == Some(404) => Ok(None),
            Err(error) => Err(map_sdk_error(key, error)),
        }
    }

    async fn put(
        &self,
        key: &str,
        body: PutBody,
        opts: PutOptions,
    ) -> Result<ObjectMeta, StoreError> {
        let len = match &body {
            PutBody::Bytes(bytes) => bytes.len() as u64,
            PutBody::Stream { len, .. } => *len,
            PutBody::File(path) => tokio::fs::metadata(path)
                .await
                .map_err(StoreError::from)?
                .len(),
        };
        let result = if len > self.multipart_threshold {
            self.put_multipart(key, body, len, &opts).await
        } else {
            self.put_single(key, body, len, &opts).await
        };
        match result {
            Ok(meta) => Ok(meta),
            Err(error) => Err(self.enrich_precondition(key, error).await),
        }
    }

    async fn delete(&self, key: &str, if_version: Option<Version>) -> Result<(), StoreError> {
        let mut request = self.client.delete_object().bucket(&*self.bucket).key(key);
        if let Some(version) = &if_version {
            request = request.if_match(version.as_str());
        }
        match request.send().await {
            Ok(_) => Ok(()),
            Err(error) if error_status(&error) == Some(404) && if_version.is_none() => Ok(()),
            Err(error) if error_status(&error) == Some(404) => Err(StoreError::not_found(key)),
            Err(error) => {
                let conditional = if_version.is_some();
                let mapped = ambiguous_conditional(key, map_sdk_error(key, error), conditional);
                Err(self.enrich_precondition(key, mapped).await)
            }
        }
    }

    fn list(
        &self,
        prefix: &str,
        start_after: Option<&str>,
    ) -> BoxStream<'static, Result<ObjectMeta, StoreError>> {
        let state = ListState {
            client: self.client.clone(),
            bucket: self.bucket.clone(),
            prefix: prefix.to_string(),
            start_after: start_after.map(str::to_string),
            continuation: None,
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
                    .client
                    .list_objects_v2()
                    .bucket(&*state.bucket)
                    .prefix(state.prefix.as_str());
                if let Some(token) = state.continuation.take() {
                    request = request.continuation_token(token);
                } else if let Some(start) = &state.start_after {
                    request = request.start_after(start.as_str());
                }
                let output = request
                    .send()
                    .await
                    .map_err(|error| map_sdk_error(&state.prefix, error))?;
                let next = output.next_continuation_token().map(str::to_string);
                state.done = !output.is_truncated().unwrap_or(false) || next.is_none();
                state.continuation = next;
                for object in output.contents() {
                    state.buffer.push_back(object_meta(object)?);
                }
            }
        }))
    }

    async fn list_prefixes(&self, prefix: &str) -> Result<Vec<String>, StoreError> {
        let mut out = Vec::new();
        let mut continuation: Option<String> = None;
        loop {
            let mut request = self
                .client
                .list_objects_v2()
                .bucket(&*self.bucket)
                .prefix(prefix)
                .delimiter("/");
            if let Some(token) = continuation.take() {
                request = request.continuation_token(token);
            }
            let output = request
                .send()
                .await
                .map_err(|error| map_sdk_error(prefix, error))?;
            out.extend(
                output
                    .common_prefixes()
                    .iter()
                    .filter_map(|item| item.prefix())
                    .map(str::to_string),
            );
            let next = output.next_continuation_token().map(str::to_string);
            if output.is_truncated().unwrap_or(false) {
                if next.is_none() {
                    return Err(StoreError::Other(anyhow::anyhow!(
                        "s3 list was truncated without a continuation token"
                    )));
                }
                continuation = next;
            } else {
                break;
            }
        }
        out.sort();
        out.dedup();
        Ok(out)
    }

    async fn signed_get_url(&self, key: &str, ttl: Duration) -> Result<Option<String>, StoreError> {
        if ttl.is_zero() || ttl > MAX_PRESIGN {
            return Err(StoreError::invalid(
                "s3 signed URL lifetime must be between 1s and 7 days",
            ));
        }
        let config = aws_sdk_s3::presigning::PresigningConfig::expires_in(ttl)
            .map_err(|error| StoreError::invalid(format!("invalid presign lifetime: {error}")))?;
        let request = self
            .client
            .get_object()
            .bucket(&*self.bucket)
            .key(key)
            .presigned(config)
            .await
            .map_err(|error| map_sdk_error(key, error))?;
        Ok(Some(request.uri().to_string()))
    }
}

fn multipart_part_size(threshold: u64, len: u64) -> Result<usize, StoreError> {
    let spread = len.div_ceil(MAX_PARTS);
    let size = threshold.max(MIN_PART_SIZE).max(spread);
    usize::try_from(size)
        .map_err(|_| StoreError::invalid("multipart part size does not fit in memory"))
}

fn empty_stream() -> ByteStream {
    Box::pin(futures::stream::once(async { Ok(Bytes::new()) }))
}

fn sdk_body_stream(body: SdkByteStream) -> ByteStream {
    Box::pin(futures::stream::unfold(Some(body), |state| async move {
        let mut body = state?;
        match body.try_next().await {
            Ok(Some(chunk)) => Some((Ok(chunk), Some(body))),
            Ok(None) => None,
            Err(error) => Some((
                Err(StoreError::retryable(anyhow::anyhow!(
                    "s3 response body read failed: {error}"
                ))),
                None,
            )),
        }
    }))
}

fn total_from_content_range(value: &str) -> Option<u64> {
    value.rsplit_once('/')?.1.parse().ok()
}

fn object_meta(object: &aws_sdk_s3::types::Object) -> Result<ObjectMeta, StoreError> {
    let key = object
        .key()
        .ok_or_else(|| StoreError::Other(anyhow::anyhow!("s3 listing entry has no key")))?
        .to_string();
    let size = object.size().unwrap_or(0).max(0) as u64;
    let etag = object
        .e_tag()
        .ok_or_else(|| StoreError::Other(anyhow::anyhow!("s3 listing entry {key} has no ETag")))?;
    Ok(ObjectMeta {
        key,
        size,
        version: Version::new(etag),
        checksum: Some(etag.to_string()),
    })
}

/// A conditional mutation whose response was lost may already have applied.
/// Reporting it as retryable would let a retry turn success into a spurious
/// conflict, so surface the ambiguity instead.
fn ambiguous_conditional(key: &str, error: StoreError, conditional: bool) -> StoreError {
    if conditional && error.is_retryable() {
        StoreError::Other(anyhow::anyhow!(
            "ambiguous conditional write for {key}; the operation may have applied"
        ))
    } else {
        error
    }
}

fn error_status<E>(error: &SdkError<E>) -> Option<u16> {
    error
        .raw_response()
        .map(|response| response.status().as_u16())
}

fn map_sdk_error<E>(key: &str, error: SdkError<E>) -> StoreError
where
    E: std::error::Error + Send + Sync + 'static,
{
    match error {
        SdkError::ConstructionFailure(inner) => StoreError::invalid(format!(
            "s3 request construction failed for {key}: {inner:?}"
        )),
        SdkError::TimeoutError(inner) => {
            StoreError::retryable(anyhow::anyhow!("s3 request timed out for {key}: {inner:?}"))
        }
        SdkError::DispatchFailure(inner) => {
            let message = format!("s3 dispatch failure for {key}: {inner:?}");
            if inner.is_timeout() || inner.is_io() {
                StoreError::retryable(anyhow::anyhow!(message))
            } else {
                StoreError::Other(anyhow::anyhow!(message))
            }
        }
        SdkError::ResponseError(inner) => StoreError::retryable(anyhow::anyhow!(
            "s3 response failed while reading {key}: {inner:?}"
        )),
        SdkError::ServiceError(inner) => {
            let status = inner.raw().status().as_u16();
            let message = format!("s3 returned HTTP {status} for {key}: {inner:?}");
            match status {
                404 => StoreError::not_found(key),
                408 | 409 | 429 | 500 | 502 | 503 | 504 => {
                    StoreError::retryable(anyhow::anyhow!(message))
                }
                412 => StoreError::precondition(key, None),
                416 => StoreError::invalid(format!("range not satisfiable for {key}")),
                _ => StoreError::Other(anyhow::anyhow!(message)),
            }
        }
        other => StoreError::Other(anyhow::anyhow!("s3 request for {key} failed: {other:?}")),
    }
}

/// Pulls exactly the declared number of bytes from any [`PutBody`] in parts.
enum Chunker {
    Bytes {
        bytes: Bytes,
        pos: usize,
    },
    File {
        path: PathBuf,
        file: Option<tokio::fs::File>,
    },
    Stream {
        stream: ByteStream,
        pending: Bytes,
    },
}

impl Chunker {
    fn new(body: PutBody) -> Self {
        match body {
            PutBody::Bytes(bytes) => Self::Bytes { bytes, pos: 0 },
            PutBody::File(path) => Self::File { path, file: None },
            PutBody::Stream { stream, .. } => Self::Stream {
                stream,
                pending: Bytes::new(),
            },
        }
    }

    async fn next_part(&mut self, max: usize) -> Result<Option<Bytes>, StoreError> {
        match self {
            Self::Bytes { bytes, pos } => {
                if *pos >= bytes.len() {
                    return Ok(None);
                }
                let end = (*pos + max).min(bytes.len());
                let chunk = bytes.slice(*pos..end);
                *pos = end;
                Ok(Some(chunk))
            }
            Self::File { path, file } => {
                if file.is_none() {
                    *file = Some(
                        tokio::fs::File::open(&*path)
                            .await
                            .map_err(StoreError::from)?,
                    );
                }
                let file = file.as_mut().expect("opened above");
                let mut buffer = vec![0u8; max];
                let read = {
                    use tokio::io::AsyncReadExt as _;
                    file.read(&mut buffer).await.map_err(StoreError::from)?
                };
                if read == 0 {
                    Ok(None)
                } else {
                    buffer.truncate(read);
                    Ok(Some(Bytes::from(buffer)))
                }
            }
            Self::Stream { stream, pending } => {
                let mut out = Vec::with_capacity(max.min(8 * 1024 * 1024));
                while out.len() < max {
                    if pending.is_empty() {
                        match stream.next().await {
                            Some(Ok(chunk)) => {
                                *pending = chunk;
                                if pending.is_empty() {
                                    continue;
                                }
                            }
                            Some(Err(error)) => return Err(error),
                            None => break,
                        }
                    }
                    let take = (max - out.len()).min(pending.len());
                    out.extend_from_slice(&pending[..take]);
                    *pending = pending.slice(take..);
                }
                if out.is_empty() {
                    Ok(None)
                } else {
                    Ok(Some(Bytes::from(out)))
                }
            }
        }
    }

    /// Reject bodies longer than their declared length.
    async fn ensure_exhausted(&mut self, len: u64) -> Result<(), StoreError> {
        let too_long = || StoreError::invalid(format!("body exceeds declared length {len}"));
        match self {
            Self::Bytes { bytes, pos } => {
                if *pos < bytes.len() {
                    return Err(too_long());
                }
            }
            Self::File { path, file } => {
                if file.is_none() {
                    *file = Some(
                        tokio::fs::File::open(&*path)
                            .await
                            .map_err(StoreError::from)?,
                    );
                }
                let file = file.as_mut().expect("opened above");
                let mut buffer = [0u8; 1];
                let read = {
                    use tokio::io::AsyncReadExt as _;
                    file.read(&mut buffer).await.map_err(StoreError::from)?
                };
                if read != 0 {
                    return Err(too_long());
                }
            }
            Self::Stream { stream, pending } => {
                if !pending.is_empty() {
                    return Err(too_long());
                }
                while let Some(chunk) = stream.next().await {
                    let chunk = chunk?;
                    if !chunk.is_empty() {
                        return Err(too_long());
                    }
                }
            }
        }
        Ok(())
    }
}

struct ListState {
    client: Client,
    bucket: Arc<str>,
    prefix: String,
    start_after: Option<String>,
    continuation: Option<String>,
    buffer: VecDeque<ObjectMeta>,
    done: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::contract;

    async fn test_store() -> Option<S3Store> {
        let bucket = std::env::var("WALGIT_S3_BUCKET").ok()?;
        let mut config = S3Config::new(bucket);
        if let Ok(region) = std::env::var("WALGIT_S3_REGION") {
            config = config.with_region(region);
        }
        if let Ok(endpoint) = std::env::var("WALGIT_S3_ENDPOINT") {
            config = config.with_endpoint(endpoint).with_path_style(true);
        }
        if let (Ok(access), Ok(secret)) = (
            std::env::var("WALGIT_S3_ACCESS_KEY_ID"),
            std::env::var("WALGIT_S3_SECRET_ACCESS_KEY"),
        ) {
            config = config.with_credentials(access, secret, None);
        }
        Some(S3Store::new(config).await.expect("s3 store"))
    }

    #[tokio::test]
    async fn s3_passes_the_contract_when_configured() {
        let Some(store) = test_store().await else {
            eprintln!("WALGIT_S3_BUCKET not set; skipping S3 contract");
            return;
        };
        contract::run(&store, "walgit-contract/").await;
    }

    #[test]
    fn content_range_total_is_parsed() {
        assert_eq!(total_from_content_range("bytes 0-9/20"), Some(20));
        assert_eq!(total_from_content_range("bytes */20"), Some(20));
        assert_eq!(total_from_content_range("nonsense"), None);
    }

    #[tokio::test]
    async fn chunker_reads_in_parts_and_rejects_length_mismatches() {
        let stream: ByteStream = Box::pin(futures::stream::iter(vec![Ok(Bytes::from_static(
            b"abcdef",
        ))]));
        let mut chunker = Chunker::new(PutBody::Stream { len: 6, stream });
        assert_eq!(
            chunker.next_part(4).await.unwrap().unwrap(),
            Bytes::from_static(b"abcd")
        );
        assert_eq!(
            chunker.next_part(4).await.unwrap().unwrap(),
            Bytes::from_static(b"ef")
        );
        assert!(chunker.next_part(4).await.unwrap().is_none());
        chunker.ensure_exhausted(6).await.unwrap();

        let short: ByteStream =
            Box::pin(futures::stream::iter(vec![Ok(Bytes::from_static(b"abc"))]));
        let mut chunker = Chunker::new(PutBody::Stream {
            len: 6,
            stream: short,
        });
        let short = chunker.next_part(6).await.unwrap().unwrap();
        assert_eq!(short.len(), 3);
        assert!(chunker.next_part(6).await.unwrap().is_none());
        // Short bodies are detected by the caller's length accounting, not by
        // the exhaustion probe.
        chunker.ensure_exhausted(6).await.unwrap();

        let long: ByteStream = Box::pin(futures::stream::iter(vec![Ok(Bytes::from_static(
            b"abcdefg",
        ))]));
        let mut chunker = Chunker::new(PutBody::Stream {
            len: 6,
            stream: long,
        });
        let _ = chunker.next_part(6).await.unwrap();
        assert!(chunker.ensure_exhausted(6).await.is_err());
    }

    #[test]
    fn part_size_covers_many_parts() {
        assert_eq!(
            multipart_part_size(DEFAULT_MULTIPART_THRESHOLD, 8).unwrap(),
            DEFAULT_MULTIPART_THRESHOLD as usize
        );
        let huge = MAX_PARTS * MIN_PART_SIZE * 2;
        let size = multipart_part_size(DEFAULT_MULTIPART_THRESHOLD, huge).unwrap() as u64;
        assert!(huge.div_ceil(size) <= MAX_PARTS);
    }
}
