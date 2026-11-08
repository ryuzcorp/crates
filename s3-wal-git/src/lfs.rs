//! Git LFS batch API, object transfer and locking.
//!
//! Objects live under [`Layout::lfs_object_key`] and are content addressed by
//! their SHA-256 OID, so a repeated upload is a no-op and a download is a
//! plain object-store GET. The [`LfsStore`] surface is transport agnostic:
//! `src/http/lfs.rs` owns routing, authentication and HTTP status mapping,
//! while this module owns validation and the wire types.
//!
//! Locking follows the LFS locking API. Locks are held in memory and, for
//! [`LfsLocks::new`], persisted to one JSON object per repository with
//! compare-and-swap so multiple processes cannot lose an update.
//!
//! All JSON shapes match the Git LFS specification: batch requests and
//! responses, the `basic` transfer, and lock create/list/verify/unlock.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use futures::StreamExt as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tokio::sync::Mutex;

use crate::config::Layout;
use crate::error::StoreError;
use crate::git::{validate_refname, validate_slug};
use crate::store::{
    collect, ByteStream, DynStore, GetOptions, ObjectMeta, ObjectStore, ObjectStoreExt, PutBody,
    PutMode, PutOptions, Version,
};

/// JSON content type for every LFS API response.
pub const LFS_CONTENT_TYPE: &str = "application/vnd.git-lfs+json";
/// The only transfer adapter this server speaks.
pub const TRANSFER_BASIC: &str = "basic";
/// Length of a SHA-256 OID in hex.
pub const OID_HEX_LEN: usize = 64;
/// Largest lock file this module reads back.
const MAX_LOCK_FILE_BYTES: usize = 16 * 1024 * 1024;
/// Bounded CAS retries for the lock file. No backoff: conflicts are rare and
/// deterministic retries keep tests fast.
const LOCK_CAS_ATTEMPTS: usize = 8;

/// LFS API error. HTTP layers map [`LfsError::status`] and
/// [`LfsError::body`].
#[derive(Debug, thiserror::Error)]
pub enum LfsError {
    #[error("lfs object {oid} not found")]
    NotFound { oid: String },
    #[error("invalid lfs object id: {0}")]
    InvalidOid(String),
    #[error("lfs object {oid} exceeds the {limit} byte limit")]
    TooLarge { oid: String, limit: u64 },
    #[error("lfs body length {actual} disagrees with declared {declared}")]
    LengthMismatch { declared: u64, actual: u64 },
    #[error("lfs object {oid} has content hash {actual}")]
    OidMismatch { oid: String, actual: String },
    #[error("lfs request invalid: {0}")]
    Invalid(String),
    #[error("path {path} is already locked by {owner}")]
    LockConflict { path: String, owner: String },
    #[error("lock {id} not found")]
    LockNotFound { id: String },
    #[error("lock {id} belongs to another owner")]
    LockOwnerMismatch { id: String },
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

impl LfsError {
    /// HTTP status this error maps to.
    pub fn status(&self) -> u16 {
        match self {
            Self::NotFound { .. } | Self::LockNotFound { .. } => 404,
            Self::TooLarge { .. } => 413,
            Self::LockConflict { .. } | Self::LockOwnerMismatch { .. } => 409,
            Self::InvalidOid(_) | Self::Invalid(_) | Self::LengthMismatch { .. } => 422,
            Self::OidMismatch { .. } => 422,
            Self::Store(_) | Self::Json(_) => 500,
        }
    }

    /// Per-object error body for batch responses and lock errors.
    pub fn body(&self) -> LfsErrorBody {
        LfsErrorBody {
            code: self.status(),
            message: self.to_string(),
        }
    }
}

/// LFS batch per-object error body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LfsErrorBody {
    pub code: u16,
    pub message: String,
}

/// Which direction a batch request asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Operation {
    Download,
    Upload,
}

/// `ref` object in batch and lock requests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchRef {
    pub name: String,
}

/// One object reference in a batch request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchObject {
    pub oid: String,
    pub size: u64,
}

/// `POST /objects/batch` request body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchRequest {
    pub operation: Operation,
    #[serde(default)]
    pub transfers: Vec<String>,
    #[serde(default, rename = "ref", skip_serializing_if = "Option::is_none")]
    pub reference: Option<BatchRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash_algo: Option<String>,
    #[serde(default)]
    pub objects: Vec<BatchObject>,
}

impl BatchRequest {
    /// Validate the request against server limits and the LFS spec.
    pub fn validate(&self, limits: &LfsLimits) -> Result<(), LfsError> {
        if !self.transfers.is_empty() && !self.transfers.iter().any(|item| item == TRANSFER_BASIC) {
            return Err(LfsError::Invalid(format!(
                "transfers must include \"{TRANSFER_BASIC}\""
            )));
        }
        if let Some(algo) = &self.hash_algo {
            if !algo.eq_ignore_ascii_case("sha256") {
                return Err(LfsError::Invalid(format!("unsupported hash_algo: {algo}")));
            }
        }
        if let Some(reference) = &self.reference {
            validate_refname(&reference.name)
                .map_err(|error| LfsError::Invalid(format!("ref: {error}")))?;
        }
        if self.objects.len() > limits.max_batch_objects {
            return Err(LfsError::Invalid(format!(
                "batch has {} objects, limit is {}",
                self.objects.len(),
                limits.max_batch_objects
            )));
        }
        for object in &self.objects {
            validate_oid(&object.oid)?;
            if object.size > limits.max_object_bytes {
                return Err(LfsError::TooLarge {
                    oid: object.oid.clone(),
                    limit: limits.max_object_bytes,
                });
            }
        }
        Ok(())
    }
}

/// One action returned by the batch endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchAction {
    pub href: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub header: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}

/// Actions available for one object.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchActions {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub download: Option<BatchAction>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upload: Option<BatchAction>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verify: Option<BatchAction>,
}

/// One object in a batch response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchObjectResponse {
    pub oid: String,
    pub size: u64,
    #[serde(default)]
    pub authenticated: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actions: Option<BatchActions>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<LfsErrorBody>,
}

/// `POST /objects/batch` response body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchResponse {
    pub transfer: String,
    pub objects: Vec<BatchObjectResponse>,
}

/// Ceilings applied to LFS requests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LfsLimits {
    /// Largest single object, in bytes.
    pub max_object_bytes: u64,
    /// Most objects one batch may name.
    pub max_batch_objects: usize,
}

impl Default for LfsLimits {
    fn default() -> Self {
        Self {
            max_object_bytes: 5 * 1024 * 1024 * 1024,
            max_batch_objects: 1000,
        }
    }
}

/// Result of re-hashing an object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyResult {
    pub oid: String,
    pub size: u64,
}

/// True when `oid` is exactly 64 hexadecimal characters.
pub fn is_valid_oid(oid: &str) -> bool {
    oid.len() == OID_HEX_LEN && oid.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn validate_oid(oid: &str) -> Result<(), LfsError> {
    if is_valid_oid(oid) {
        Ok(())
    } else {
        Err(LfsError::InvalidOid(oid.to_string()))
    }
}

fn check_slug(slug: &str) -> Result<(), LfsError> {
    validate_slug(slug).map_err(|error| LfsError::Invalid(format!("repository: {error}")))
}

/// Content-addressed LFS object store over one [`crate::store::ObjectStore`].
#[derive(Clone)]
pub struct LfsStore {
    store: DynStore,
    layout: Layout,
    limits: LfsLimits,
    transfer_base: Option<String>,
    signed_url_ttl: Duration,
}

impl LfsStore {
    pub fn new(store: DynStore, layout: Layout) -> Self {
        Self {
            store,
            layout,
            limits: LfsLimits::default(),
            transfer_base: None,
            signed_url_ttl: Duration::ZERO,
        }
    }

    pub fn with_limits(mut self, limits: LfsLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Public base URL used to build batch action hrefs, for example
    /// `https://git.example.com`. Without it hrefs are root-relative.
    pub fn with_transfer_base(mut self, base: impl Into<String>) -> Self {
        self.transfer_base = Some(base.into());
        self
    }

    /// Ask the backend for presigned download URLs valid for `ttl`. Zero (the
    /// default) disables signed URLs and serves through this server instead.
    pub fn with_signed_url_ttl(mut self, ttl: Duration) -> Self {
        self.signed_url_ttl = ttl;
        self
    }

    pub fn layout(&self) -> &Layout {
        &self.layout
    }

    pub fn limits(&self) -> &LfsLimits {
        &self.limits
    }

    pub fn object_key(&self, slug: &str, oid: &str) -> String {
        self.layout.lfs_object_key(slug, oid)
    }

    /// Answer a batch request. Downloads probe object existence; uploads
    /// return a signed URL when available, otherwise the routed href.
    pub async fn batch(
        &self,
        slug: &str,
        request: BatchRequest,
    ) -> Result<BatchResponse, LfsError> {
        check_slug(slug)?;
        request.validate(&self.limits)?;
        let mut objects = Vec::with_capacity(request.objects.len());
        for object in &request.objects {
            let key = self.object_key(slug, &object.oid);
            match request.operation {
                Operation::Upload => {
                    objects.push(BatchObjectResponse {
                        oid: object.oid.clone(),
                        size: object.size,
                        // Routed hrefs need the caller's git-lfs credentials;
                        // `authenticated: true` suppresses them.
                        authenticated: false,
                        actions: Some(BatchActions {
                            upload: Some(self.upload_action(slug, &object.oid)),
                            ..BatchActions::default()
                        }),
                        error: None,
                    });
                }
                Operation::Download => match self.store.head(&key).await? {
                    Some(meta) => {
                        let action = self.download_action(&key, slug, &object.oid).await?;
                        // A presigned URL carries its own authorization;
                        // a routed href needs the caller's credentials.
                        let authenticated = action.expires_at.is_some();
                        objects.push(BatchObjectResponse {
                            oid: object.oid.clone(),
                            size: meta.size,
                            authenticated,
                            actions: Some(BatchActions {
                                download: Some(action),
                                ..BatchActions::default()
                            }),
                            error: None,
                        });
                    }
                    None => {
                        let error = LfsError::NotFound {
                            oid: object.oid.clone(),
                        };
                        objects.push(BatchObjectResponse {
                            oid: object.oid.clone(),
                            size: object.size,
                            authenticated: false,
                            actions: None,
                            error: Some(error.body()),
                        });
                    }
                },
            }
        }
        crate::metrics::lfs_operation("batch", "ok");
        Ok(BatchResponse {
            transfer: TRANSFER_BASIC.to_string(),
            objects,
        })
    }

    /// Metadata for one object; `Ok(None)` when absent.
    pub async fn head(&self, slug: &str, oid: &str) -> Result<Option<u64>, LfsError> {
        check_slug(slug)?;
        validate_oid(oid)?;
        Ok(self
            .store
            .head(&self.object_key(slug, oid))
            .await?
            .map(|meta| meta.size))
    }

    /// Stream an upload, verifying length and content hash before returning.
    /// A mismatch removes the stored object so the key stays trustworthy.
    pub async fn upload(
        &self,
        slug: &str,
        oid: &str,
        size: u64,
        body: ByteStream,
    ) -> Result<ObjectMeta, LfsError> {
        check_slug(slug)?;
        validate_oid(oid)?;
        self.check_size(oid, size)?;
        let key = self.object_key(slug, oid);
        if let Some(meta) = self.store.head(&key).await? {
            if meta.size == size {
                crate::metrics::lfs_bytes("upload", 0);
                crate::metrics::lfs_operation("upload", "ok");
                return Ok(meta);
            }
            return Err(LfsError::Invalid(format!(
                "object {oid} already exists with size {}",
                meta.size
            )));
        }

        // Download to a private staging file while hashing; only verified
        // bytes are written to the content address. A failed or concurrent
        // upload can therefore never poison the OID.
        let tmp = crate::config::tmp_path(&format!("lfs-{slug}-{oid}"));
        let result = async {
            use tokio::io::AsyncWriteExt as _;

            let mut file = tokio::fs::File::create(&tmp)
                .await
                .map_err(|error| LfsError::Store(error.into()))?;
            let mut hasher = Sha256::new();
            let mut total = 0u64;
            let mut stream = body;
            while let Some(chunk) = stream.next().await {
                let chunk = chunk?;
                total = total.saturating_add(chunk.len() as u64);
                if total > size {
                    return Err(LfsError::LengthMismatch {
                        declared: size,
                        actual: total,
                    });
                }
                hasher.update(&chunk);
                file.write_all(&chunk)
                    .await
                    .map_err(|error| LfsError::Store(error.into()))?;
            }
            file.flush()
                .await
                .map_err(|error| LfsError::Store(error.into()))?;
            file.sync_all()
                .await
                .map_err(|error| LfsError::Store(error.into()))?;
            drop(file);

            if total != size {
                return Err(LfsError::LengthMismatch {
                    declared: size,
                    actual: total,
                });
            }
            let actual_hash = hex::encode(hasher.finalize());
            if !actual_hash.eq_ignore_ascii_case(oid) {
                return Err(LfsError::OidMismatch {
                    oid: oid.to_string(),
                    actual: actual_hash,
                });
            }

            let options = PutOptions {
                mode: PutMode::Create,
                content_type: Some("application/octet-stream"),
                immutable: true,
            };
            match self
                .store
                .put(&key, PutBody::File(tmp.clone()), options)
                .await
            {
                Ok(meta) => Ok(meta),
                Err(StoreError::PreconditionFailed { .. }) => {
                    // Another verified writer won. It wrote under the same
                    // content address, so its bytes are the object.
                    if let Some(meta) = self.store.head(&key).await? {
                        if meta.size == size {
                            return Ok(meta);
                        }
                    }
                    Err(LfsError::Invalid(format!(
                        "concurrent write changed object {oid}"
                    )))
                }
                Err(error) => Err(error.into()),
            }
        }
        .await;
        let _ = tokio::fs::remove_file(&tmp).await;
        let meta = result?;
        crate::metrics::lfs_bytes("upload", size);
        crate::metrics::lfs_operation("upload", "ok");
        Ok(meta)
    }

    /// Upload an in-memory body.
    pub async fn upload_bytes(
        &self,
        slug: &str,
        oid: &str,
        size: u64,
        body: Bytes,
    ) -> Result<ObjectMeta, LfsError> {
        check_slug(slug)?;
        validate_oid(oid)?;
        self.check_size(oid, size)?;
        if body.len() as u64 != size {
            return Err(LfsError::LengthMismatch {
                declared: size,
                actual: body.len() as u64,
            });
        }
        let actual = hex::encode(Sha256::digest(&body));
        if !actual.eq_ignore_ascii_case(oid) {
            return Err(LfsError::OidMismatch {
                oid: oid.to_string(),
                actual,
            });
        }
        let key = self.object_key(slug, oid);
        if let Some(meta) = self.store.head(&key).await? {
            return Ok(meta);
        }
        let options = PutOptions {
            mode: PutMode::Create,
            content_type: Some("application/octet-stream"),
            immutable: true,
        };
        let result = self.store.put(&key, PutBody::Bytes(body), options).await;
        match result {
            Ok(meta) => {
                crate::metrics::lfs_bytes("upload", size);
                crate::metrics::lfs_operation("upload", "ok");
                Ok(meta)
            }
            Err(StoreError::PreconditionFailed { .. }) => {
                self.store
                    .head(&key)
                    .await?
                    .ok_or_else(|| LfsError::NotFound {
                        oid: oid.to_string(),
                    })
            }
            Err(error) => Err(error.into()),
        }
    }

    /// Open an object for streaming download.
    pub async fn download(
        &self,
        slug: &str,
        oid: &str,
    ) -> Result<(ObjectMeta, ByteStream), LfsError> {
        check_slug(slug)?;
        validate_oid(oid)?;
        let key = self.object_key(slug, oid);
        match self.store.get(&key, GetOptions::default()).await {
            Ok(crate::store::GetResult::Object { meta, body }) => {
                crate::metrics::lfs_bytes("download", meta.size);
                crate::metrics::lfs_operation("download", "ok");
                Ok((meta, body))
            }
            Ok(crate::store::GetResult::NotModified { .. }) => {
                Err(LfsError::Invalid("unexpected not-modified".into()))
            }
            Err(StoreError::NotFound { .. }) => Err(LfsError::NotFound {
                oid: oid.to_string(),
            }),
            Err(error) => Err(error.into()),
        }
    }

    /// Read an object fully into memory.
    pub async fn download_bytes(&self, slug: &str, oid: &str) -> Result<Bytes, LfsError> {
        let (_meta, body) = self.download(slug, oid).await?;
        let bytes = collect(body, usize::MAX).await?;
        crate::metrics::lfs_bytes("download", bytes.len() as u64);
        Ok(bytes)
    }

    /// Re-hash a stored object and confirm its OID. Returns the byte size.
    pub async fn verify(&self, slug: &str, oid: &str) -> Result<VerifyResult, LfsError> {
        let (_meta, mut body) = self.download(slug, oid).await?;
        let mut hasher = Sha256::new();
        let mut total = 0u64;
        while let Some(chunk) = body.next().await {
            let chunk = chunk?;
            total += chunk.len() as u64;
            if total > self.limits.max_object_bytes {
                return Err(LfsError::TooLarge {
                    oid: oid.to_string(),
                    limit: self.limits.max_object_bytes,
                });
            }
            hasher.update(&chunk);
        }
        let actual = hex::encode(hasher.finalize());
        if !actual.eq_ignore_ascii_case(oid) {
            return Err(LfsError::OidMismatch {
                oid: oid.to_string(),
                actual,
            });
        }
        crate::metrics::lfs_operation("verify", "ok");
        Ok(VerifyResult {
            oid: oid.to_string(),
            size: total,
        })
    }

    fn check_size(&self, oid: &str, size: u64) -> Result<(), LfsError> {
        if size > self.limits.max_object_bytes {
            return Err(LfsError::TooLarge {
                oid: oid.to_string(),
                limit: self.limits.max_object_bytes,
            });
        }
        Ok(())
    }

    fn routed_href(&self, slug: &str, oid: &str) -> String {
        match &self.transfer_base {
            Some(base) => format!("{}/{slug}/lfs/objects/{oid}", base.trim_end_matches('/')),
            None => format!("/{slug}/lfs/objects/{oid}"),
        }
    }

    fn upload_action(&self, slug: &str, oid: &str) -> BatchAction {
        BatchAction {
            href: self.routed_href(slug, oid),
            header: BTreeMap::new(),
            expires_at: None,
        }
    }

    async fn download_action(
        &self,
        key: &str,
        slug: &str,
        oid: &str,
    ) -> Result<BatchAction, LfsError> {
        if !self.signed_url_ttl.is_zero() {
            if let Some(url) = self.store.signed_get_url(key, self.signed_url_ttl).await? {
                let expires_at = chrono::Utc::now()
                    + chrono::Duration::from_std(self.signed_url_ttl).unwrap_or_default();
                return Ok(BatchAction {
                    href: url,
                    header: BTreeMap::new(),
                    expires_at: Some(expires_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)),
                });
            }
        }
        Ok(BatchAction {
            href: self.routed_href(slug, oid),
            header: BTreeMap::new(),
            expires_at: None,
        })
    }
}

/// A lock owner. Names come from the authenticated principal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockOwner {
    pub name: String,
}

/// One LFS lock.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LfsLock {
    pub id: String,
    pub path: String,
    pub locked_at: String,
    pub owner: LockOwner,
}

/// `POST /locks` request body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockCreateRequest {
    pub path: String,
    #[serde(default, rename = "ref", skip_serializing_if = "Option::is_none")]
    pub reference: Option<BatchRef>,
}

/// `POST /locks` response body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockResponse {
    pub lock: LfsLock,
}

/// `GET /locks` response body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockList {
    pub locks: Vec<LfsLock>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

/// `POST /locks/verify` request body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockVerifyRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
    #[serde(default, rename = "ref", skip_serializing_if = "Option::is_none")]
    pub reference: Option<BatchRef>,
}

/// `POST /locks/verify` response body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockVerifyResponse {
    pub ours: Vec<LfsLock>,
    pub theirs: Vec<LfsLock>,
}

/// `POST /locks/{id}/unlock` request body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnlockRequest {
    #[serde(default)]
    pub force: bool,
}

/// LFS lock error body (`{"message": ...}`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockErrorBody {
    pub message: String,
}

/// One stored lock plus the ref it was created against (not part of the wire
/// lock object, but needed to answer `verify` per ref).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct LockRecord {
    #[serde(flatten)]
    lock: LfsLock,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ref_name: Option<String>,
}

/// Persisted lock file for one repository.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct LockFile {
    version: u8,
    #[serde(default)]
    locks: Vec<LockRecord>,
}

impl Default for LockFile {
    fn default() -> Self {
        Self {
            version: 1,
            locks: Vec::new(),
        }
    }
}

enum LockBackend {
    Memory {
        locks: Mutex<BTreeMap<String, Vec<LockRecord>>>,
    },
    Object {
        store: DynStore,
        layout: Layout,
    },
}

struct LocksInner {
    backend: LockBackend,
    gate: Mutex<()>,
    counter: AtomicU64,
}

/// LFS lock manager: in-memory, or backed by a compare-and-swapped object.
#[derive(Clone)]
pub struct LfsLocks {
    inner: Arc<LocksInner>,
}

impl LfsLocks {
    /// Locks that live only in this process.
    pub fn in_memory() -> Self {
        Self {
            inner: Arc::new(LocksInner {
                backend: LockBackend::Memory {
                    locks: Mutex::new(BTreeMap::new()),
                },
                gate: Mutex::new(()),
                counter: AtomicU64::new(0),
            }),
        }
    }

    /// Locks persisted under `{prefix}/{slug}/lfs/locks.json`.
    pub fn new(store: DynStore, layout: Layout) -> Self {
        Self {
            inner: Arc::new(LocksInner {
                backend: LockBackend::Object { store, layout },
                gate: Mutex::new(()),
                counter: AtomicU64::new(0),
            }),
        }
    }

    /// Key of the persisted lock file. (Callers can build routes from it; a
    /// future `Layout::lfs_lock_key` would make this canonical.)
    pub fn lock_key(layout: &Layout, slug: &str) -> String {
        format!("{}lfs/locks.json", layout.repo_prefix(slug))
    }

    /// Create a lock. Re-locking the same path as the same owner returns the
    /// existing lock; another owner receives [`LfsError::LockConflict`].
    pub async fn create(
        &self,
        slug: &str,
        owner: &str,
        request: &LockCreateRequest,
    ) -> Result<LfsLock, LfsError> {
        check_slug(slug)?;
        validate_owner(owner)?;
        validate_path(&request.path)?;
        if let Some(reference) = &request.reference {
            validate_refname(&reference.name)
                .map_err(|error| LfsError::Invalid(format!("ref: {error}")))?;
        }
        let ref_name = request.reference.as_ref().map(|item| item.name.clone());
        let id = self.next_id(owner, &request.path);
        let lock = LfsLock {
            id: id.clone(),
            path: request.path.clone(),
            locked_at: now_rfc3339(),
            owner: LockOwner {
                name: owner.to_string(),
            },
        };
        let path = request.path.clone();
        self.with_records(slug, |records| {
            if let Some(existing) = records.iter().find(|item| item.lock.path == path) {
                if existing.lock.owner.name == owner {
                    return Ok(existing.lock.clone());
                }
                return Err(LfsError::LockConflict {
                    path: path.clone(),
                    owner: existing.lock.owner.name.clone(),
                });
            }
            records.push(LockRecord {
                lock: lock.clone(),
                ref_name: ref_name.clone(),
            });
            Ok(lock.clone())
        })
        .await
    }

    /// List locks, sorted by id and paginated by `cursor`/`limit`.
    pub async fn list(
        &self,
        slug: &str,
        owner: &str,
        cursor: Option<&str>,
        limit: Option<usize>,
    ) -> Result<LockList, LfsError> {
        check_slug(slug)?;
        validate_owner(owner)?;
        let records = self.read_records(slug).await?;
        let (locks, next_cursor) = paginate(records, cursor, limit);
        Ok(LockList {
            locks: locks.into_iter().map(|record| record.lock).collect(),
            next_cursor,
        })
    }

    /// Split locks into the caller's and everyone else's, optionally per ref.
    pub async fn verify(
        &self,
        slug: &str,
        owner: &str,
        request: &LockVerifyRequest,
    ) -> Result<LockVerifyResponse, LfsError> {
        check_slug(slug)?;
        validate_owner(owner)?;
        if let Some(reference) = &request.reference {
            validate_refname(&reference.name)
                .map_err(|error| LfsError::Invalid(format!("ref: {error}")))?;
        }
        let wanted_ref = request.reference.as_ref().map(|item| item.name.as_str());
        let records: Vec<LockRecord> = self
            .read_records(slug)
            .await?
            .into_iter()
            .filter(|record| match (wanted_ref, record.ref_name.as_deref()) {
                (None, _) => true,
                (Some(_), None) => true,
                (Some(wanted), Some(stored)) => wanted == stored,
            })
            .collect();
        let (records, _) = paginate(records, request.cursor.as_deref(), request.limit);
        let mut ours = Vec::new();
        let mut theirs = Vec::new();
        for record in records {
            if record.lock.owner.name == owner {
                ours.push(record.lock);
            } else {
                theirs.push(record.lock);
            }
        }
        Ok(LockVerifyResponse { ours, theirs })
    }

    /// Delete a lock owned by `owner`.
    pub async fn delete(&self, slug: &str, owner: &str, id: &str) -> Result<LfsLock, LfsError> {
        check_slug(slug)?;
        validate_owner(owner)?;
        let id = id.to_string();
        self.with_records(slug, |records| {
            let index = remove_index(records, &id)?;
            if records[index].lock.owner.name != owner {
                return Err(LfsError::LockOwnerMismatch { id: id.clone() });
            }
            Ok(records.remove(index).lock)
        })
        .await
    }

    /// Unlock a lock. `force` bypasses the owner check (admin route).
    pub async fn unlock(
        &self,
        slug: &str,
        owner: &str,
        id: &str,
        force: bool,
    ) -> Result<LfsLock, LfsError> {
        check_slug(slug)?;
        validate_owner(owner)?;
        let id = id.to_string();
        self.with_records(slug, |records| {
            let index = remove_index(records, &id)?;
            if !force && records[index].lock.owner.name != owner {
                return Err(LfsError::LockOwnerMismatch { id: id.clone() });
            }
            Ok(records.remove(index).lock)
        })
        .await
    }

    fn next_id(&self, owner: &str, path: &str) -> String {
        let counter = self.inner.counter.fetch_add(1, Ordering::Relaxed);
        let mut hasher = Sha256::new();
        hasher.update(owner.as_bytes());
        hasher.update([0]);
        hasher.update(path.as_bytes());
        hasher.update([0]);
        hasher.update(counter.to_le_bytes());
        hasher.update(now_rfc3339().as_bytes());
        hex::encode(&hasher.finalize()[..16])
    }

    async fn read_records(&self, slug: &str) -> Result<Vec<LockRecord>, LfsError> {
        let _gate = self.inner.gate.lock().await;
        match &self.inner.backend {
            LockBackend::Memory { locks } => {
                Ok(locks.lock().await.get(slug).cloned().unwrap_or_default())
            }
            LockBackend::Object { store, layout } => {
                let key = Self::lock_key(layout, slug);
                let (records, _version) = load_lock_file(store.as_ref(), &key).await?;
                Ok(records)
            }
        }
    }

    async fn with_records<T>(
        &self,
        slug: &str,
        mut change: impl FnMut(&mut Vec<LockRecord>) -> Result<T, LfsError>,
    ) -> Result<T, LfsError> {
        let _gate = self.inner.gate.lock().await;
        match &self.inner.backend {
            LockBackend::Memory { locks } => {
                let mut map = locks.lock().await;
                let records = map.entry(slug.to_string()).or_default();
                change(records)
            }
            LockBackend::Object { store, layout } => {
                let key = Self::lock_key(layout, slug);
                for _ in 0..LOCK_CAS_ATTEMPTS {
                    let (mut records, version) = load_lock_file(store.as_ref(), &key).await?;
                    let value = change(&mut records)?;
                    let file = LockFile {
                        version: 1,
                        locks: records,
                    };
                    let bytes = serde_json::to_vec(&file)?;
                    let mode = match &version {
                        Some(version) => PutMode::Update(version.clone()),
                        None => PutMode::Create,
                    };
                    let options = PutOptions {
                        mode,
                        content_type: Some("application/json"),
                        ..PutOptions::default()
                    };
                    let result = store
                        .as_ref()
                        .put(&key, PutBody::Bytes(bytes.into()), options)
                        .await;
                    match result {
                        Ok(_) => return Ok(value),
                        Err(error) if error.is_precondition_failed() => continue,
                        Err(error) => return Err(error.into()),
                    }
                }
                Err(LfsError::Invalid(format!(
                    "lock file for {slug} changed concurrently"
                )))
            }
        }
    }
}

async fn load_lock_file(
    store: &dyn ObjectStore,
    key: &str,
) -> Result<(Vec<LockRecord>, Option<Version>), LfsError> {
    match store.get_bytes(key).await? {
        Some((meta, bytes)) => {
            if bytes.len() > MAX_LOCK_FILE_BYTES {
                return Err(LfsError::Invalid("lock file is too large".into()));
            }
            let file: LockFile = if bytes.is_empty() {
                LockFile::default()
            } else {
                serde_json::from_slice(&bytes)?
            };
            Ok((file.locks, Some(meta.version)))
        }
        None => Ok((Vec::new(), None)),
    }
}

fn remove_index(records: &[LockRecord], id: &str) -> Result<usize, LfsError> {
    records
        .iter()
        .position(|record| record.lock.id == id)
        .ok_or_else(|| LfsError::LockNotFound { id: id.to_string() })
}

fn paginate(
    mut records: Vec<LockRecord>,
    cursor: Option<&str>,
    limit: Option<usize>,
) -> (Vec<LockRecord>, Option<String>) {
    records.sort_by(|a, b| a.lock.id.cmp(&b.lock.id));
    if let Some(cursor) = cursor {
        records.retain(|record| record.lock.id.as_str() > cursor);
    }
    let limit = limit.unwrap_or(100).clamp(1, 1000);
    if records.len() <= limit {
        return (records, None);
    }
    let next = records[limit - 1].lock.id.clone();
    records.truncate(limit);
    (records, Some(next))
}

/// Validate a lock owner principal.
pub fn validate_owner(owner: &str) -> Result<(), LfsError> {
    let trimmed = owner.trim();
    if trimmed.is_empty() {
        return Err(LfsError::Invalid("lock owner is empty".into()));
    }
    if owner.len() > 255 {
        return Err(LfsError::Invalid("lock owner is too long".into()));
    }
    if owner.chars().any(char::is_control) {
        return Err(LfsError::Invalid(
            "lock owner contains control characters".into(),
        ));
    }
    Ok(())
}

/// Validate a repository-relative lock path.
pub fn validate_path(path: &str) -> Result<(), LfsError> {
    if path.is_empty() || path.len() > 4096 {
        return Err(LfsError::Invalid("lock path length is invalid".into()));
    }
    if path.starts_with('/') || path.contains('\\') || path.contains('\0') {
        return Err(LfsError::Invalid(format!("lock path is invalid: {path}")));
    }
    if path.chars().any(char::is_control) {
        return Err(LfsError::Invalid(
            "lock path contains control characters".into(),
        ));
    }
    if path
        .split('/')
        .any(|segment| segment.is_empty() || segment == "." || segment == "..")
    {
        return Err(LfsError::Invalid(format!(
            "lock path is not normalized: {path}"
        )));
    }
    Ok(())
}

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// Convenience alias for the request type HTTP layers deserialize.
pub type LfsBatchRequest = BatchRequest;
/// Convenience alias for the response type HTTP layers serialize.
pub type LfsBatchResponse = BatchResponse;
/// Convenience alias for a wire lock.
pub type LfsLockResponse = LockResponse;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::MemoryStore;

    fn store() -> DynStore {
        Arc::new(MemoryStore::new())
    }

    fn layout() -> Layout {
        Layout::default()
    }

    fn oid_of(bytes: &[u8]) -> String {
        hex::encode(Sha256::digest(bytes))
    }

    fn stream(bytes: &'static [u8]) -> ByteStream {
        Box::pin(futures::stream::iter(vec![Ok(Bytes::from_static(bytes))]))
    }

    #[test]
    fn oid_validation_is_strict() {
        assert!(is_valid_oid(&"a".repeat(64)));
        assert!(is_valid_oid(&"A".repeat(64)));
        assert!(!is_valid_oid(&"a".repeat(63)));
        assert!(!is_valid_oid(&"g".repeat(64)));
        assert!(!is_valid_oid(""));
    }

    #[test]
    fn batch_request_validation() {
        let limits = LfsLimits {
            max_object_bytes: 1024,
            max_batch_objects: 2,
        };
        let good = BatchRequest {
            operation: Operation::Download,
            transfers: vec![TRANSFER_BASIC.to_string()],
            reference: Some(BatchRef {
                name: "refs/heads/main".into(),
            }),
            hash_algo: Some("sha256".into()),
            objects: vec![BatchObject {
                oid: "a".repeat(64),
                size: 10,
            }],
        };
        good.validate(&limits).unwrap();

        let mut bad = good.clone();
        bad.operation = Operation::Upload;
        bad.transfers = vec!["ssh".into()];
        assert!(matches!(bad.validate(&limits), Err(LfsError::Invalid(_))));

        let mut bad = good.clone();
        bad.hash_algo = Some("sha1".into());
        assert!(matches!(bad.validate(&limits), Err(LfsError::Invalid(_))));

        let mut bad = good.clone();
        bad.objects[0].oid = "xyz".into();
        assert!(matches!(
            bad.validate(&limits),
            Err(LfsError::InvalidOid(_))
        ));

        let mut bad = good.clone();
        bad.objects[0].size = 2048;
        assert!(matches!(
            bad.validate(&limits),
            Err(LfsError::TooLarge { .. })
        ));

        let mut bad = good.clone();
        bad.objects.push(bad.objects[0].clone());
        bad.objects.push(bad.objects[0].clone());
        assert!(matches!(bad.validate(&limits), Err(LfsError::Invalid(_))));

        let mut bad = good;
        bad.reference = Some(BatchRef {
            name: "not-a-ref".into(),
        });
        assert!(matches!(bad.validate(&limits), Err(LfsError::Invalid(_))));
    }

    #[test]
    fn operation_and_wire_names_match_the_spec() {
        let value: BatchRequest = serde_json::from_str(
            r#"{"operation":"upload","transfers":["basic"],"ref":{"name":"refs/heads/main"},"objects":[{"oid":"0000000000000000000000000000000000000000000000000000000000000000","size":0}]}"#,
        )
        .unwrap();
        assert_eq!(value.operation, Operation::Upload);
        assert_eq!(value.reference.unwrap().name, "refs/heads/main");
        assert!(
            serde_json::from_str::<BatchRequest>(r#"{"operation":"follow","objects":[]}"#).is_err()
        );
        let body = serde_json::to_value(BatchResponse {
            transfer: TRANSFER_BASIC.into(),
            objects: vec![BatchObjectResponse {
                oid: "a".repeat(64),
                size: 1,
                authenticated: true,
                actions: None,
                error: Some(LfsErrorBody {
                    code: 404,
                    message: "gone".into(),
                }),
            }],
        })
        .unwrap();
        assert_eq!(body["transfer"], "basic");
        assert_eq!(body["objects"][0]["error"]["code"], 404);
    }

    #[tokio::test]
    async fn upload_download_verify_roundtrip() {
        let store = store();
        let lfs = LfsStore::new(store, layout());
        let bytes = b"hello lfs";
        let oid = oid_of(bytes);
        let meta = lfs
            .upload("acme/demo", &oid, bytes.len() as u64, stream(bytes))
            .await
            .unwrap();
        assert_eq!(meta.size, bytes.len() as u64);
        assert_eq!(lfs.head("acme/demo", &oid).await.unwrap(), Some(9));
        let downloaded = lfs.download_bytes("acme/demo", &oid).await.unwrap();
        assert_eq!(&downloaded[..], bytes);
        let verified = lfs.verify("acme/demo", &oid).await.unwrap();
        assert_eq!(verified.size, bytes.len() as u64);
        assert_eq!(lfs.head("acme/demo", &"b".repeat(64)).await.unwrap(), None);
        assert!(matches!(
            lfs.download("acme/demo", &"b".repeat(64)).await,
            Err(LfsError::NotFound { .. })
        ));
    }

    #[tokio::test]
    async fn upload_rejects_wrong_hash_and_cleans_up() {
        let store = store();
        let lfs = LfsStore::new(store.clone(), layout());
        let bytes = b"payload";
        let claimed = "c".repeat(64);
        let error = lfs
            .upload("acme/demo", &claimed, bytes.len() as u64, stream(bytes))
            .await
            .unwrap_err();
        assert!(matches!(error, LfsError::OidMismatch { .. }));
        assert_eq!(lfs.head("acme/demo", &claimed).await.unwrap(), None);
        assert!(store
            .head(&lfs.object_key("acme/demo", &claimed))
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn upload_rejects_length_mismatch() {
        let lfs = LfsStore::new(store(), layout());
        let bytes = b"abc";
        let oid = oid_of(bytes);
        let error = lfs
            .upload("acme/demo", &oid, 100, stream(bytes))
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            LfsError::LengthMismatch {
                declared: 100,
                actual: 3
            }
        ));
    }

    #[tokio::test]
    async fn upload_is_idempotent() {
        let lfs = LfsStore::new(store(), layout());
        let bytes = b"same";
        let oid = oid_of(bytes);
        lfs.upload("acme/demo", &oid, 4, stream(bytes))
            .await
            .unwrap();
        let again = lfs
            .upload("acme/demo", &oid, 4, stream(bytes))
            .await
            .unwrap();
        assert_eq!(again.size, 4);
        assert_eq!(lfs.verify("acme/demo", &oid).await.unwrap().size, 4);
    }

    #[tokio::test]
    async fn upload_bytes_roundtrip() {
        let lfs = LfsStore::new(store(), layout());
        let bytes = Bytes::from_static(b"inline");
        let oid = oid_of(&bytes);
        lfs.upload_bytes("acme/demo", &oid, bytes.len() as u64, bytes.clone())
            .await
            .unwrap();
        assert_eq!(lfs.download_bytes("acme/demo", &oid).await.unwrap(), bytes);
        assert!(matches!(
            lfs.upload_bytes("acme/demo", &oid, 2, bytes).await,
            Err(LfsError::LengthMismatch { .. })
        ));
    }

    #[tokio::test]
    async fn batch_download_reports_missing_and_present_objects() {
        let lfs = LfsStore::new(store(), layout());
        let bytes = b"batch";
        let oid = oid_of(bytes);
        lfs.upload("acme/demo", &oid, 5, stream(bytes))
            .await
            .unwrap();
        let missing = "d".repeat(64);
        let response = lfs
            .batch(
                "acme/demo",
                BatchRequest {
                    operation: Operation::Download,
                    transfers: vec![TRANSFER_BASIC.into()],
                    reference: None,
                    hash_algo: None,
                    objects: vec![
                        BatchObject {
                            oid: oid.clone(),
                            size: 5,
                        },
                        BatchObject {
                            oid: missing.clone(),
                            size: 9,
                        },
                    ],
                },
            )
            .await
            .unwrap();
        assert_eq!(response.transfer, "basic");
        assert_eq!(response.objects.len(), 2);
        assert!(response.objects[0]
            .actions
            .as_ref()
            .unwrap()
            .download
            .is_some());
        let error = response.objects[1].error.as_ref().unwrap();
        assert_eq!(error.code, 404);
        assert_eq!(response.objects[1].oid, missing);
    }

    #[tokio::test]
    async fn batch_upload_returns_actions() {
        let lfs = LfsStore::new(store(), layout()).with_transfer_base("https://git.test");
        let response = lfs
            .batch(
                "acme/demo",
                BatchRequest {
                    operation: Operation::Upload,
                    transfers: vec![],
                    reference: None,
                    hash_algo: None,
                    objects: vec![BatchObject {
                        oid: "e".repeat(64),
                        size: 12,
                    }],
                },
            )
            .await
            .unwrap();
        let actions = response.objects[0].actions.as_ref().unwrap();
        let upload = actions.upload.as_ref().unwrap();
        assert!(upload
            .href
            .starts_with("https://git.test/acme/demo/lfs/objects/"));
        assert!(actions.verify.is_none());
    }

    #[tokio::test]
    async fn signed_urls_are_used_when_enabled() {
        let lfs = LfsStore::new(store(), layout()).with_signed_url_ttl(Duration::from_secs(60));
        let bytes = b"signed";
        let oid = oid_of(bytes);
        lfs.upload("acme/demo", &oid, 6, stream(bytes))
            .await
            .unwrap();
        let response = lfs
            .batch(
                "acme/demo",
                BatchRequest {
                    operation: Operation::Download,
                    transfers: vec![TRANSFER_BASIC.into()],
                    reference: None,
                    hash_algo: None,
                    objects: vec![BatchObject {
                        oid: oid.clone(),
                        size: 6,
                    }],
                },
            )
            .await
            .unwrap();
        let action = response.objects[0]
            .actions
            .as_ref()
            .unwrap()
            .download
            .as_ref()
            .unwrap();
        assert!(action.href.starts_with("memory://"), "{}", action.href);
        assert!(action.expires_at.is_some());
        assert!(response.objects[0].authenticated);
    }

    fn create_request(path: &str) -> LockCreateRequest {
        LockCreateRequest {
            path: path.to_string(),
            reference: Some(BatchRef {
                name: "refs/heads/main".into(),
            }),
        }
    }

    #[tokio::test]
    async fn lock_lifecycle_in_memory() {
        let locks = LfsLocks::in_memory();
        let alice = locks
            .create("acme/demo", "alice", &create_request("src/main.rs"))
            .await
            .unwrap();
        assert_eq!(alice.path, "src/main.rs");
        assert_eq!(alice.owner.name, "alice");
        assert!(!alice.locked_at.is_empty());

        // Same owner, same path: idempotent.
        let again = locks
            .create("acme/demo", "alice", &create_request("src/main.rs"))
            .await
            .unwrap();
        assert_eq!(again.id, alice.id);

        // Another owner: conflict.
        let error = locks
            .create("acme/demo", "bob", &create_request("src/main.rs"))
            .await
            .unwrap_err();
        assert!(matches!(error, LfsError::LockConflict { .. }));

        let bob = locks
            .create("acme/demo", "bob", &create_request("docs/readme.md"))
            .await
            .unwrap();
        let listed = locks.list("acme/demo", "alice", None, None).await.unwrap();
        assert_eq!(listed.locks.len(), 2);
        assert!(listed.next_cursor.is_none());

        let page = locks
            .list("acme/demo", "alice", None, Some(1))
            .await
            .unwrap();
        assert_eq!(page.locks.len(), 1);
        let next = page.next_cursor.clone().expect("more locks");
        let page = locks
            .list("acme/demo", "alice", Some(&next), Some(1))
            .await
            .unwrap();
        assert_eq!(page.locks.len(), 1);
        assert!(page.next_cursor.is_none());

        let verified = locks
            .verify(
                "acme/demo",
                "alice",
                &LockVerifyRequest {
                    cursor: None,
                    limit: None,
                    reference: Some(BatchRef {
                        name: "refs/heads/main".into(),
                    }),
                },
            )
            .await
            .unwrap();
        assert_eq!(verified.ours.len(), 1);
        assert_eq!(verified.ours[0].id, alice.id);
        assert_eq!(verified.theirs.len(), 1);
        assert_eq!(verified.theirs[0].id, bob.id);

        assert!(matches!(
            locks.delete("acme/demo", "bob", &alice.id).await,
            Err(LfsError::LockOwnerMismatch { .. })
        ));
        let removed = locks.delete("acme/demo", "alice", &alice.id).await.unwrap();
        assert_eq!(removed.id, alice.id);
        assert!(matches!(
            locks.delete("acme/demo", "alice", &alice.id).await,
            Err(LfsError::LockNotFound { .. })
        ));
        let forced = locks
            .unlock("acme/demo", "alice", &bob.id, true)
            .await
            .unwrap();
        assert_eq!(forced.id, bob.id);
        assert!(locks
            .list("acme/demo", "alice", None, None)
            .await
            .unwrap()
            .locks
            .is_empty());
    }

    #[tokio::test]
    async fn lock_file_persists_across_instances() {
        let store = store();
        let first = LfsLocks::new(store.clone(), layout());
        let lock = first
            .create("acme/demo", "alice", &create_request("src/lib.rs"))
            .await
            .unwrap();
        let second = LfsLocks::new(store.clone(), layout());
        let listed = second.list("acme/demo", "alice", None, None).await.unwrap();
        assert_eq!(listed.locks, vec![lock.clone()]);
        let removed = second
            .unlock("acme/demo", "bob", &lock.id, false)
            .await
            .unwrap_err();
        assert!(matches!(removed, LfsError::LockOwnerMismatch { .. }));
        second
            .unlock("acme/demo", "bob", &lock.id, true)
            .await
            .unwrap();
        let third = LfsLocks::new(store, layout());
        assert!(third
            .list("acme/demo", "alice", None, None)
            .await
            .unwrap()
            .locks
            .is_empty());
    }

    #[tokio::test]
    async fn lock_validation_rejects_bad_input() {
        let locks = LfsLocks::in_memory();
        assert!(matches!(
            locks.create("acme/demo", "", &create_request("a")).await,
            Err(LfsError::Invalid(_))
        ));
        for path in ["", "/abs", "../escape", "a//b", "trail/"] {
            assert!(
                matches!(
                    locks
                        .create("acme/demo", "alice", &create_request(path))
                        .await,
                    Err(LfsError::Invalid(_))
                ),
                "{path}"
            );
        }
        let mut request = create_request("ok.txt");
        request.reference = Some(BatchRef {
            name: "nope".into(),
        });
        assert!(matches!(
            locks.create("acme/demo", "alice", &request).await,
            Err(LfsError::Invalid(_))
        ));
    }

    #[tokio::test]
    async fn lock_file_is_a_single_key_and_cas_safe() {
        let store = store();
        let locks = LfsLocks::new(store.clone(), layout());
        locks
            .create("acme/demo", "alice", &create_request("a.txt"))
            .await
            .unwrap();
        let key = LfsLocks::lock_key(&layout(), "acme/demo");
        assert!(store.head(&key).await.unwrap().is_some());
        // A stale external write is detected by CAS: mutate the key behind the
        // manager's back, then create another lock via a fresh manager.
        store
            .put(
                &key,
                b"{\"version\":1,\"locks\":[]}".to_vec().into(),
                PutMode::Overwrite.into(),
            )
            .await
            .unwrap();
        locks
            .create("acme/demo", "bob", &create_request("b.txt"))
            .await
            .unwrap();
        let raw = store.get_bytes(&key).await.unwrap().unwrap().1;
        let file: LockFile = serde_json::from_slice(&raw).unwrap();
        assert_eq!(file.locks.len(), 1);
        assert_eq!(file.locks[0].lock.path, "b.txt");
    }

    #[test]
    fn locks_serialize_as_the_spec_shapes() {
        let lock = LfsLock {
            id: "1".into(),
            path: "a.txt".into(),
            locked_at: "2026-01-01T00:00:00Z".into(),
            owner: LockOwner {
                name: "alice".into(),
            },
        };
        let value = serde_json::to_value(LockResponse { lock }).unwrap();
        assert_eq!(value["lock"]["path"], "a.txt");
        assert_eq!(value["lock"]["owner"]["name"], "alice");
        let list = serde_json::to_value(LockList {
            locks: vec![],
            next_cursor: None,
        })
        .unwrap();
        assert_eq!(list, serde_json::json!({"locks": []}));
        let request: LockCreateRequest =
            serde_json::from_str(r#"{"path":"a.txt","ref":{"name":"refs/heads/main"}}"#).unwrap();
        assert_eq!(request.reference.unwrap().name, "refs/heads/main");
        let verify: LockVerifyRequest =
            serde_json::from_str(r#"{"cursor":"abc","limit":10,"ref":{"name":"refs/heads/main"}}"#)
                .unwrap();
        assert_eq!(verify.limit, Some(10));
    }
}
