//! Cooperative leases in the object store.
//!
//! A lease is one JSON object at [`crate::config::Layout::lease_key`]. Acquisition is a
//! conditional write: `Create` when nobody holds it, `Update(version)` when the
//! previous holder's TTL has run out. Heartbeat is a CAS extension of the same
//! object, release a versioned delete. No clock is read directly; all times
//! come from a [`Clock`], so tests advance time deterministically.
//!
//! Leases are advisory: a holder that stalls past its TTL loses the lease on
//! the next CAS from a contender. That is the intended failure mode — the TTL
//! bounds the damage, not the holder.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::error::{StoreError, WalError};
use crate::manifest::ManifestCodec;
use crate::store::{ObjectStoreExt as _, PutMode, Version};
use crate::wal::Wal;

/// One held lease, as persisted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lease {
    pub holder: String,
    pub purpose: String,
    pub token: String,
    pub expires_at_unix_ms: u64,
}

impl Lease {
    pub fn is_expired(&self, now_unix_ms: u64) -> bool {
        self.expires_at_unix_ms <= now_unix_ms
    }
}

/// What a caller asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseRequest {
    pub name: String,
    pub holder: String,
    pub purpose: String,
    /// Zero means [`crate::config::WalConfig::lease_ttl`].
    pub ttl: Duration,
    /// How long [`acquire`] waits for a held lease before giving up.
    pub wait: Duration,
}

impl LeaseRequest {
    pub fn new(name: impl Into<String>) -> Self {
        let holder = default_holder();
        Self {
            name: name.into(),
            holder: holder.clone(),
            purpose: String::new(),
            ttl: Duration::ZERO,
            wait: Duration::ZERO,
        }
    }

    pub fn holder(mut self, holder: impl Into<String>) -> Self {
        self.holder = holder.into();
        self
    }

    pub fn purpose(mut self, purpose: impl Into<String>) -> Self {
        self.purpose = purpose.into();
        self
    }

    pub fn ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }

    pub fn wait(mut self, wait: Duration) -> Self {
        self.wait = wait;
        self
    }
}

/// Lease failures that are not plain store errors.
#[derive(Debug, thiserror::Error)]
pub enum LeaseError {
    #[error("lease {name} is held by {holder} until {expires_at_unix_ms}")]
    Held {
        name: String,
        holder: String,
        expires_at_unix_ms: u64,
    },
    #[error("lease {name} is no longer held by us")]
    Lost { name: String },
    #[error("lease {name} is corrupt: {detail}")]
    Corrupt { name: String, detail: String },
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

impl From<LeaseError> for WalError {
    fn from(error: LeaseError) -> Self {
        match error {
            LeaseError::Store(error) => Self::Store(error),
            LeaseError::Json(error) => Self::Json(error),
            other => Self::Other(other.into()),
        }
    }
}

/// Time source for expiry and wait loops.
pub trait Clock: Send + Sync {
    /// Milliseconds since the Unix epoch.
    fn now_unix_ms(&self) -> u64;
}

/// The wall clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_unix_ms(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_millis() as u64)
            .unwrap_or(0)
    }
}

fn default_holder() -> String {
    let host = std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "unknown".to_string());
    format!("{host}/{}", std::process::id())
}

fn new_token() -> String {
    // 128 bits of process-local randomness are enough to tell holders apart.
    let high = rand::random::<u64>();
    let low = rand::random::<u64>();
    format!("{high:016x}{low:016x}")
}

fn ttl_ms(ttl: Duration) -> u64 {
    let millis = ttl.as_millis() as u64;
    millis.max(1)
}

/// An owned lease. Dropping it releases the lease best-effort; call
/// [`LeaseGuard::release`] when the release must be observed.
pub struct LeaseGuard {
    store: crate::store::DynStore,
    key: String,
    holder: String,
    purpose: String,
    token: String,
    name: String,
    ttl: Duration,
    clock: Arc<dyn Clock>,
    state: Mutex<LeaseState>,
    released: AtomicBool,
}

#[derive(Debug, Clone)]
struct LeaseState {
    version: Option<Version>,
    expires_at_unix_ms: u64,
}

impl LeaseGuard {
    fn new(
        store: crate::store::DynStore,
        key: String,
        name: String,
        lease: Lease,
        version: Version,
        ttl: Duration,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            store,
            key,
            holder: lease.holder,
            purpose: lease.purpose,
            token: lease.token,
            name,
            ttl,
            clock,
            state: Mutex::new(LeaseState {
                version: Some(version),
                expires_at_unix_ms: lease.expires_at_unix_ms,
            }),
            released: AtomicBool::new(false),
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn holder(&self) -> &str {
        &self.holder
    }

    pub fn purpose(&self) -> &str {
        &self.purpose
    }

    pub fn token(&self) -> &str {
        &self.token
    }

    /// The lease as held right now.
    pub fn lease(&self) -> Lease {
        let state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        Lease {
            holder: self.holder.clone(),
            purpose: self.purpose.clone(),
            token: self.token.clone(),
            expires_at_unix_ms: state.expires_at_unix_ms,
        }
    }

    pub fn is_released(&self) -> bool {
        self.released.load(Ordering::SeqCst)
    }

    /// Extend the lease by `extend` (or one TTL when zero) with a CAS write.
    pub async fn heartbeat(&self, extend: Duration) -> Result<Lease, LeaseError> {
        if self.is_released() {
            return Err(LeaseError::Lost {
                name: self.name.clone(),
            });
        }
        let version = {
            let state = self.state.lock().unwrap_or_else(|error| error.into_inner());
            state.version.clone()
        };
        let Some(version) = version else {
            return Err(LeaseError::Lost {
                name: self.name.clone(),
            });
        };
        let now = self.clock.now_unix_ms();
        let current = {
            let state = self.state.lock().unwrap_or_else(|error| error.into_inner());
            state.expires_at_unix_ms
        };
        if current <= now {
            self.released.store(true, Ordering::SeqCst);
            return Err(LeaseError::Lost {
                name: self.name.clone(),
            });
        }
        let extend = if extend.is_zero() { self.ttl } else { extend };
        let lease = Lease {
            holder: self.holder.clone(),
            purpose: self.purpose.clone(),
            token: self.token.clone(),
            expires_at_unix_ms: current.saturating_add(ttl_ms(extend)),
        };
        let body = serde_json::to_vec(&lease)?;
        match self
            .store
            .put_bytes(&self.key, body, PutMode::Update(version))
            .await
        {
            Ok(meta) => {
                let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
                state.version = Some(meta.version);
                state.expires_at_unix_ms = lease.expires_at_unix_ms;
                Ok(lease)
            }
            Err(error) if error.is_precondition_failed() => {
                self.released.store(true, Ordering::SeqCst);
                Err(LeaseError::Lost {
                    name: self.name.clone(),
                })
            }
            Err(error) => Err(LeaseError::Store(error)),
        }
    }

    /// Delete the lease only if the object is still the one we hold.
    pub async fn release(&self) -> Result<(), LeaseError> {
        let version = {
            let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
            state.version.take()
        };
        self.released.store(true, Ordering::SeqCst);
        let Some(version) = version else {
            return Ok(());
        };
        match self.store.delete(&self.key, Some(version)).await {
            Ok(()) => Ok(()),
            Err(error) if error.is_not_found() || error.is_precondition_failed() => {
                Err(LeaseError::Lost {
                    name: self.name.clone(),
                })
            }
            Err(error) => Err(LeaseError::Store(error)),
        }
    }

    /// Best-effort release from a synchronous drop.
    fn release_in_background(&self) {
        if self.released.swap(true, Ordering::SeqCst) {
            return;
        }
        let version = {
            let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
            state.version.take()
        };
        let Some(version) = version else {
            return;
        };
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let store = self.store.clone();
        let key = self.key.clone();
        handle.spawn(async move {
            let _ = store.delete(&key, Some(version)).await;
        });
    }
}

impl Drop for LeaseGuard {
    fn drop(&mut self) {
        self.release_in_background();
    }
}

impl std::fmt::Debug for LeaseGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LeaseGuard")
            .field("name", &self.name)
            .field("holder", &self.holder)
            .field("purpose", &self.purpose)
            .field("token", &self.token)
            .field("released", &self.is_released())
            .finish()
    }
}

fn lease_body(lease: &Lease) -> Result<Vec<u8>, LeaseError> {
    Ok(serde_json::to_vec(lease)?)
}

fn now_of(clock: &Arc<dyn Clock>) -> u64 {
    clock.now_unix_ms()
}

fn decode_lease(name: &str, bytes: &[u8]) -> Result<Lease, LeaseError> {
    serde_json::from_slice(bytes).map_err(|error| LeaseError::Corrupt {
        name: name.to_string(),
        detail: error.to_string(),
    })
}

/// Try once. `None` means the lease is held by someone else and unexpired;
/// an expired lease is taken over with a CAS.
pub async fn try_acquire<C: ManifestCodec>(
    wal: &Wal<C>,
    slug: &str,
    request: &LeaseRequest,
) -> Result<Option<LeaseGuard>, LeaseError> {
    try_acquire_with_clock(wal, slug, request, Arc::new(SystemClock)).await
}

/// [`try_acquire`] with an injected clock.
pub async fn try_acquire_with_clock<C: ManifestCodec>(
    wal: &Wal<C>,
    slug: &str,
    request: &LeaseRequest,
    clock: Arc<dyn Clock>,
) -> Result<Option<LeaseGuard>, LeaseError> {
    let key = wal.config().layout.lease_key(slug, &request.name);
    let ttl = if request.ttl.is_zero() {
        wal.config().lease_ttl
    } else {
        request.ttl
    };
    let store = wal.store().clone();

    for _ in 0..3 {
        let next = Lease {
            holder: request.holder.clone(),
            purpose: request.purpose.clone(),
            token: new_token(),
            expires_at_unix_ms: now_of(&clock).saturating_add(ttl_ms(ttl)),
        };
        let body = lease_body(&next)?;
        match store.get_bytes(&key).await? {
            None => match store.put_bytes(&key, body, PutMode::Create).await {
                Ok(meta) => {
                    return Ok(Some(LeaseGuard::new(
                        store,
                        key,
                        request.name.clone(),
                        next,
                        meta.version,
                        ttl,
                        clock,
                    )));
                }
                Err(error) if error.is_precondition_failed() => continue,
                Err(error) => return Err(LeaseError::Store(error)),
            },
            Some((meta, bytes)) => {
                let current = decode_lease(&request.name, &bytes)?;
                if !current.is_expired(now_of(&clock)) {
                    return Ok(None);
                }
                match store
                    .put_bytes(&key, body, PutMode::Update(meta.version))
                    .await
                {
                    Ok(meta) => {
                        return Ok(Some(LeaseGuard::new(
                            store,
                            key,
                            request.name.clone(),
                            next,
                            meta.version,
                            ttl,
                            clock,
                        )));
                    }
                    Err(error) if error.is_precondition_failed() => return Ok(None),
                    Err(error) => return Err(LeaseError::Store(error)),
                }
            }
        }
    }
    Ok(None)
}

/// Wait up to `request.wait` for the lease, polling with jitter.
pub async fn acquire<C: ManifestCodec>(
    wal: &Wal<C>,
    slug: &str,
    request: &LeaseRequest,
) -> Result<Option<LeaseGuard>, LeaseError> {
    acquire_with_clock(wal, slug, request, Arc::new(SystemClock)).await
}

/// [`acquire`] with an injected clock.
pub async fn acquire_with_clock<C: ManifestCodec>(
    wal: &Wal<C>,
    slug: &str,
    request: &LeaseRequest,
    clock: Arc<dyn Clock>,
) -> Result<Option<LeaseGuard>, LeaseError> {
    let started = std::time::Instant::now();
    let mut attempt = 0u32;
    loop {
        if let Some(guard) = try_acquire_with_clock(wal, slug, request, clock.clone()).await? {
            return Ok(Some(guard));
        }
        let elapsed = started.elapsed();
        if elapsed >= request.wait {
            return Ok(None);
        }
        let remaining = request.wait - elapsed;
        let base = 5u64.saturating_mul(1u64 << attempt.min(5));
        let jitter = rand::random::<u64>() % base.max(2);
        let delay = Duration::from_millis(base.saturating_add(jitter)).min(remaining);
        if delay.is_zero() {
            return Ok(None);
        }
        tokio::time::sleep(delay).await;
        attempt = attempt.saturating_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Layout, WalConfig};
    use crate::manifest::RefsCodec;
    use crate::store::MemoryStore;
    use std::sync::atomic::AtomicU64;

    #[derive(Default)]
    struct FakeClock {
        now: AtomicU64,
    }

    impl FakeClock {
        fn new(now: u64) -> Arc<Self> {
            Arc::new(Self {
                now: AtomicU64::new(now),
            })
        }

        fn advance(&self, millis: u64) {
            self.now.fetch_add(millis, Ordering::SeqCst);
        }
    }

    impl Clock for FakeClock {
        fn now_unix_ms(&self) -> u64 {
            self.now.load(Ordering::SeqCst)
        }
    }

    fn wal() -> Wal<RefsCodec> {
        let store = Arc::new(MemoryStore::new());
        let config = Arc::new(WalConfig::new(
            std::env::temp_dir().join("s3-wal-lease"),
            Layout::new("git"),
        ));
        Wal::new(store, config, Arc::new(RefsCodec))
    }

    fn request(name: &str, holder: &str) -> LeaseRequest {
        LeaseRequest::new(name)
            .holder(holder)
            .purpose("test")
            .ttl(Duration::from_secs(30))
    }

    #[tokio::test]
    async fn acquire_expire_heartbeat_release() {
        let wal = wal();
        let clock = FakeClock::new(1_000);
        let request = request("compact", "alice");

        let guard = try_acquire_with_clock(&wal, "demo", &request, clock.clone())
            .await
            .unwrap()
            .expect("free lease");
        assert_eq!(guard.holder(), "alice");
        assert_eq!(guard.lease().expires_at_unix_ms, 1_000 + 30_000);
        assert!(wal
            .store()
            .get_bytes(&wal.config().layout.lease_key("demo", "compact"))
            .await
            .unwrap()
            .is_some());

        // A second holder cannot take an unexpired lease.
        let contender = LeaseRequest::new("compact").holder("bob");
        assert!(
            try_acquire_with_clock(&wal, "demo", &contender, clock.clone())
                .await
                .unwrap()
                .is_none()
        );

        // Heartbeat extends by CAS; the old expiry is replaced.
        let extended = guard.heartbeat(Duration::from_secs(60)).await.unwrap();
        assert_eq!(extended.expires_at_unix_ms, 1_000 + 90_000);

        // Past the extended expiry a contender takes over.
        clock.advance(120_000);
        let taken = try_acquire_with_clock(&wal, "demo", &contender, clock.clone())
            .await
            .unwrap()
            .expect("expired lease is taken over");
        assert_eq!(taken.holder(), "bob");

        // The stale guard's heartbeat is refused.
        assert!(matches!(
            guard.heartbeat(Duration::from_secs(1)).await,
            Err(LeaseError::Lost { .. })
        ));

        // Conditional release by the current holder succeeds.
        taken.release().await.unwrap();
        assert!(wal
            .store()
            .get_bytes(&wal.config().layout.lease_key("demo", "compact"))
            .await
            .unwrap()
            .is_none());
        // Releasing twice is a no-op.
        taken.release().await.unwrap();
    }

    #[tokio::test]
    async fn two_contenders_have_exactly_one_winner() {
        let wal = wal();
        let clock = FakeClock::new(5_000);
        let a = request("gc", "alice");
        let b = request("gc", "bob");
        let (left, right) = tokio::join!(
            try_acquire_with_clock(&wal, "demo", &a, clock.clone()),
            try_acquire_with_clock(&wal, "demo", &b, clock.clone()),
        );
        let left = left.unwrap();
        let right = right.unwrap();
        assert_ne!(left.is_some(), right.is_some());
        let winner = left.or(right).expect("one winner");
        assert!(matches!(winner.holder(), "alice" | "bob"));
    }

    #[tokio::test]
    async fn expired_lease_is_replaced_by_cas() {
        let wal = wal();
        let clock = FakeClock::new(0);
        let first = request("compact", "alice");
        let guard = try_acquire_with_clock(&wal, "demo", &first, clock.clone())
            .await
            .unwrap()
            .expect("first");
        clock.advance(30_001);
        let second = request("compact", "bob");
        let replacement = try_acquire_with_clock(&wal, "demo", &second, clock.clone())
            .await
            .unwrap()
            .expect("replacement");
        assert_eq!(replacement.holder(), "bob");
        // The old guard cannot delete the new holder's lease.
        assert!(matches!(
            guard.release().await,
            Err(LeaseError::Lost { .. })
        ));
        assert_eq!(
            wal.store()
                .get_bytes(&wal.config().layout.lease_key("demo", "compact"))
                .await
                .unwrap()
                .unwrap()
                .1
                .as_ref(),
            serde_json::to_vec(&replacement.lease()).unwrap().as_slice()
        );
    }

    #[tokio::test]
    async fn acquire_without_wait_does_not_poll() {
        let wal = wal();
        let clock = FakeClock::new(0);
        let first = request("compact", "alice");
        let guard = try_acquire_with_clock(&wal, "demo", &first, clock.clone())
            .await
            .unwrap()
            .unwrap();
        let waiting = LeaseRequest::new("compact")
            .holder("bob")
            .ttl(Duration::from_secs(5))
            .wait(Duration::ZERO);
        assert!(acquire_with_clock(&wal, "demo", &waiting, clock.clone())
            .await
            .unwrap()
            .is_none());
        drop(guard);
    }

    #[tokio::test]
    async fn corrupt_lease_reports_typed_error() {
        let wal = wal();
        let key = wal.config().layout.lease_key("demo", "compact");
        wal.store()
            .put_bytes(&key, b"not json".to_vec(), PutMode::Create)
            .await
            .unwrap();
        let error = try_acquire(&wal, "demo", &request("compact", "alice"))
            .await
            .unwrap_err();
        assert!(matches!(error, LeaseError::Corrupt { .. }));
    }
}
