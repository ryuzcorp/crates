//! Transport layers and concurrency ceilings for the smart-HTTP router.
//!
//! [`apply_layers`] adds the request-id, catch-panic, trace, timeout, global
//! concurrency and body-size layers. [`PushLimiter`] is the per-repository
//! semaphore held across policy checks, `git receive-pack` and the WAL write;
//! it is separate from the global request limiter so a large fetch cannot
//! starve pushes and one busy repository cannot starve the others.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Request, State};
use axum::http::{header::HeaderName, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Router;
use dashmap::DashMap;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

use crate::config::Limits;

/// Request header carrying the correlation id (also echoed on responses).
pub const REQUEST_ID_HEADER: HeaderName = HeaderName::from_static("x-request-id");

/// Longest accepted client-supplied request id.
const MAX_REQUEST_ID_LEN: usize = 128;

/// Global request ceiling when the configuration does not name one.
pub const DEFAULT_MAX_CONCURRENT_REQUESTS: usize = 256;

/// Default deadline for one HTTP exchange, including the git subprocess.
/// `PROTOCOL_TIMEOUT` is 300s, so the transport allows a little slack.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(330);

/// The correlation id attached to the request and response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestId(pub String);

impl RequestId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Derived transport configuration.
#[derive(Debug, Clone, Copy)]
pub struct HttpLimits {
    pub body_bytes: usize,
    pub request_timeout: Duration,
    pub max_concurrent_requests: usize,
    pub max_concurrent_pushes: usize,
}

impl HttpLimits {
    pub fn from_limits(limits: &Limits) -> Self {
        let body_bytes = usize::try_from(limits.max_body_bytes)
            .unwrap_or(usize::MAX)
            .max(1);
        let max_concurrent_pushes = limits.max_concurrent_pushes.max(1);
        // Requests are far cheaper than pushes; allow several in-flight
        // requests per push slot so fetches are not serialized by a low push
        // ceiling, and always admit at least a handful.
        let max_concurrent_requests = (max_concurrent_pushes * 32).max(32);
        Self {
            body_bytes,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            max_concurrent_requests,
            max_concurrent_pushes,
        }
    }
}

/// Apply every transport layer. The returned router carries no state.
pub fn apply_layers(router: Router, limits: &Limits) -> Router {
    let config = HttpLimits::from_limits(limits);
    let global = Arc::new(Semaphore::new(config.max_concurrent_requests));
    // Layers are applied innermost first: the request id and panic guard run
    // first so every response (including a 413 from the body limit) is
    // correlated and the process never dies on a handler panic.
    router
        .layer(axum::extract::DefaultBodyLimit::disable())
        .layer(RequestBodyLimitLayer::new(config.body_bytes))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            config.request_timeout,
        ))
        .layer(axum::middleware::from_fn_with_state(
            global,
            limit_in_flight,
        ))
        .layer(TraceLayer::new_for_http())
        .layer(CatchPanicLayer::new())
        .layer(axum::middleware::from_fn(request_id))
}

/// Reuse a client-supplied request id when it is safe, otherwise generate one.
pub async fn request_id(mut request: Request, next: Next) -> Response {
    let supplied = request
        .headers()
        .get(&REQUEST_ID_HEADER)
        .and_then(|value| value.to_str().ok())
        .filter(|value| {
            !value.is_empty()
                && value.len() <= MAX_REQUEST_ID_LEN
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_graphic() && byte != b',')
        })
        .map(str::to_string);
    let id = supplied.unwrap_or_else(generate_request_id);
    if let Ok(value) = HeaderValue::from_str(&id) {
        request.headers_mut().insert(REQUEST_ID_HEADER, value);
    }
    request.extensions_mut().insert(RequestId(id.clone()));
    let mut response = next.run(request).await;
    if let Ok(value) = HeaderValue::from_str(&id) {
        response.headers_mut().insert(REQUEST_ID_HEADER, value);
    }
    response
}

static REQUEST_SEQ: AtomicU64 = AtomicU64::new(1);

fn generate_request_id() -> String {
    let seq = REQUEST_SEQ.fetch_add(1, Ordering::Relaxed);
    let noise = rand::random::<u64>();
    format!("{seq:016x}{noise:016x}")
}

/// Refuse new work once the global ceiling is reached rather than queueing an
/// unbounded number of bodies in memory.
async fn limit_in_flight(
    State(limit): State<Arc<Semaphore>>,
    request: Request,
    next: Next,
) -> Response {
    let Ok(permit) = limit.clone().try_acquire_owned() else {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [(axum::http::header::RETRY_AFTER, "1")],
            "too many concurrent requests",
        )
            .into_response();
    };
    let response = next.run(request).await;
    drop(permit);
    response
}

/// Per-repository push slots plus one global push ceiling.
#[derive(Clone)]
pub struct PushLimiter {
    inner: Arc<PushLimiterInner>,
}

struct PushLimiterInner {
    per_repo: DashMap<String, Arc<Semaphore>>,
    global: Arc<Semaphore>,
    per_repo_limit: usize,
}

impl PushLimiter {
    pub fn new(per_repo: usize) -> Self {
        let per_repo = per_repo.max(1);
        Self {
            inner: Arc::new(PushLimiterInner {
                per_repo: DashMap::new(),
                global: Arc::new(Semaphore::new(per_repo)),
                per_repo_limit: per_repo,
            }),
        }
    }

    pub fn per_repo_limit(&self) -> usize {
        self.inner.per_repo_limit
    }

    /// Wait for a global and a repository slot. The returned permit releases
    /// both on drop.
    pub async fn acquire(&self, slug: &str) -> PushPermit {
        let repo = {
            let entry = self
                .inner
                .per_repo
                .entry(slug.to_string())
                .or_insert_with(|| Arc::new(Semaphore::new(self.inner.per_repo_limit)));
            entry.clone()
        };
        let global = self
            .inner
            .global
            .clone()
            .acquire_owned()
            .await
            .expect("push limiter semaphore is never closed");
        let repo = repo
            .acquire_owned()
            .await
            .expect("push limiter semaphore is never closed");
        PushPermit {
            _global: global,
            _repo: repo,
        }
    }

    /// Number of tracked repositories (diagnostics/tests).
    pub fn tracked_repos(&self) -> usize {
        self.inner.per_repo.len()
    }
}

/// Both push permits; dropping it frees the slots.
#[derive(Debug)]
pub struct PushPermit {
    _global: OwnedSemaphorePermit,
    _repo: OwnedSemaphorePermit,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_are_bounded() {
        let limits = Limits {
            max_body_bytes: 1024,
            max_concurrent_pushes: 0,
            ..Limits::default()
        };
        let derived = HttpLimits::from_limits(&limits);
        assert_eq!(derived.body_bytes, 1024);
        assert_eq!(derived.max_concurrent_pushes, 1);
        assert!(derived.max_concurrent_requests >= 32);
    }

    #[test]
    fn request_ids_are_unique_and_hex() {
        let a = generate_request_id();
        let b = generate_request_id();
        assert_ne!(a, b);
        assert_eq!(a.len(), 32);
        assert!(a.bytes().all(|byte| byte.is_ascii_hexdigit()));
    }

    #[tokio::test]
    async fn per_repo_limit_is_enforced() {
        let limiter = PushLimiter::new(1);
        let first = limiter.acquire("a/b").await;
        let entry = limiter.inner.per_repo.get("a/b").unwrap().clone();
        // The only repository slot is held by `first`.
        assert!(entry.try_acquire().is_err());
        drop(first);
        assert!(entry.try_acquire().is_ok());
    }
}
