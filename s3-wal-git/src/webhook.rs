//! Webhook delivery: HMAC-signed JSON posts with deterministic delivery ids.
//!
//! A [`WebhookSink`] is the transport seam. [`HttpWebhook`] is the production
//! implementation (feature `webhook-client`); tests use an in-memory sink.
//!
//! Headers on every delivery:
//!
//! - `X-Walgit-Signature: sha256=<hex hmac>` — HMAC-SHA256 of the exact body
//!   bytes keyed with the endpoint secret.
//! - `X-Walgit-Delivery: <hex>` — SHA-256 of the body; stable for identical
//!   payloads so receivers can deduplicate retries.
//! - `Content-Type: application/json`.
//!
//! The sink contract is narrow on purpose: [`WebhookSink::post`] returns `Ok`
//! only for a 2xx response. Callers advance durable cursors solely on `Ok`.

use std::fmt;

use hmac::{Hmac, KeyInit as _, Mac as _};
use sha2::{Digest as _, Sha256};

/// Signature header name.
pub const SIGNATURE_HEADER: &str = "X-Walgit-Signature";
/// Delivery-id header name.
pub const DELIVERY_HEADER: &str = "X-Walgit-Delivery";
/// Prefix of the signature header value.
pub const SIGNATURE_PREFIX: &str = "sha256=";
/// Timeout applied to every HTTP delivery.
pub const DEFAULT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

type HmacSha256 = Hmac<Sha256>;

/// Webhook transport failure.
#[derive(Debug, thiserror::Error)]
pub enum WebhookError {
    /// The request could not be built or sent.
    #[error("webhook transport failed: {0}")]
    Transport(String),
    /// The endpoint answered with a non-2xx status. The cursor must not move.
    #[error("webhook endpoint returned {status}")]
    Status { status: u16, body: String },
    /// The webhook URL or secret is unusable.
    #[error("webhook configuration invalid: {0}")]
    Invalid(String),
}

impl WebhookError {
    pub fn status(status: u16, body: impl Into<String>) -> Self {
        Self::Status {
            status,
            body: body.into(),
        }
    }

    pub fn transport(error: impl fmt::Display) -> Self {
        Self::Transport(error.to_string())
    }
}

/// Delivery transport. Implementations must not retry internally: a retry is
/// the caller's decision because it owns the cursor.
#[async_trait::async_trait]
pub trait WebhookSink: Send + Sync {
    /// POST `body` to `url`, signing it with `secret`. `Ok` means 2xx.
    async fn post(&self, url: &str, secret: &[u8], body: &[u8]) -> Result<(), WebhookError>;
}

/// `sha256=<hex>` HMAC of `body`, the value of [`SIGNATURE_HEADER`].
///
/// Any secret length is accepted by HMAC; an empty secret still produces a
/// valid MAC and is the caller's choice.
pub fn sign(secret: &[u8], body: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(body);
    let tag = mac.finalize().into_bytes();
    format!("{SIGNATURE_PREFIX}{}", hex::encode(tag))
}

/// Hex SHA-256 of `body`, the value of [`DELIVERY_HEADER`].
pub fn delivery_id(body: &[u8]) -> String {
    hex::encode(Sha256::digest(body))
}

/// Constant-time signature check against a [`SIGNATURE_HEADER`] value.
pub fn verify_signature(secret: &[u8], body: &[u8], signature: &str) -> bool {
    let Some(encoded) = signature.strip_prefix(SIGNATURE_PREFIX) else {
        return false;
    };
    let Ok(expected) = hex::decode(encoded) else {
        return false;
    };
    let Ok(mut mac) = HmacSha256::new_from_slice(secret) else {
        return false;
    };
    mac.update(body);
    mac.verify_slice(&expected).is_ok()
}

/// Production HTTP sink. Requires feature `webhook-client`.
#[cfg(feature = "webhook-client")]
#[derive(Clone, Debug)]
pub struct HttpWebhook {
    client: reqwest::Client,
}

#[cfg(feature = "webhook-client")]
impl HttpWebhook {
    /// Build a client with the default 10-second timeout.
    pub fn new() -> Result<Self, WebhookError> {
        Self::with_timeout(DEFAULT_TIMEOUT)
    }

    /// Build a client with an explicit request timeout.
    pub fn with_timeout(timeout: std::time::Duration) -> Result<Self, WebhookError> {
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .map_err(WebhookError::transport)?;
        Ok(Self { client })
    }

    /// The underlying client, for tests that preconfigure resolvers/proxies.
    pub fn client(&self) -> &reqwest::Client {
        &self.client
    }
}

#[cfg(feature = "webhook-client")]
impl Default for HttpWebhook {
    fn default() -> Self {
        Self::new().expect("default reqwest client")
    }
}

#[cfg(feature = "webhook-client")]
#[async_trait::async_trait]
impl WebhookSink for HttpWebhook {
    async fn post(&self, url: &str, secret: &[u8], body: &[u8]) -> Result<(), WebhookError> {
        if url.is_empty() {
            return Err(WebhookError::Invalid("empty webhook url".into()));
        }
        let response = self
            .client
            .post(url)
            .header(SIGNATURE_HEADER, sign(secret, body))
            .header(DELIVERY_HEADER, delivery_id(body))
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body.to_vec())
            .send()
            .await
            .map_err(WebhookError::transport)?;
        let status = response.status();
        if status.is_success() {
            return Ok(());
        }
        let text = response.text().await.unwrap_or_default();
        Err(WebhookError::status(status.as_u16(), text))
    }
}

/// In-memory sink for tests: records every delivery and can fail on demand.
#[cfg(test)]
pub(crate) mod testing {
    use std::sync::{Arc, Mutex, MutexGuard};

    use super::{sign, WebhookError, WebhookSink};

    /// One recorded delivery.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Delivery {
        pub url: String,
        pub secret: Vec<u8>,
        pub body: Vec<u8>,
        pub signature: String,
    }

    /// Records posts; optionally answers with a fixed failure status.
    #[derive(Clone, Default)]
    pub struct MemorySink {
        inner: Arc<Mutex<State>>,
    }

    #[derive(Default)]
    struct State {
        deliveries: Vec<Delivery>,
        failure: Option<u16>,
    }

    fn lock(state: &Mutex<State>) -> MutexGuard<'_, State> {
        state.lock().unwrap_or_else(|error| error.into_inner())
    }

    impl MemorySink {
        pub fn new() -> Self {
            Self::default()
        }

        /// Reject every subsequent post with `status` (until cleared).
        pub fn fail_with(&self, status: u16) {
            lock(&self.inner).failure = Some(status);
        }

        pub fn clear_failure(&self) {
            lock(&self.inner).failure = None;
        }

        pub fn deliveries(&self) -> Vec<Delivery> {
            lock(&self.inner).deliveries.clone()
        }

        pub fn len(&self) -> usize {
            lock(&self.inner).deliveries.len()
        }
    }

    #[async_trait::async_trait]
    impl WebhookSink for MemorySink {
        async fn post(&self, url: &str, secret: &[u8], body: &[u8]) -> Result<(), WebhookError> {
            let mut state = lock(&self.inner);
            if let Some(status) = state.failure {
                return Err(WebhookError::status(status, "injected failure"));
            }
            state.deliveries.push(Delivery {
                url: url.to_string(),
                secret: secret.to_vec(),
                body: body.to_vec(),
                signature: sign(secret, body),
            });
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::MemorySink;
    use super::*;

    #[test]
    fn rfc4231_case_2_vector() {
        // RFC 4231 §4.2: key "Jefe", data "what do ya want for nothing?".
        let secret = b"Jefe";
        let body = b"what do ya want for nothing?";
        let expected = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843";
        assert_eq!(sign(secret, body), format!("sha256={expected}"));
        assert!(verify_signature(
            secret,
            body,
            &format!("sha256={expected}")
        ));
        assert!(!verify_signature(
            secret,
            b"tampered",
            &format!("sha256={expected}")
        ));
        assert!(!verify_signature(
            b"other",
            body,
            &format!("sha256={expected}")
        ));
    }

    #[test]
    fn signature_parsing_rejects_malformed_values() {
        assert!(!verify_signature(b"k", b"b", ""));
        assert!(!verify_signature(b"k", b"b", "sha1=abcd"));
        assert!(!verify_signature(b"k", b"b", "sha256=zz"));
        let good = sign(b"k", b"b");
        assert!(verify_signature(b"k", b"b", &good));
    }

    #[test]
    fn delivery_id_is_stable_and_content_addressed() {
        assert_eq!(delivery_id(b"payload"), delivery_id(b"payload"));
        assert_ne!(delivery_id(b"payload"), delivery_id(b"payload2"));
        assert_eq!(delivery_id(b"payload").len(), 64);
    }

    #[tokio::test]
    async fn memory_sink_records_signed_deliveries() {
        let sink = MemorySink::new();
        sink.post("https://example.test/hook", b"secret", b"{\"a\":1}")
            .await
            .unwrap();
        let deliveries = sink.deliveries();
        assert_eq!(deliveries.len(), 1);
        assert_eq!(deliveries[0].url, "https://example.test/hook");
        assert_eq!(deliveries[0].signature, sign(b"secret", b"{\"a\":1}"));
        assert!(verify_signature(
            b"secret",
            b"{\"a\":1}",
            &deliveries[0].signature
        ));
    }

    #[tokio::test]
    async fn non_2xx_is_an_error_the_caller_can_retry() {
        let sink = MemorySink::new();
        sink.fail_with(503);
        let error = sink
            .post("https://example.test/hook", b"", b"body")
            .await
            .unwrap_err();
        assert!(matches!(error, WebhookError::Status { status: 503, .. }));
        assert_eq!(sink.len(), 0);
        sink.clear_failure();
        sink.post("https://example.test/hook", b"", b"body")
            .await
            .unwrap();
        assert_eq!(sink.len(), 1);
    }

    #[cfg(feature = "webhook-client")]
    #[test]
    fn http_client_defaults_to_ten_seconds() {
        // Construction must succeed without I/O; the timeout is applied by the
        // builder and exercised end-to-end by integration tests.
        let sink = HttpWebhook::new().unwrap();
        let _ = sink.client();
        assert!(HttpWebhook::with_timeout(Duration::from_secs(1)).is_ok());
        assert_eq!(DEFAULT_TIMEOUT, Duration::from_secs(10));
    }

    #[cfg(feature = "webhook-client")]
    use std::time::Duration;
}
