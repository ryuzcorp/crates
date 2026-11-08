//! Static-token and HTTP Basic helpers for the smart-HTTP routes.
//!
//! [`GitHooks::authorize`](super::GitHooks::authorize) is the application's
//! authorization seam. A deployment that only needs a shared secret can put an
//! [`AuthConfig`] in front of it: an optional static token, accepted as
//! `Authorization: Bearer <token>` or as the password of HTTP Basic, with an
//! optional anonymous-read flag. Refusals are deliberately uniform so a
//! missing and a wrong credential look identical to a client.

use std::fmt;
use std::sync::Arc;

use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::Engine as _;

use super::Access;

/// `WWW-Authenticate` value used by every 401.
pub const BASIC_CHALLENGE: &str = "Basic realm=\"git\"";

/// One authorization refusal. `status` and `message` reach the client as-is;
/// only 401 gets the uniform Basic challenge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthError {
    pub status: StatusCode,
    pub message: String,
}

impl AuthError {
    pub fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }

    /// The uniform refusal for a missing or wrong credential.
    pub fn unauthorized() -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "unauthorized")
    }

    /// A detailed refusal the client is meant to read.
    pub fn forbidden(message: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, message)
    }

    /// A detailed not-found refusal (for example a disabled repository).
    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, message)
    }
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.status, self.message)
    }
}

impl std::error::Error for AuthError {}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        if self.status == StatusCode::UNAUTHORIZED {
            return (
                self.status,
                [(header::WWW_AUTHENTICATE, BASIC_CHALLENGE)],
                self.message,
            )
                .into_response();
        }
        (self.status, self.message).into_response()
    }
}

/// Credentials parsed from an `Authorization` header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Credentials {
    Basic { user: String, password: String },
    Bearer { token: String },
}

/// Static-token gate evaluated before [`super::GitHooks::authorize`].
#[derive(Debug, Clone)]
pub struct AuthConfig {
    token: Option<Arc<str>>,
    anonymous_read: bool,
    realm: Arc<str>,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            token: None,
            anonymous_read: false,
            realm: Arc::from("git"),
        }
    }
}

impl AuthConfig {
    /// No static token: only the application's hooks decide.
    pub fn new() -> Self {
        Self::default()
    }

    /// Require this token for authenticated access.
    pub fn with_token(token: impl Into<Arc<str>>) -> Self {
        Self {
            token: Some(token.into()),
            ..Self::default()
        }
    }

    /// Allow reads without a token. Writes still require one.
    pub fn anonymous_read(mut self) -> Self {
        self.anonymous_read = true;
        self
    }

    pub fn with_realm(mut self, realm: impl Into<Arc<str>>) -> Self {
        self.realm = realm.into();
        self
    }

    pub fn token(&self) -> Option<&str> {
        self.token.as_deref()
    }

    pub fn is_anonymous_read(&self) -> bool {
        self.anonymous_read
    }

    /// Whether a token is configured at all.
    pub fn is_enabled(&self) -> bool {
        self.token.is_some()
    }

    /// Check the headers for `need`. `Ok` when no token is configured, when a
    /// read is permitted anonymously, or when the presented token matches.
    pub fn check(&self, headers: &HeaderMap, need: Access) -> Result<(), AuthError> {
        let Some(expected) = self.token.as_deref() else {
            return Ok(());
        };
        if need == Access::View && self.anonymous_read {
            return Ok(());
        }
        let presented = match credentials(headers) {
            Some(Credentials::Basic { password, .. }) => password,
            Some(Credentials::Bearer { token }) => token,
            None => return Err(self.unauthorized()),
        };
        if constant_time_eq(presented.as_bytes(), expected.as_bytes()) {
            Ok(())
        } else {
            Err(self.unauthorized())
        }
    }

    /// The uniform 401 with this configuration's realm.
    pub fn unauthorized(&self) -> AuthError {
        AuthError::new(
            StatusCode::UNAUTHORIZED,
            format!("unauthorized: realm {:?}", &*self.realm),
        )
    }
}

/// Parse the `Authorization` header, accepting `Basic` and `Bearer`.
pub fn credentials(headers: &HeaderMap) -> Option<Credentials> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, rest) = value.split_once(' ')?;
    let rest = rest.trim();
    if rest.is_empty() {
        return None;
    }
    if scheme.eq_ignore_ascii_case("basic") {
        decode_basic(rest).map(|(user, password)| Credentials::Basic { user, password })
    } else if scheme.eq_ignore_ascii_case("bearer") {
        Some(Credentials::Bearer {
            token: rest.to_string(),
        })
    } else {
        None
    }
}

/// Decode a base64 `user:password` pair.
pub fn decode_basic(value: &str) -> Option<(String, String)> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(value.trim())
        .ok()?;
    let text = String::from_utf8(bytes).ok()?;
    let (user, password) = text.split_once(':')?;
    Some((user.to_string(), password.to_string()))
}

/// Encode Basic credentials (helpers for tests and clients).
pub fn encode_basic(user: &str, password: &str) -> String {
    let raw = format!("{user}:{password}");
    base64::engine::general_purpose::STANDARD.encode(raw)
}

/// Compare without an early exit on the first differing byte.
fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in left.iter().zip(right) {
        diff |= a ^ b;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn headers_with(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, HeaderValue::from_str(value).unwrap());
        headers
    }

    #[test]
    fn basic_roundtrip() {
        let encoded = encode_basic("git", "s3cret");
        assert_eq!(
            decode_basic(&encoded),
            Some(("git".to_string(), "s3cret".to_string()))
        );
        assert_eq!(
            credentials(&headers_with(&format!("Basic {encoded}"))),
            Some(Credentials::Basic {
                user: "git".into(),
                password: "s3cret".into()
            })
        );
        assert!(decode_basic("not base64").is_none());
        assert!(
            decode_basic(&base64::engine::general_purpose::STANDARD.encode("nocolon")).is_none()
        );
    }

    #[test]
    fn bearer_is_accepted() {
        assert_eq!(
            credentials(&headers_with("Bearer abc")),
            Some(Credentials::Bearer {
                token: "abc".into()
            })
        );
        assert!(credentials(&headers_with("Digest abc")).is_none());
    }

    #[test]
    fn token_gate_and_anonymous_read() {
        let auth = AuthConfig::with_token("t0ken");
        assert!(auth.check(&HeaderMap::new(), Access::Push).is_err());
        assert!(auth.check(&HeaderMap::new(), Access::View).is_err());
        assert!(auth
            .check(&headers_with("Bearer t0ken"), Access::Push)
            .is_ok());
        assert!(auth
            .check(
                &headers_with(&format!("Basic {}", encode_basic("any", "t0ken"))),
                Access::Push
            )
            .is_ok());
        assert!(auth
            .check(&headers_with("Bearer wrong"), Access::Push)
            .is_err());

        let anon = AuthConfig::with_token("t0ken").anonymous_read();
        assert!(anon.check(&HeaderMap::new(), Access::View).is_ok());
        assert!(anon.check(&HeaderMap::new(), Access::Push).is_err());
    }

    #[test]
    fn no_token_configured_allows_all() {
        let auth = AuthConfig::new();
        assert!(auth.check(&HeaderMap::new(), Access::Push).is_ok());
    }

    #[test]
    fn unauthorized_response_carries_the_challenge() {
        let response = AuthConfig::with_token("x").unauthorized().into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.headers()[header::WWW_AUTHENTICATE],
            BASIC_CHALLENGE
        );
    }
}
