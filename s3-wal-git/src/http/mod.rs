//! Smart HTTP v0/v2, receive ingest, LFS and transport limits.
//!
//! [`router`] mounts stock `git clone`/`fetch`/`push` over HTTP:
//!
//! - `GET  /{repo}/info/refs?service=git-{upload,receive}-pack`
//! - `POST /{repo}/git-upload-pack`
//! - `POST /{repo}/git-receive-pack`
//! - `POST /{repo}/info/lfs/objects/batch`
//! - `GET|PUT /{repo}/lfs/objects/{oid}`
//!
//! `{repo}` is a catch-all so both `demo` and `acme/demo.git` resolve through
//! [`RepoId`].
//!
//! The application supplies [`GitHooks`] for authorization and post-push
//! behavior, and may add a [`PushPolicy`] rule engine. The WAL keeps object
//! layout and durability: a push is served from the local bare mirror and
//! persisted as immutable objects plus one manifest flip, so a client never
//! talks to the bucket directly.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;

use crate::config::WalConfig;
use crate::error::{GitError, StoreError, WalError};
use crate::git::receive::PushCommand;
use crate::git::RepoId;
use crate::lfs::LfsStore;
use crate::manifest::ManifestCodec;
use crate::store::DynStore;
use crate::wal::{GitSync, RecordOutcome, Wal};

pub mod auth;
pub mod lfs;
pub mod limits;
pub mod receive;
pub mod smart;

pub use auth::{AuthConfig, AuthError, Credentials, BASIC_CHALLENGE};
pub use limits::{HttpLimits, PushLimiter, RequestId, REQUEST_ID_HEADER};

/// What a request wants to do with a repository.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    View,
    Push,
}

impl Access {
    pub fn can_write(self) -> bool {
        matches!(self, Self::Push)
    }
}

/// What the application's authorization granted for this request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    View,
    Push,
    Admin,
}

impl Role {
    pub fn can_push(self) -> bool {
        !matches!(self, Self::View)
    }

    pub fn is_admin(self) -> bool {
        matches!(self, Self::Admin)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::View => "view",
            Self::Push => "push",
            Self::Admin => "admin",
        }
    }
}

/// The authorization result for one request.
///
/// Besides the role, the grant may carry the policy principal and any tags the
/// edge already bound; the repository policy engine matches them by name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    pub role: Role,
    pub principal: Option<String>,
    pub tags: Vec<String>,
}

impl Grant {
    pub fn new(role: Role) -> Self {
        Self {
            role,
            principal: None,
            tags: Vec::new(),
        }
    }

    pub fn view() -> Self {
        Self::new(Role::View)
    }

    pub fn push() -> Self {
        Self::new(Role::Push)
    }

    pub fn admin() -> Self {
        Self::new(Role::Admin)
    }

    /// Bind the policy principal (for example a user or token id).
    pub fn with_principal(mut self, principal: impl Into<String>) -> Self {
        self.principal = Some(principal.into());
        self
    }

    /// Bind tags matched by `@tag` actor entries.
    pub fn with_tags<I, S>(mut self, tags: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.tags = tags.into_iter().map(Into::into).collect();
        self
    }

    /// The principal name a policy rule sees.
    pub fn principal(&self) -> &str {
        self.principal.as_deref().unwrap_or("anonymous")
    }
}

/// A push handed to an optional [`PushPolicy`] engine before mutable work.
#[derive(Debug, Clone, Copy)]
pub struct PushPolicyContext<'a> {
    pub repo: &'a str,
    pub role: Role,
    pub commands: &'a [PushCommand],
    pub push_options: &'a [String],
}

/// Optional repository policy, evaluated after authorization and before the
/// slug lock. Implement it over the policy module's rule engine, or supply any
/// application-specific checks. An `Err` message reaches the client as 403.
#[async_trait]
pub trait PushPolicy: Send + Sync + 'static {
    async fn evaluate(&self, context: PushPolicyContext<'_>) -> Result<(), String>;
}

/// Application-owned authorization and post-push behavior.
#[async_trait]
pub trait GitHooks: Send + Sync + 'static {
    /// Decide whether this request may read or write `repo`.
    ///
    /// Prefer [`GitHooks::authorize_request`], which also receives the request
    /// headers. This method remains for simple repository-wide policies.
    async fn authorize(&self, repo: &str, need: Access) -> Result<Grant, AuthError>;

    /// Per-request authorization with the original headers. The default
    /// delegates to [`GitHooks::authorize`]; applications that authenticate
    /// users override this and inspect `Authorization` or cookies.
    async fn authorize_request(
        &self,
        repo: &str,
        need: Access,
        _headers: &axum::http::HeaderMap,
    ) -> Result<Grant, AuthError> {
        self.authorize(repo, need).await
    }

    /// Extra push rules beyond the built-in role checks (creates and
    /// fast-forwards for `push`, anything for `admin`).
    async fn check_push(
        &self,
        _repo: &str,
        _role: Role,
        _commands: &[PushCommand],
    ) -> Result<(), String> {
        Ok(())
    }

    /// Branch protection, evaluated after [`GitHooks::check_push`].
    async fn check_branch_protection(
        &self,
        _repo: &str,
        _role: Role,
        _commands: &[PushCommand],
    ) -> Result<(), String> {
        Ok(())
    }

    /// An optional `remote:` note printed during a push (for example the
    /// application URL on the first push). `first_push` is true when the
    /// default branch did not exist before this request.
    fn note_push(&self, _repo: &str, _first_push: bool) -> Option<String> {
        None
    }

    /// Called after a push is persisted to the WAL. A failure here never fails
    /// the push; the implementation is expected to log its own errors.
    async fn refs_moved(&self, _repo: &str, _outcome: &RecordOutcome) {}
}

/// Shared state for the smart-HTTP router.
pub struct GitHttp<C: ManifestCodec, H: GitHooks> {
    pub store: DynStore,
    pub config: Arc<WalConfig>,
    pub codec: Arc<C>,
    pub sync: GitSync,
    pub hooks: H,
    pub auth: AuthConfig,
    pub policy: Option<Arc<dyn PushPolicy>>,
    pub lfs: Option<LfsStore>,
    pub pushes: PushLimiter,
}

impl<C: ManifestCodec, H: GitHooks> GitHttp<C, H> {
    pub fn new(store: DynStore, config: Arc<WalConfig>, codec: Arc<C>, hooks: H) -> Self {
        let per_repo = config.limits.max_concurrent_pushes;
        Self {
            store,
            config,
            codec,
            sync: GitSync::default(),
            hooks,
            auth: AuthConfig::new(),
            policy: None,
            lfs: None,
            pushes: PushLimiter::new(per_repo),
        }
    }

    pub fn with_sync(mut self, sync: GitSync) -> Self {
        self.sync = sync;
        self
    }

    /// Add a static-token gate in front of the hooks.
    pub fn with_auth(mut self, auth: AuthConfig) -> Self {
        self.auth = auth;
        self
    }

    /// Add an optional repository policy engine.
    pub fn with_policy(mut self, policy: Arc<dyn PushPolicy>) -> Self {
        self.policy = Some(policy);
        self
    }

    /// Enable the LFS routes for this state.
    pub fn with_lfs(mut self, lfs: LfsStore) -> Self {
        self.lfs = Some(lfs);
        self
    }

    /// A WAL handle sharing this state's store, codec and lock table.
    pub fn wal(&self) -> Wal<C> {
        Wal::new(self.store.clone(), self.config.clone(), self.codec.clone())
            .with_sync(self.sync.clone())
    }

    /// The repository slug after validating a catch-all path segment.
    pub fn repo_slug(repo: &str) -> Result<String, AuthError> {
        RepoId::parse(repo)
            .map(|id| id.slug())
            .map_err(|_| AuthError::not_found("repository not found"))
    }
}

/// Resolve the repository from whichever path arity matched.
pub(crate) fn repo_from_params(params: &HashMap<String, String>) -> Result<String, AuthError> {
    let (owner, name) = match (params.get("owner"), params.get("repo")) {
        (Some(owner), Some(name)) => (Some(owner.as_str()), name.as_str()),
        (None, Some(name)) => (None, name.as_str()),
        _ => return Err(AuthError::not_found("repository not found")),
    };
    let raw = match owner {
        Some(owner) => format!("{owner}/{name}"),
        None => name.to_string(),
    };
    RepoId::parse(&raw)
        .map(|id| id.slug())
        .map_err(|_| AuthError::not_found("repository not found"))
}

/// Build the smart-HTTP router. Mount it wherever the application serves git,
/// for example `Router::nest("/v1/git", router(state))`.
pub fn router<C, H>(state: Arc<GitHttp<C, H>>) -> Router
where
    C: ManifestCodec + 'static,
    H: GitHooks + 'static,
{
    let limits = state.config.limits.clone();
    // A repository is `name` or `owner/name` (the only shapes `RepoId`
    // accepts). axum's matcher keeps catch-all parameters at the end of a
    // route, so the two arities are registered explicitly. The handler reads
    // whichever names matched through a parameter map.
    let app = Router::new()
        .route("/{repo}/info/refs", get(smart::info_refs::<C, H>))
        .route("/{owner}/{repo}/info/refs", get(smart::info_refs::<C, H>))
        .route("/{repo}/git-upload-pack", post(smart::upload_pack::<C, H>))
        .route(
            "/{owner}/{repo}/git-upload-pack",
            post(smart::upload_pack::<C, H>),
        )
        .route(
            "/{repo}/git-receive-pack",
            post(receive::receive_pack::<C, H>),
        )
        .route(
            "/{owner}/{repo}/git-receive-pack",
            post(receive::receive_pack::<C, H>),
        )
        .route("/{repo}/info/lfs/objects/batch", post(lfs::batch::<C, H>))
        .route(
            "/{owner}/{repo}/info/lfs/objects/batch",
            post(lfs::batch::<C, H>),
        )
        .route(
            "/{repo}/lfs/objects/{oid}",
            get(lfs::download::<C, H>).put(lfs::upload::<C, H>),
        )
        .route(
            "/{owner}/{repo}/lfs/objects/{oid}",
            get(lfs::download::<C, H>).put(lfs::upload::<C, H>),
        )
        .with_state(state);
    limits::apply_layers(app, &limits)
}

/// Map a WAL failure to its HTTP status.
pub(crate) fn wal_status(error: &WalError) -> StatusCode {
    match error {
        WalError::NotFound(_) => StatusCode::NOT_FOUND,
        WalError::AlreadyExists(_) | WalError::RefConflict { .. } => StatusCode::CONFLICT,
        WalError::RetryExhausted { .. } => StatusCode::SERVICE_UNAVAILABLE,
        WalError::Store(StoreError::NotFound { .. }) => StatusCode::NOT_FOUND,
        WalError::Store(StoreError::PreconditionFailed { .. }) => StatusCode::CONFLICT,
        WalError::Store(StoreError::Retryable(_)) => StatusCode::SERVICE_UNAVAILABLE,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

/// A WAL failure as a response, with the chain rendered for the operator.
pub(crate) fn wal_response(error: WalError) -> Response {
    let status = wal_status(&error);
    (status, format!("{error:#}")).into_response()
}

/// A git failure as an opaque 500 (its stderr may contain paths).
pub(crate) fn git_response(error: GitError) -> Response {
    tracing::error!(error = %error, "git operation failed");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        "git operation failed".to_string(),
    )
        .into_response()
}

/// A short internal-error response that never leaks a stack trace.
pub(crate) fn internal(message: impl std::fmt::Display) -> Response {
    tracing::error!(error = %message, "smart-http internal error");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal server error".to_string(),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use axum::body::Body;
    use axum::http::{header, Request};
    use bytes::Bytes;
    use tower::ServiceExt as _;

    use super::*;
    use crate::config::{Layout, StorageMode};
    use crate::git::protocol;
    use crate::manifest::{RefsCodec, RefsManifest};
    use crate::store::{MemoryStore, ObjectStoreExt as _};

    #[derive(Clone, Copy)]
    struct AllowAll;

    #[async_trait]
    impl GitHooks for AllowAll {
        async fn authorize(&self, _repo: &str, _need: Access) -> Result<Grant, AuthError> {
            Ok(Grant::admin())
        }
    }

    struct Deny;

    #[async_trait]
    impl GitHooks for Deny {
        async fn authorize(&self, _repo: &str, _need: Access) -> Result<Grant, AuthError> {
            Err(AuthError::unauthorized())
        }
    }

    struct DenyPolicy;

    #[async_trait]
    impl PushPolicy for DenyPolicy {
        async fn evaluate(&self, _context: PushPolicyContext<'_>) -> Result<(), String> {
            Err("rule test: denied".to_string())
        }
    }

    fn temp_config(dir: &Path) -> WalConfig {
        WalConfig::new(dir.join("git"), Layout::new("git"))
    }

    fn state<H: GitHooks>(hooks: H) -> (Arc<GitHttp<RefsCodec, H>>, tempfile::TempDir) {
        state_with(hooks, |_| {})
    }

    fn state_with<H: GitHooks>(
        hooks: H,
        tweak: impl FnOnce(&mut WalConfig),
    ) -> (Arc<GitHttp<RefsCodec, H>>, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let mut config = temp_config(dir.path());
        tweak(&mut config);
        let store: DynStore = Arc::new(MemoryStore::new());
        (
            Arc::new(GitHttp::new(
                store,
                Arc::new(config),
                Arc::new(RefsCodec),
                hooks,
            )),
            dir,
        )
    }

    fn pkt(payload: &[u8]) -> Vec<u8> {
        let total = payload.len() + 4;
        let mut out = format!("{total:04x}").into_bytes();
        out.extend_from_slice(payload);
        out
    }

    fn receive_body() -> Bytes {
        let mut body = pkt(format!(
            "{} {} refs/heads/main\0report-status side-band-64k\n",
            "0".repeat(40),
            "a".repeat(40)
        )
        .as_bytes());
        body.extend_from_slice(b"0000");
        Bytes::from(body)
    }

    async fn body_text(response: Response) -> String {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        String::from_utf8_lossy(&bytes).into_owned()
    }

    #[tokio::test]
    async fn unauthorized_gets_a_basic_challenge() {
        let (state, _dir) = state(Deny);
        let response = router(state)
            .oneshot(
                Request::builder()
                    .uri("/demo/info/refs?service=git-upload-pack")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.headers()[header::WWW_AUTHENTICATE],
            BASIC_CHALLENGE
        );
    }

    #[tokio::test]
    async fn static_token_gate_precedes_hooks() {
        let (state, _dir) = state(AllowAll);
        let mut http = GitHttp::new(
            state.store.clone(),
            state.config.clone(),
            state.codec.clone(),
            AllowAll,
        );
        http.auth = AuthConfig::with_token("t0ken").anonymous_read();
        let app = router(Arc::new(http));
        let read = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/demo/info/refs?service=git-upload-pack")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        // Anonymous read is allowed; a push advertisement is not.
        assert_ne!(read.status(), StatusCode::UNAUTHORIZED);
        let push = app
            .oneshot(
                Request::builder()
                    .uri("/demo/info/refs?service=git-receive-pack")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(push.status(), StatusCode::UNAUTHORIZED);
        assert!(push.headers().contains_key(header::WWW_AUTHENTICATE));
    }

    #[tokio::test]
    async fn v0_info_refs_advertisement_is_wrapped() {
        let (state, _dir) = state(AllowAll);
        let response = router(state)
            .oneshot(
                Request::builder()
                    .uri("/demo/info/refs?service=git-upload-pack")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()[header::CONTENT_TYPE],
            "application/x-git-upload-pack-advertisement"
        );
        let body = body_text(response).await;
        assert!(body.contains("# service=git-upload-pack"), "{body}");
        assert!(
            body.starts_with("001e# service=git-upload-pack\n"),
            "{body}"
        );
    }

    #[tokio::test]
    async fn v2_info_refs_advertisement_has_no_service_wrapper() {
        let (state, _dir) = state(AllowAll);
        let response = router(state)
            .oneshot(
                Request::builder()
                    .uri("/acme/demo.git/info/refs?service=git-upload-pack")
                    .header("git-protocol", "version=2")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(
            body.starts_with(&protocol::pkt_line_str("version 2")),
            "{}",
            String::from_utf8_lossy(&body)
        );
        assert!(!String::from_utf8_lossy(&body).contains("# service"));
    }

    #[tokio::test]
    async fn unparseable_push_head_is_refused_before_auth() {
        let (state, _dir) = state(Deny);
        let response = router(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/demo/git-receive-pack")
                    .body(Body::from("not a pkt line"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn body_limit_returns_413() {
        let (state, _dir) = state_with(AllowAll, |config| {
            config.limits.max_body_bytes = 64;
        });
        let response = router(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/demo/git-upload-pack")
                    .body(Body::from(vec![0u8; 4096]))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn policy_denial_is_403() {
        let (base, _dir) = state(AllowAll);
        let mut http = GitHttp::new(
            base.store.clone(),
            base.config.clone(),
            base.codec.clone(),
            AllowAll,
        );
        http.policy = Some(Arc::new(DenyPolicy));
        let response = router(Arc::new(http))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/demo/git-receive-pack")
                    .body(Body::from(receive_body()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(body_text(response).await, "rule test: denied");
    }

    fn git_command() -> tokio::process::Command {
        let mut cmd = tokio::process::Command::new("git");
        cmd.env_clear()
            .env("PATH", "/usr/local/bin:/usr/bin:/bin")
            .env("HOME", "/nonexistent")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_AUTHOR_NAME", "http-test")
            .env("GIT_AUTHOR_EMAIL", "http-test@example.com")
            .env("GIT_COMMITTER_NAME", "http-test")
            .env("GIT_COMMITTER_EMAIL", "http-test@example.com");
        cmd
    }

    async fn git(args: &[&str], cwd: Option<&Path>) -> String {
        let mut cmd = git_command();
        cmd.args(args);
        if let Some(cwd) = cwd {
            cmd.current_dir(cwd);
        }
        let out = cmd.output().await.unwrap();
        assert!(
            out.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    async fn server<H: GitHooks + 'static>(
        state: Arc<GitHttp<RefsCodec, H>>,
    ) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = router(state);
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        (addr, handle)
    }

    async fn commit_one(dir: &Path) -> String {
        let source = dir.join("source");
        git(&["init", "-b", "main", source.to_str().unwrap()], None).await;
        tokio::fs::write(source.join("README.md"), "# app\n")
            .await
            .unwrap();
        git(&["add", "-A"], Some(&source)).await;
        git(&["commit", "-m", "one"], Some(&source)).await;
        git(&["rev-parse", "HEAD"], Some(&source)).await
    }

    /// End-to-end: real `git push` then `git clone` through the router,
    /// persisted as bundles plus one manifest flip in the store.
    #[tokio::test]
    async fn real_git_push_and_clone_roundtrip() {
        let (state, dir) = state(AllowAll);
        let store = state.store.clone();
        let config = state.config.clone();
        let (addr, server) = server(state).await;
        let sha = commit_one(dir.path()).await;
        let source = dir.path().join("source");
        git(
            &[
                "push",
                &format!("http://{addr}/demo"),
                "refs/heads/main:refs/heads/main",
            ],
            Some(&source),
        )
        .await;

        let (_, bytes) = store
            .get_bytes(&config.layout.manifest_key("demo"))
            .await
            .unwrap()
            .expect("manifest after push");
        let manifest: RefsManifest = RefsCodec.decode(&bytes).unwrap();
        assert_eq!(manifest.seq, 1);
        assert_eq!(manifest.refs["refs/heads/main"].sha, sha);
        let bundle = manifest.refs["refs/heads/main"]
            .bundle
            .as_ref()
            .expect("bundle key");
        assert!(store.head(bundle).await.unwrap().is_some());

        let clone = dir.path().join("clone");
        git(
            &[
                "clone",
                &format!("http://{addr}/demo"),
                clone.to_str().unwrap(),
            ],
            None,
        )
        .await;
        assert_eq!(
            tokio::fs::read_to_string(clone.join("README.md"))
                .await
                .unwrap(),
            "# app\n"
        );
        server.abort();
    }

    /// Pack mode: the incoming pack is ingested before receive-pack and named
    /// by the manifest, so no per-ref bundle is written.
    #[tokio::test]
    async fn pack_mode_push_persists_the_pack() {
        let (state, dir) = state_with(AllowAll, |config| {
            config.storage = StorageMode::Pack;
        });
        let store = state.store.clone();
        let config = state.config.clone();
        let (addr, server) = server(state).await;
        let sha = commit_one(dir.path()).await;
        let source = dir.path().join("source");
        git(
            &[
                "push",
                &format!("http://{addr}/demo"),
                "refs/heads/main:refs/heads/main",
            ],
            Some(&source),
        )
        .await;

        let (_, bytes) = store
            .get_bytes(&config.layout.manifest_key("demo"))
            .await
            .unwrap()
            .expect("manifest after push");
        let manifest: RefsManifest = RefsCodec.decode(&bytes).unwrap();
        assert_eq!(manifest.refs["refs/heads/main"].sha, sha);
        assert!(!manifest.packs.is_empty(), "manifest names no pack");
        let pack = &manifest.packs[0];
        let key = config.layout.pack_key("demo", &pack.checksum, "pack");
        assert!(
            store.head(&key).await.unwrap().is_some(),
            "pack {key} missing"
        );
        assert!(
            manifest.refs["refs/heads/main"].bundle.is_none(),
            "pack mode must not carry a bundle key"
        );
        server.abort();
    }

    #[tokio::test]
    async fn lfs_batch_upload_and_missing_download() {
        let (base, _dir) = state(AllowAll);
        let mut http = GitHttp::new(
            base.store.clone(),
            base.config.clone(),
            base.codec.clone(),
            AllowAll,
        );
        http.lfs = Some(crate::lfs::LfsStore::new(
            base.store.clone(),
            base.config.layout.clone(),
        ));
        let app = router(Arc::new(http));
        let oid = "a".repeat(64);
        let upload = serde_json::json!({
            "operation": "upload",
            "transfers": ["basic"],
            "objects": [{"oid": oid, "size": 3}]
        });
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/demo/info/lfs/objects/batch")
                    .header(header::CONTENT_TYPE, crate::lfs::LFS_CONTENT_TYPE)
                    .body(Body::from(upload.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()[header::CONTENT_TYPE],
            crate::lfs::LFS_CONTENT_TYPE
        );
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(body["transfer"], "basic");
        assert!(body["objects"][0]["actions"]["upload"]["href"].is_string());

        let download = serde_json::json!({
            "operation": "download",
            "transfers": ["basic"],
            "objects": [{"oid": oid, "size": 3}]
        });
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/demo/info/lfs/objects/batch")
                    .header(header::CONTENT_TYPE, crate::lfs::LFS_CONTENT_TYPE)
                    .body(Body::from(download.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(body["objects"][0]["error"]["code"], 404);
    }

    #[tokio::test]
    async fn lfs_object_upload_and_download_roundtrip() {
        use sha2::{Digest as _, Sha256};

        let (base, _dir) = state(AllowAll);
        let mut http = GitHttp::new(
            base.store.clone(),
            base.config.clone(),
            base.codec.clone(),
            AllowAll,
        );
        http.lfs = Some(crate::lfs::LfsStore::new(
            base.store.clone(),
            base.config.layout.clone(),
        ));
        let app = router(Arc::new(http));
        let oid = hex::encode(Sha256::digest(b"abc"));
        let put = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/demo/lfs/objects/{oid}"))
                    .header(header::CONTENT_LENGTH, "3")
                    .body(Body::from("abc"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(put.status(), StatusCode::OK);
        let get = app
            .oneshot(
                Request::builder()
                    .uri(format!("/demo/lfs/objects/{oid}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(get.status(), StatusCode::OK);
        assert_eq!(
            get.headers()[header::CONTENT_TYPE],
            "application/octet-stream"
        );
        assert_eq!(
            axum::body::to_bytes(get.into_body(), usize::MAX)
                .await
                .unwrap(),
            "abc"
        );
    }

    #[tokio::test]
    async fn unknown_repository_is_created_empty_for_advertisement() {
        let (state, _dir) = state(AllowAll);
        let response = router(state)
            .oneshot(
                Request::builder()
                    .uri("/brand/new/info/refs?service=git-upload-pack")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()[header::CONTENT_TYPE],
            "application/x-git-upload-pack-advertisement"
        );
    }
}
