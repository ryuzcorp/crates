//! Stock `git clone`/`fetch`/`push` over smart HTTP.
//!
//! [`router`] returns an axum [`Router`] with three routes:
//!
//! - `GET  /{slug}/info/refs?service=git-{upload,receive}-pack`
//! - `POST /{slug}/git-upload-pack`
//! - `POST /{slug}/git-receive-pack`
//!
//! The application supplies [`GitHooks`]: it decides who may read and write,
//! may add policy rules, and is told which refs moved after a push. The WAL
//! keeps object layout and durability: a push is served from the local bare
//! mirror and persisted as tip bundles plus one manifest flip, so a client
//! never talks to the bucket.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{Path as AxumPath, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use serde::Deserialize;

use crate::config::WalConfig;
use crate::git::{is_ancestor, list_refs, run_git, run_git_stdin};
use crate::manifest::ManifestCodec;
use crate::policy::{
    check_push_policy, parse_receive_commands, updates_needing_ff, PolicyDecision, PushCommand,
    Role,
};
use crate::store::ObjectStore;
use crate::wal::{GitSync, RecordOutcome, Wal};

const GIT_TIMEOUT: Duration = Duration::from_secs(300);

/// What a request wants to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    View,
    Push,
}

/// What the application's authorization granted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Grant {
    pub role: Role,
}

impl Grant {
    pub fn new(role: Role) -> Self {
        Self { role }
    }
}

/// A refusal from the application's authorization layer.
#[derive(Debug, Clone)]
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

    /// The uniform git-client refusal (401 + Basic challenge).
    pub fn unauthorized() -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "unauthorized")
    }

    pub fn forbidden(message: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, message)
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, message)
    }
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        if self.status == StatusCode::UNAUTHORIZED {
            return (
                self.status,
                [(header::WWW_AUTHENTICATE, "Basic realm=\"git\"")],
                self.message,
            )
                .into_response();
        }
        (self.status, self.message).into_response()
    }
}

/// Application-owned authorization and post-push behavior.
///
/// `authorize` runs before any git process. A refusal's status and message
/// reach the git client verbatim; return [`AuthError::unauthorized`] for the
/// uniform Basic-auth refusal, or a detailed 403/404 when the client should
/// read why (for example an over-limit push-to-create).
pub trait GitHooks: Send + Sync + 'static {
    fn authorize(
        &self,
        slug: &str,
        need: Access,
    ) -> impl Future<Output = Result<Grant, AuthError>> + Send;

    /// Extra push rules beyond the structural defaults (creates and
    /// fast-forwards for `push`, anything for `admin`).
    fn check_push(
        &self,
        _slug: &str,
        _role: Role,
        _cmds: &[PushCommand],
    ) -> impl Future<Output = Result<(), String>> + Send {
        async { Ok(()) }
    }

    /// Branch protection, evaluated after [`GitHooks::check_push`]. The
    /// default protects nothing.
    fn check_branch_protection(
        &self,
        _slug: &str,
        _role: Role,
        _cmds: &[PushCommand],
    ) -> impl Future<Output = Result<(), String>> + Send {
        async { Ok(()) }
    }

    /// An optional `remote:` note printed on a push (for example the app URL
    /// on the first push). `first_push` is true when the default branch did
    /// not exist before this request.
    fn note_push(&self, _slug: &str, _first_push: bool) -> Option<String> {
        None
    }

    /// Called after a push has been persisted to the WAL. Failures here never
    /// fail the push.
    fn refs_moved(&self, _slug: &str, _outcome: &RecordOutcome) -> impl Future<Output = ()> + Send {
        async {}
    }
}

/// Shared state for the smart-HTTP router.
pub struct GitHttp<S: ObjectStore, C: ManifestCodec, H: GitHooks> {
    pub store: S,
    pub config: WalConfig,
    pub codec: C,
    pub sync: GitSync,
    pub hooks: H,
}

impl<S: ObjectStore, C: ManifestCodec, H: GitHooks> GitHttp<S, C, H> {
    pub fn new(store: S, config: WalConfig, codec: C, hooks: H) -> Self {
        Self {
            store,
            config,
            codec,
            sync: GitSync::default(),
            hooks,
        }
    }

    pub fn with_sync(mut self, sync: GitSync) -> Self {
        self.sync = sync;
        self
    }

    fn wal(&self) -> Wal<'_, S, C> {
        Wal::new(&self.store, &self.config, &self.codec, &self.sync)
    }
}

/// Build the smart-HTTP router. Mount it wherever the application serves git
/// (for example `Router::nest("/v1/git", s3_wal_git::http::router(state))`).
pub fn router<S, C, H>(state: Arc<GitHttp<S, C, H>>) -> Router
where
    S: ObjectStore + Clone + 'static,
    C: ManifestCodec + Clone + 'static,
    H: GitHooks + Clone,
{
    let app: Router<Arc<GitHttp<S, C, H>>> = Router::new()
        .route("/{slug}/info/refs", get(info_refs::<S, C, H>))
        .route("/{slug}/git-upload-pack", post(upload_pack::<S, C, H>))
        .route("/{slug}/git-receive-pack", post(receive_pack::<S, C, H>));
    app.with_state(state)
}

#[derive(Debug, Deserialize)]
pub struct InfoRefsQuery {
    pub service: Option<String>,
}

fn pkt_line(payload: &str) -> Vec<u8> {
    pkt_line_bytes(payload.as_bytes())
}

fn pkt_line_bytes(payload: &[u8]) -> Vec<u8> {
    let total = payload.len() + 4;
    let mut out = format!("{total:04x}").into_bytes();
    out.extend_from_slice(payload);
    out
}

fn flush_pkt() -> &'static [u8] {
    b"0000"
}

fn wrap_advertise(service: &str, refs: &[u8]) -> Vec<u8> {
    let mut out = pkt_line(&format!("# service={service}\n"));
    out.extend_from_slice(flush_pkt());
    out.extend_from_slice(refs);
    out
}

fn internal(error: impl std::fmt::Display) -> Response {
    (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response()
}

async fn info_refs<S, C, H>(
    State(state): State<Arc<GitHttp<S, C, H>>>,
    AxumPath(slug): AxumPath<String>,
    Query(query): Query<InfoRefsQuery>,
    _headers: HeaderMap,
) -> Response
where
    S: ObjectStore + Clone + 'static,
    C: ManifestCodec + Clone + 'static,
    H: GitHooks + Clone,
{
    let Some(service) = query.service.as_deref() else {
        return (StatusCode::FORBIDDEN, "service required").into_response();
    };
    if service != "git-upload-pack" && service != "git-receive-pack" {
        return (StatusCode::FORBIDDEN, "unsupported service").into_response();
    }
    let need = if service == "git-receive-pack" {
        Access::Push
    } else {
        Access::View
    };
    if let Err(refusal) = state.hooks.authorize(&slug, need).await {
        return refusal.into_response();
    }
    let wal = state.wal();
    let bare = match wal.ensure_synced(&slug).await {
        Ok(bare) => bare,
        Err(e) => return internal(format!("{e:#}")),
    };
    let program = if service == "git-upload-pack" {
        "upload-pack"
    } else {
        "receive-pack"
    };
    let Some(bare_arg) = bare.to_str() else {
        return internal("bare mirror path is not valid UTF-8");
    };
    let out = match run_git(
        &[program, "--stateless-rpc", "--advertise-refs", bare_arg],
        &[],
        Duration::from_secs(30),
    )
    .await
    {
        Ok(out) => out.into_bytes(),
        Err(e) => return internal(format!("{e:#}")),
    };
    (
        StatusCode::OK,
        [
            (
                header::CONTENT_TYPE,
                format!("application/x-{service}-advertisement"),
            ),
            (header::CACHE_CONTROL, "no-cache".to_string()),
        ],
        wrap_advertise(service, &out),
    )
        .into_response()
}

async fn upload_pack<S, C, H>(
    State(state): State<Arc<GitHttp<S, C, H>>>,
    AxumPath(slug): AxumPath<String>,
    _headers: HeaderMap,
    body: Bytes,
) -> Response
where
    S: ObjectStore + Clone + 'static,
    C: ManifestCodec + Clone + 'static,
    H: GitHooks + Clone,
{
    if let Err(refusal) = state.hooks.authorize(&slug, Access::View).await {
        return refusal.into_response();
    }
    let wal = state.wal();
    let bare = match wal.ensure_synced(&slug).await {
        Ok(bare) => bare,
        Err(e) => return internal(format!("{e:#}")),
    };
    let Some(bare_arg) = bare.to_str() else {
        return internal("bare mirror path is not valid UTF-8");
    };
    match run_git_stdin(
        &["upload-pack", "--stateless-rpc", bare_arg],
        &body,
        &[],
        GIT_TIMEOUT,
    )
    .await
    {
        Ok(out) => (
            StatusCode::OK,
            [(
                header::CONTENT_TYPE,
                "application/x-git-upload-pack-result".to_string(),
            )],
            out,
        )
            .into_response(),
        Err(e) => internal(format!("{e:#}")),
    }
}

async fn receive_pack<S, C, H>(
    State(state): State<Arc<GitHttp<S, C, H>>>,
    AxumPath(slug): AxumPath<String>,
    _headers: HeaderMap,
    body: Bytes,
) -> Response
where
    S: ObjectStore + Clone + 'static,
    C: ManifestCodec + Clone + 'static,
    H: GitHooks + Clone,
{
    // The parsed head IS the policy input, so a head the policy layer cannot
    // read is refused before authorization or git: it is never handed to git
    // with every check skipped.
    let commands = match parse_receive_commands(&body) {
        Ok(commands) if !commands.is_empty() => commands,
        _ => {
            tracing::warn!(slug, "git receive: refused an unparseable request head");
            return (
                StatusCode::FORBIDDEN,
                "refused: the push request could not be parsed",
            )
                .into_response();
        }
    };
    let grant = match state.hooks.authorize(&slug, Access::Push).await {
        Ok(grant) => grant,
        Err(refusal) => return refusal.into_response(),
    };
    let role = grant.role;
    if let PolicyDecision::Deny(message) = check_push_policy(role, &commands) {
        return (StatusCode::FORBIDDEN, message).into_response();
    }
    if let Err(message) = state.hooks.check_push(&slug, role, &commands).await {
        return (StatusCode::FORBIDDEN, message).into_response();
    }
    if let Err(message) = state
        .hooks
        .check_branch_protection(&slug, role, &commands)
        .await
    {
        return (StatusCode::FORBIDDEN, message).into_response();
    }
    // Serialize pushes per slug across policy → git → bundles → manifest.
    let _guard = state.sync.lock(&slug).await;
    let wal = state.wal();
    let bare = match wal.ensure_synced_locked(&slug).await {
        Ok(bare) => bare,
        Err(e) => return internal(format!("{e:#}")),
    };
    if role != Role::Admin {
        for (refname, old, new) in updates_needing_ff(&commands) {
            if !is_ancestor(&bare, old, new).await {
                return (
                    StatusCode::FORBIDDEN,
                    format!("rule push-policy: 'push' may not force-push {refname} (admin only)"),
                )
                    .into_response();
            }
        }
    }
    let before = match list_refs(&bare, &state.config.extra_ref_prefixes).await {
        Ok(refs) => refs,
        Err(e) => return internal(format!("{e:#}")),
    };
    let default_ref = format!("refs/heads/{}", state.config.default_branch);
    let first_push = !before.contains_key(&default_ref);
    // Defense in depth: git itself refuses non-fast-forward updates and ref
    // deletions below admin, so a parsing divergence cannot become a
    // force-push or a delete.
    let mut argv: Vec<String> = Vec::new();
    if role != Role::Admin {
        argv.extend(
            [
                "-c",
                "receive.denyNonFastForwards=true",
                "-c",
                "receive.denyDeletes=true",
            ]
            .map(str::to_string),
        );
    }
    let Some(bare_arg) = bare.to_str() else {
        return internal("bare mirror path is not valid UTF-8");
    };
    argv.extend(["receive-pack", "--stateless-rpc", bare_arg].map(str::to_string));
    let argv: Vec<&str> = argv.iter().map(String::as_str).collect();
    let out = match run_git_stdin(&argv, &body, &[], GIT_TIMEOUT).await {
        Ok(out) => out,
        Err(e) => return internal(format!("{e:#}")),
    };
    let outcome = match wal.record_push_locked(&slug, &before).await {
        Ok(outcome) => outcome,
        Err(e) => {
            tracing::error!(slug, error = %format!("{e:#}"), "git receive: WAL write failed");
            return (StatusCode::CONFLICT, format!("{e:#}")).into_response();
        }
    };
    // The publish guard only covers the WAL; a hook may read or write other
    // repositories and must not inherit this slug's lock.
    drop(_guard);
    state.hooks.refs_moved(&slug, &outcome).await;
    let mut out = out;
    if let Some(note) = state.hooks.note_push(&slug, first_push) {
        if wants_sideband(&body) {
            out = with_notes(out, &[note]);
        }
    }
    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            "application/x-git-receive-pack-result".to_string(),
        )],
        out,
    )
        .into_response()
}

/// The sideband channel git's demuxer prints to stderr (prefixed `remote: `).
const SIDE_BAND_PROGRESS: u8 = 2;

/// Whether the push asked for sideband progress. Without it our channel byte
/// would be read as a protocol line, so the note is skipped instead.
fn wants_sideband(body: &[u8]) -> bool {
    let head = &body[..body.len().min(512)];
    head.windows(b"side-band-64k".len())
        .any(|w| w == b"side-band-64k")
}

/// Append sideband (`remote:`) lines before the final flush packet. The client
/// stops reading at the flush, so a packet after it would never be printed. A
/// body without the flush is passed through untouched.
fn with_notes(out: Vec<u8>, notes: &[String]) -> Vec<u8> {
    let Some(body) = out.strip_suffix(flush_pkt()) else {
        return out;
    };
    let mut merged = body.to_vec();
    for note in notes {
        let mut payload = vec![SIDE_BAND_PROGRESS];
        payload.extend_from_slice(note.as_bytes());
        payload.push(b'\n');
        merged.extend_from_slice(&pkt_line_bytes(&payload));
    }
    merged.extend_from_slice(flush_pkt());
    merged
}

/// The default receive-pack timeout.
pub const RECEIVE_TIMEOUT: Duration = GIT_TIMEOUT;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::RefsCodec;
    use crate::store::MemoryStore;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    #[derive(Clone)]
    struct AllowAll;

    impl GitHooks for AllowAll {
        async fn authorize(&self, _slug: &str, _need: Access) -> Result<Grant, AuthError> {
            Ok(Grant::new(Role::Admin))
        }
    }

    #[derive(Clone)]
    struct Deny;

    impl GitHooks for Deny {
        async fn authorize(&self, _slug: &str, _need: Access) -> Result<Grant, AuthError> {
            Err(AuthError::unauthorized())
        }
    }

    fn state<H: GitHooks>(hooks: H) -> Arc<GitHttp<MemoryStore, RefsCodec, H>> {
        let dir = tempfile::tempdir().unwrap().keep();
        let config = WalConfig::new(dir.join("git"), crate::config::Layout::new("git"));
        Arc::new(GitHttp::new(MemoryStore::new(), config, RefsCodec, hooks))
    }

    #[tokio::test]
    async fn unauthorized_gets_a_basic_challenge() {
        let response = router(state(Deny))
            .oneshot(
                Request::builder()
                    .uri("/demo/info/refs?service=git-upload-pack")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(response.headers().contains_key(header::WWW_AUTHENTICATE));
    }

    #[tokio::test]
    async fn info_refs_advertises_an_empty_repo() {
        let response = router(state(AllowAll))
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
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let text = String::from_utf8_lossy(&body);
        assert!(text.contains("# service=git-upload-pack"), "{text}");
    }

    #[tokio::test]
    async fn unparseable_push_head_is_refused_before_auth() {
        let response = router(state(Deny))
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

    /// End-to-end: a real `git push` and `git clone` through the axum router,
    /// persisted as bundles + one manifest flip in the store.
    #[tokio::test]
    async fn real_git_push_and_clone_roundtrip_through_http() {
        let dir = tempfile::tempdir().unwrap().keep();
        let config = WalConfig::new(dir.join("git"), crate::config::Layout::new("git"));
        let store = MemoryStore::new();
        let state = Arc::new(GitHttp::new(
            store.clone(),
            config.clone(),
            RefsCodec,
            AllowAll,
        ));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = router(state);
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let source = dir.join("source");
        let git = |args: Vec<String>, cwd: Option<std::path::PathBuf>| async move {
            let mut cmd = tokio::process::Command::new("git");
            cmd.args(&args)
                .env_clear()
                .env("PATH", "/usr/local/bin:/usr/bin:/bin")
                .env("HOME", "/nonexistent")
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_TERMINAL_PROMPT", "0")
                .env("GIT_AUTHOR_NAME", "push-test")
                .env("GIT_AUTHOR_EMAIL", "push-test@example.com")
                .env("GIT_COMMITTER_NAME", "push-test")
                .env("GIT_COMMITTER_EMAIL", "push-test@example.com");
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
        };
        git(
            vec![
                "init".into(),
                "-b".into(),
                "main".into(),
                source.display().to_string(),
            ],
            None,
        )
        .await;
        tokio::fs::write(source.join("README.md"), "# app\n")
            .await
            .unwrap();
        git(vec!["add".into(), "-A".into()], Some(source.clone())).await;
        git(
            vec!["commit".into(), "-m".into(), "one".into()],
            Some(source.clone()),
        )
        .await;
        let sha = git(
            vec!["rev-parse".into(), "HEAD".into()],
            Some(source.clone()),
        )
        .await;
        git(
            vec![
                "push".into(),
                format!("http://{addr}/demo"),
                "refs/heads/main:refs/heads/main".into(),
            ],
            Some(source.clone()),
        )
        .await;

        let sync = GitSync::default();
        let wal = Wal::new(&store, &config, &RefsCodec, &sync);
        let manifest = wal.read_manifest("demo").await.unwrap().unwrap();
        assert_eq!(manifest.seq, 1);
        assert_eq!(manifest.refs["refs/heads/main"].sha, sha);
        assert!(store
            .get(&manifest.refs["refs/heads/main"].bundle)
            .await
            .unwrap()
            .is_some());

        // A fresh clone is served from the same manifest.
        let clone = dir.join("clone");
        git(
            vec![
                "clone".into(),
                format!("http://{addr}/demo"),
                clone.display().to_string(),
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

    #[test]
    fn notes_land_before_the_flush() {
        let out = b"000dunpack ok\n0000".to_vec();
        let noted = with_notes(out, &["demo: http://a.localhost".to_string()]);
        let text = String::from_utf8_lossy(&noted);
        assert!(text.ends_with("0000"));
        let note_at = text.find("demo:").expect("note");
        let flush_at = text.rfind("0000").expect("flush");
        assert!(note_at < flush_at, "{text}");
        let bare = b"000dunpack ok\n".to_vec();
        assert_eq!(with_notes(bare.clone(), &["x".to_string()]), bare);
    }

    #[test]
    fn sideband_capability_is_detected() {
        let line = format!(
            "{} {} refs/heads/main\0report-status side-band-64k\n",
            "0".repeat(40),
            "a".repeat(40)
        );
        let mut body = pkt_line_bytes(line.as_bytes());
        body.extend_from_slice(b"0000");
        assert!(wants_sideband(&body));
        assert!(!wants_sideband(b"0000"));
    }
}
