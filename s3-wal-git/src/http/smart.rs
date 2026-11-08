//! `info/refs` and `git-upload-pack` handlers.
//!
//! Protocol v2 is negotiated through the `Git-Protocol` request header and
//! passed to git as `GIT_PROTOCOL=version=2`. A v2 advertisement is returned
//! raw; a v0 advertisement keeps the `# service=...` pkt-line wrapper. Receive
//! pack has no v2 wire protocol and always advertises v0.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use axum::body::{Body, Bytes};
use axum::extract::{Path as AxumPath, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

use crate::git::protocol::{wrap_advertise, Protocol, Service};
use crate::git::{run_git_raw, spawn_git_stdin};
use crate::manifest::ManifestCodec;

use super::auth::AuthError;
use super::{git_response, internal, Access, GitHooks, GitHttp};

/// Ref advertisement is fast even on a cold mirror.
const ADVERTISE_TIMEOUT: Duration = Duration::from_secs(30);

/// `?service=git-upload-pack` or `git-receive-pack`.
#[derive(Debug, Deserialize)]
pub struct InfoRefsQuery {
    pub service: Option<String>,
}

/// `GET /{repo}/info/refs`.
pub async fn info_refs<C, H>(
    State(state): State<Arc<GitHttp<C, H>>>,
    AxumPath(params): AxumPath<HashMap<String, String>>,
    Query(query): Query<InfoRefsQuery>,
    headers: HeaderMap,
) -> Response
where
    C: ManifestCodec + 'static,
    H: GitHooks + 'static,
{
    let Some(service) = query.service.as_deref().and_then(Service::parse) else {
        return (
            StatusCode::FORBIDDEN,
            "smart HTTP requires service=git-upload-pack or service=git-receive-pack",
        )
            .into_response();
    };
    let slug = match super::repo_from_params(&params) {
        Ok(slug) => slug,
        Err(error) => return error.into_response(),
    };
    let need = match service {
        Service::UploadPack => Access::View,
        Service::ReceivePack => Access::Push,
    };
    if let Err(error) = state.auth.check(&headers, need) {
        return error.into_response();
    }
    if let Err(error) = state.hooks.authorize_request(&slug, need, &headers).await {
        return error.into_response();
    }
    let wal = state.wal();
    let bare = match wal.ensure_synced(&slug).await {
        Ok(bare) => bare,
        Err(error) => return super::wal_response(error),
    };
    let Some(bare_arg) = bare.to_str() else {
        return internal("bare mirror path is not valid UTF-8");
    };
    let protocol = match service {
        Service::UploadPack => Protocol::from_header(
            headers
                .get("git-protocol")
                .and_then(|value| value.to_str().ok()),
        ),
        Service::ReceivePack => Protocol::V0,
    };
    let env: Vec<(&str, &str)> = protocol.git_protocol_env().into_iter().collect();
    let out = match run_git_raw(
        &[
            service.program(),
            "--stateless-rpc",
            "--advertise-refs",
            bare_arg,
        ],
        &env,
        ADVERTISE_TIMEOUT,
    )
    .await
    {
        Ok(out) => out,
        Err(error) => return git_response(error),
    };
    let body = match protocol {
        Protocol::V2 => out,
        Protocol::V0 => wrap_advertise(service, &out),
    };
    (
        StatusCode::OK,
        [
            (
                header::CONTENT_TYPE,
                format!("application/x-{}-advertisement", service.as_str()),
            ),
            (header::CACHE_CONTROL, "no-cache".to_string()),
            (header::VARY, "Git-Protocol".to_string()),
        ],
        body,
    )
        .into_response()
}

/// `POST /{repo}/git-upload-pack`.
pub async fn upload_pack<C, H>(
    State(state): State<Arc<GitHttp<C, H>>>,
    AxumPath(params): AxumPath<HashMap<String, String>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response
where
    C: ManifestCodec + 'static,
    H: GitHooks + 'static,
{
    let slug = match super::repo_from_params(&params) {
        Ok(slug) => slug,
        Err(error) => return error.into_response(),
    };
    if let Err(error) = state.auth.check(&headers, Access::View) {
        return error.into_response();
    }
    if let Err(error) = state
        .hooks
        .authorize_request(&slug, Access::View, &headers)
        .await
    {
        return error.into_response();
    }
    let wal = state.wal();
    let bare = match wal.ensure_synced(&slug).await {
        Ok(bare) => bare,
        Err(error) => return super::wal_response(error),
    };
    let Some(bare_arg) = bare.to_str() else {
        return internal("bare mirror path is not valid UTF-8");
    };
    let protocol = Protocol::from_header(
        headers
            .get("git-protocol")
            .and_then(|value| value.to_str().ok()),
    );
    let env: Vec<(&str, &str)> = protocol.git_protocol_env().into_iter().collect();
    let (child, stdout) = match spawn_git_stdin(
        &["upload-pack", "--stateless-rpc", bare_arg],
        body.to_vec(),
        &env,
    )
    .await
    {
        Ok(pair) => pair,
        Err(error) => return git_response(error),
    };
    // Stream the pack instead of buffering it: a large clone must not allocate
    // its full output, and the client should receive progress as git writes.
    let stream = futures::stream::unfold((stdout, Some(child)), |(mut out, child)| async move {
        use tokio::io::AsyncReadExt as _;
        let mut buf = vec![0u8; 64 * 1024];
        match out.read(&mut buf).await {
            Ok(0) => {
                if let Some(mut child) = child {
                    let _ = child.wait().await;
                }
                None
            }
            Ok(n) => {
                buf.truncate(n);
                Some((Ok(Bytes::from(buf)), (out, child)))
            }
            Err(error) => Some((Err(error), (out, child))),
        }
    });
    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            "application/x-git-upload-pack-result".to_string(),
        )],
        Body::from_stream(stream),
    )
        .into_response()
}

/// The uniform refusal used when a hook fails; kept here so handlers do not
/// construct statuses inline.
pub(crate) fn forbidden(message: impl Into<String>) -> Response {
    AuthError::forbidden(message).into_response()
}
