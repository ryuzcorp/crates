//! Git LFS batch and basic-transfer routes over [`LfsStore`].
//!
//! Authentication reuses [`GitHooks::authorize`]:
//! downloads need [`Access::View`], uploads need [`Access::Push`]. The batch
//! response is produced by [`LfsStore`]; the object routes perform the actual
//! basic transfer (`PUT` streams and verifies, `GET` streams back).

use std::collections::HashMap;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Path as AxumPath, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use futures::StreamExt as _;

use crate::lfs::{BatchRequest, LfsError, LfsStore, Operation, LFS_CONTENT_TYPE};
use crate::manifest::ManifestCodec;
use crate::store::{ByteStream, StoreError};

use super::{Access, GitHooks, GitHttp};

/// Check the static token and the application hooks for one LFS request.
async fn gate<C, H>(
    state: &GitHttp<C, H>,
    headers: &HeaderMap,
    slug: &str,
    need: Access,
) -> Result<(), Box<Response>>
where
    C: ManifestCodec + 'static,
    H: GitHooks + 'static,
{
    if let Err(error) = state.auth.check(headers, need) {
        return Err(Box::new(error.into_response()));
    }
    if let Err(error) = state.hooks.authorize(slug, need).await {
        return Err(Box::new(error.into_response()));
    }
    Ok(())
}

fn lfs_store<C, H>(state: &GitHttp<C, H>) -> Result<LfsStore, Box<Response>>
where
    C: ManifestCodec,
    H: GitHooks,
{
    state.lfs.clone().ok_or_else(|| {
        Box::new((StatusCode::NOT_FOUND, "LFS is not enabled for this server").into_response())
    })
}

fn lfs_error(error: LfsError) -> Response {
    let status = StatusCode::from_u16(error.status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let body = serde_json::to_vec(&error.body()).unwrap_or_default();
    (status, [(header::CONTENT_TYPE, LFS_CONTENT_TYPE)], body).into_response()
}

fn json_response<T: serde::Serialize>(value: &T) -> Response {
    match serde_json::to_vec(value) {
        Ok(body) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, LFS_CONTENT_TYPE)],
            body,
        )
            .into_response(),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("could not encode LFS response: {error}"),
        )
            .into_response(),
    }
}

fn stream_body(body: ByteStream) -> Body {
    Body::from_stream(body)
}

/// `POST /{repo}/info/lfs/objects/batch`.
pub async fn batch<C, H>(
    State(state): State<Arc<GitHttp<C, H>>>,
    AxumPath(params): AxumPath<HashMap<String, String>>,
    headers: HeaderMap,
    Json(request): Json<BatchRequest>,
) -> Response
where
    C: ManifestCodec + 'static,
    H: GitHooks + 'static,
{
    let slug = match super::repo_from_params(&params) {
        Ok(slug) => slug,
        Err(error) => return error.into_response(),
    };
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    if !content_type.starts_with(LFS_CONTENT_TYPE) && !content_type.starts_with("application/json")
    {
        return (
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            format!("LFS batch requires {LFS_CONTENT_TYPE}"),
        )
            .into_response();
    }
    let need = match request.operation {
        Operation::Download => Access::View,
        Operation::Upload => Access::Push,
    };
    if let Err(response) = gate(&state, &headers, &slug, need).await {
        return *response;
    }
    let lfs = match lfs_store(&state) {
        Ok(lfs) => lfs,
        Err(response) => return *response,
    };
    match lfs.batch(&slug, request).await {
        Ok(response) => json_response(&response),
        Err(error) => lfs_error(error),
    }
}

/// `GET /{repo}/lfs/objects/{oid}`.
pub async fn download<C, H>(
    State(state): State<Arc<GitHttp<C, H>>>,
    AxumPath(params): AxumPath<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response
where
    C: ManifestCodec + 'static,
    H: GitHooks + 'static,
{
    let slug = match super::repo_from_params(&params) {
        Ok(slug) => slug,
        Err(error) => return error.into_response(),
    };
    let oid = match params.get("oid") {
        Some(oid) => oid.clone(),
        None => return (StatusCode::NOT_FOUND, "missing object id").into_response(),
    };
    if let Err(response) = gate(&state, &headers, &slug, Access::View).await {
        return *response;
    }
    let lfs = match lfs_store(&state) {
        Ok(lfs) => lfs,
        Err(response) => return *response,
    };
    match lfs.download(&slug, &oid).await {
        Ok((meta, body)) => {
            let mut response = Response::new(stream_body(body));
            let headers = response.headers_mut();
            headers.insert(
                header::CONTENT_TYPE,
                header::HeaderValue::from_static("application/octet-stream"),
            );
            if let Ok(value) = header::HeaderValue::from_str(&meta.size.to_string()) {
                headers.insert(header::CONTENT_LENGTH, value);
            }
            if let Some(checksum) = &meta.checksum {
                if let Ok(value) = header::HeaderValue::from_str(checksum) {
                    headers.insert(header::ETAG, value);
                }
            }
            response
        }
        Err(error) => lfs_error(error),
    }
}

/// `PUT /{repo}/lfs/objects/{oid}`.
pub async fn upload<C, H>(
    State(state): State<Arc<GitHttp<C, H>>>,
    AxumPath(params): AxumPath<HashMap<String, String>>,
    headers: HeaderMap,
    body: Body,
) -> Response
where
    C: ManifestCodec + 'static,
    H: GitHooks + 'static,
{
    let slug = match super::repo_from_params(&params) {
        Ok(slug) => slug,
        Err(error) => return error.into_response(),
    };
    let oid = match params.get("oid") {
        Some(oid) => oid.clone(),
        None => return (StatusCode::NOT_FOUND, "missing object id").into_response(),
    };
    if let Err(response) = gate(&state, &headers, &slug, Access::Push).await {
        return *response;
    }
    let lfs = match lfs_store(&state) {
        Ok(lfs) => lfs,
        Err(response) => return *response,
    };
    let size = match headers
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
    {
        Some(size) => size,
        None => {
            return (
                StatusCode::LENGTH_REQUIRED,
                "LFS upload requires Content-Length",
            )
                .into_response()
        }
    };
    let stream: ByteStream = Box::pin(
        body.into_data_stream()
            .map(|chunk| chunk.map_err(|error| StoreError::Other(anyhow::anyhow!(error)))),
    );
    match lfs.upload(&slug, &oid, size, stream).await {
        Ok(_meta) => StatusCode::OK.into_response(),
        Err(error) => lfs_error(error),
    }
}
