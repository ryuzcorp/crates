//! `git-receive-pack`: authorize, evaluate policy, run stock git, persist.
//!
//! The receive request head is parsed before authorization so an unreadable
//! body can never reach git with every check skipped. The slug lock is held
//! from the post-authorization policy checks through `git receive-pack` and
//! the manifest flip, so a concurrent push to the same repository cannot
//! interleave. In pack mode the incoming pack is indexed into the mirror before
//! git runs and handed to the WAL so the manifest can name it.

use std::collections::HashMap;
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path as AxumPath, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};

use crate::config::{ObjectFormat, StorageMode};
use crate::git::ingest::{ingest_pack, IngestOptions};
use crate::git::protocol::pkt_line;
use crate::git::receive::{parse_receive, ReceiveRequest};
use crate::git::{is_ancestor, is_full_sha, snapshot_refs, validate_refname};
use crate::manifest::ManifestCodec;

use super::smart::forbidden;
use super::{git_response, internal, Access, GitHooks, GitHttp, PushPolicyContext, Role};

/// `git receive-pack --stateless-rpc` can move a whole repository.
const RECEIVE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

/// The sideband channel git's demuxer prints as `remote: ` lines.
const SIDE_BAND_PROGRESS: u8 = 2;

/// `POST /{repo}/git-receive-pack`.
pub async fn receive_pack<C, H>(
    State(state): State<Arc<GitHttp<C, H>>>,
    AxumPath(params): AxumPath<HashMap<String, String>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response
where
    C: ManifestCodec + 'static,
    H: GitHooks + 'static,
{
    // The parsed head IS the policy input: refuse an unreadable body before
    // authorization, never hand it to git unchecked.
    let request = match parse_receive(&body) {
        Ok(request) if !request.commands.is_empty() => request,
        Ok(_) => return (StatusCode::FORBIDDEN, "refused: empty push").into_response(),
        Err(error) => {
            tracing::warn!(%error, "receive-pack: unparseable request head");
            return (
                StatusCode::FORBIDDEN,
                "refused: the push request could not be parsed",
            )
                .into_response();
        }
    };
    let slug = match super::repo_from_params(&params) {
        Ok(slug) => slug,
        Err(error) => return error.into_response(),
    };
    if let Err(error) = state.auth.check(&headers, Access::Push) {
        return error.into_response();
    }
    let grant = match state.hooks.authorize(&slug, Access::Push).await {
        Ok(grant) => grant,
        Err(error) => return error.into_response(),
    };
    let role = grant.role;
    if !role.can_push() {
        return forbidden(format!(
            "rule push-policy: role {} may not push",
            role.as_str()
        ));
    }
    if request.commands.len() > state.config.limits.max_push_refs {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            format!(
                "refusing {} ref updates; the limit is {}",
                request.commands.len(),
                state.config.limits.max_push_refs
            ),
        )
            .into_response();
    }
    if let Err(message) = validate_commands(&request, state.config.object_format) {
        return forbidden(message);
    }
    if let Some(format) = &request.caps.object_format {
        if format != state.config.object_format.as_str() {
            return forbidden(format!(
                "refused: client speaks object-format {format}, this repository uses {}",
                state.config.object_format
            ));
        }
    }
    let wal = state.wal();
    let policy = match wal.read_policy(&slug).await {
        Ok(policy) => policy,
        Err(error) => return super::wal_response(error),
    };
    if let Some(policy) = &state.policy {
        let context = PushPolicyContext {
            repo: &slug,
            role,
            commands: &request.commands,
            push_options: &request.push_options,
        };
        if let Err(message) = policy.evaluate(context).await {
            return forbidden(message);
        }
    }
    if let Err(message) = state.hooks.check_push(&slug, role, &request.commands).await {
        return forbidden(message);
    }
    if let Err(message) = state
        .hooks
        .check_branch_protection(&slug, role, &request.commands)
        .await
    {
        return forbidden(message);
    }

    // One push per repository slot, then the WAL lock. The slot is held across
    // the policy checks above only after it was granted, so ordering is
    // permit -> slug lock -> (git, WAL).
    let _permit = state.pushes.acquire(&slug).await;
    let guard: tokio::sync::OwnedMutexGuard<()> = state.sync.lock(&slug).await;
    let bare = match wal.ensure_synced_locked(&slug).await {
        Ok(bare) => bare,
        Err(error) => return super::wal_response(error),
    };
    // Policy needs to know which updates force history. Compute that against
    // the freshly synced mirror, then evaluate once; the same flags drive the
    // non-admin fast-forward refusal below.
    let mut updates = Vec::with_capacity(request.commands.len());
    for command in &request.commands {
        let old = if is_zero_oid(&command.old, state.config.object_format) {
            None
        } else {
            Some(command.old.clone())
        };
        let new = if is_zero_oid(&command.new, state.config.object_format) {
            None
        } else {
            Some(command.new.clone())
        };
        let force = match (&old, &new) {
            (Some(old), Some(new)) => !is_ancestor(&bare, old, new).await,
            _ => false,
        };
        updates.push(crate::policy::Update::new(
            command.refname.clone(),
            old,
            new,
            force,
        ));
    }
    let context = crate::policy::PushContext {
        principal: grant.principal(),
        tags: &grant.tags,
        updates: &updates,
    };
    if let Err(error) = crate::policy::evaluate_push(&policy, &context) {
        return forbidden(error.to_string());
    }
    if role != Role::Admin {
        for update in &updates {
            if update.force {
                return forbidden(format!(
                    "rule push-policy: 'push' may not force-push {} (admin only)",
                    update.refname
                ));
            }
        }
    }
    let before = match snapshot_refs(&bare, &state.config.extra_ref_prefixes).await {
        Ok(snapshot) => snapshot,
        Err(error) => return git_response(error),
    };
    let default_ref = format!("refs/heads/{}", state.config.default_branch);
    let first_push = !before.refs.contains_key(&default_ref);

    // Index the incoming pack now (pack mode) so the bytes are durable in the
    // mirror and the WAL can name them, while git still performs the protocol
    // handshake and ref update below.
    let pack_bytes = body.get(request.pack_offset..).unwrap_or_default();
    let ingested = if state.config.storage == StorageMode::Pack && pack_bytes.starts_with(b"PACK") {
        if pack_bytes.len() as u64 > state.config.limits.max_push_bytes {
            return (
                StatusCode::PAYLOAD_TOO_LARGE,
                format!(
                    "pack is {} bytes; the limit is {}",
                    pack_bytes.len(),
                    state.config.limits.max_push_bytes
                ),
            )
                .into_response();
        }
        match ingest_pack(
            &bare,
            pack_bytes,
            &IngestOptions {
                fsck: true,
                max_bytes: Some(state.config.limits.max_push_bytes),
                thin: true,
            },
        )
        .await
        {
            Ok(pack) => pack,
            Err(error) => return ingest_response(error),
        }
    } else {
        None
    };

    let Some(bare_arg) = bare.to_str() else {
        return internal("bare mirror path is not valid UTF-8");
    };
    let mut argv: Vec<String> = Vec::new();
    if role != Role::Admin {
        // Defense in depth: git itself refuses non-fast-forward updates and
        // deletions below admin, so a divergence between our parser and git's
        // cannot become a force-push or a delete.
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
    argv.extend(
        [
            "receive-pack",
            "--stateless-rpc",
            bare_arg,
            // Advertise nothing hidden by configuration; the mirror already
            // carries uploadpack.hideRefs/transfer.hideRefs.
        ]
        .map(str::to_string),
    );
    let argv: Vec<&str> = argv.iter().map(String::as_str).collect();
    let mut out = match crate::git::run_git_stdin(&argv, &body, &[], RECEIVE_TIMEOUT).await {
        Ok(out) => out,
        Err(error) => return git_response(error),
    };

    let outcome = match wal.record_push_locked(&slug, &before, ingested).await {
        Ok(outcome) => outcome,
        Err(error) => {
            tracing::error!(%slug, error = %error, "receive-pack: WAL write failed");
            return (StatusCode::CONFLICT, format!("{error:#}")).into_response();
        }
    };
    // The WAL guard ends here; a hook may touch other repositories and must
    // not inherit this slug's lock.
    drop(guard);
    state.hooks.refs_moved(&slug, &outcome).await;
    if let Some(note) = state.hooks.note_push(&slug, first_push) {
        if request.caps.side_band_64k {
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

/// A zero object id (`new` = deletion, `old` = creation).
fn is_zero_oid(oid: &str, format: ObjectFormat) -> bool {
    oid.len() == format.hex_len() && oid.bytes().all(|byte| byte == b'0')
}

/// Reject refnames and object ids that are not exactly what git would use.
fn validate_commands(request: &ReceiveRequest, format: ObjectFormat) -> Result<(), String> {
    for command in &request.commands {
        if let Err(error) = validate_refname(&command.refname) {
            return Err(format!("refused: {error}"));
        }
        let old_ok = is_zero_oid(&command.old, format) || is_full_sha(&command.old, format);
        let new_ok = is_zero_oid(&command.new, format) || is_full_sha(&command.new, format);
        if !old_ok || !new_ok {
            return Err(format!(
                "refused: {} has an invalid object id",
                command.refname
            ));
        }
        if command.refname == "HEAD" {
            return Err("refused: pushing HEAD is not allowed".to_string());
        }
    }
    Ok(())
}

/// Map an ingest failure to a client-visible status.
fn ingest_response(error: crate::error::GitError) -> Response {
    match &error {
        crate::error::GitError::InvalidInput(_) => {
            (StatusCode::PAYLOAD_TOO_LARGE, error.to_string()).into_response()
        }
        crate::error::GitError::Pack(_) | crate::error::GitError::Fsck(_) => {
            (StatusCode::UNPROCESSABLE_ENTITY, error.to_string()).into_response()
        }
        _ => git_response(error),
    }
}

/// Append sideband progress lines before the final flush packet. The client
/// stops reading at the flush, so a packet after it would never print.
fn with_notes(out: Vec<u8>, notes: &[String]) -> Vec<u8> {
    let flush = b"0000";
    let Some(body) = out.strip_suffix(flush) else {
        return out;
    };
    let mut merged = body.to_vec();
    for note in notes {
        let mut payload = vec![SIDE_BAND_PROGRESS];
        payload.extend_from_slice(note.as_bytes());
        payload.push(b'\n');
        merged.extend_from_slice(&pkt_line(&payload));
    }
    merged.extend_from_slice(flush);
    merged
}

/// Helper for tests: the sideband note framing used here.
#[cfg(test)]
pub(crate) fn sideband_note(note: &str) -> Vec<u8> {
    pkt_line(format!("\u{2}{note}\n").as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkt(payload: &[u8]) -> Vec<u8> {
        let total = payload.len() + 4;
        let mut out = format!("{total:04x}").into_bytes();
        out.extend_from_slice(payload);
        out
    }

    fn request(body: &[u8]) -> ReceiveRequest {
        parse_receive(body).unwrap()
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
    fn sideband_note_uses_channel_two() {
        let note = sideband_note("hello");
        assert_eq!(note[4], SIDE_BAND_PROGRESS);
        assert!(note.ends_with(b"hello\n"));
    }

    #[test]
    fn commands_are_validated() {
        let mut body = pkt(format!(
            "{} {} refs/heads/main\0report-status\n",
            "a".repeat(40),
            "b".repeat(40)
        )
        .as_bytes());
        body.extend_from_slice(b"0000");
        assert!(validate_commands(&request(&body), ObjectFormat::Sha1).is_ok());

        let mut bad_ref = pkt(format!(
            "{} {} refs/../escape\0report-status\n",
            "a".repeat(40),
            "b".repeat(40)
        )
        .as_bytes());
        bad_ref.extend_from_slice(b"0000");
        assert!(parse_receive(&bad_ref).is_err());

        let mut bad_oid = pkt(format!("abc {} refs/heads/main\n", "b".repeat(40)).as_bytes());
        bad_oid.extend_from_slice(b"0000");
        assert!(parse_receive(&bad_oid).is_err());
    }
}
