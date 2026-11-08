//! Immutable publish log.
//!
//! One segment object holds a JSON array of entries for a contiguous batch of
//! sequence numbers. Segments are immutable; a publish writes one with
//! `PutMode::Create` before CASing the manifest. Sequence numbers strictly
//! increase and may skip (a burned CAS), so readers must not assume density.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::{GitError, WalError};
use crate::manifest::{CheckpointRef, LogSegmentRef};
use crate::store::{DynStore, ObjectStoreExt, PutBody, PutMode, PutOptions};

/// What a batch did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogKind {
    /// One or more refs moved (a push or a programmatic publish).
    Push,
    /// A ref-only transfer outside a push (mirror/import).
    RefUpdate,
    /// Compaction retired the previous pack set.
    Compact,
    /// The log was folded into a checkpoint.
    Checkpoint,
    /// `publish_settings` replaced the repository setting.
    Settings,
}

/// One ref change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TxnKind {
    Create,
    Update,
    Delete,
}

/// One ref that changed in a batch. A ref whose tip is unchanged has no txn.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogTxn {
    pub refname: String,
    /// Tip before the batch; `None` on create.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub old: Option<String>,
    /// Tip after the batch; `None` on delete.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new: Option<String>,
    pub kind: TxnKind,
}

impl LogTxn {
    pub fn change(refname: impl Into<String>, old: Option<String>, new: Option<String>) -> Self {
        let kind = match (&old, &new) {
            (None, Some(_)) => TxnKind::Create,
            (Some(_), None) => TxnKind::Delete,
            _ => TxnKind::Update,
        };
        Self {
            refname: refname.into(),
            old,
            new,
            kind,
        }
    }
}

/// The pack a pack-mode batch uploaded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogPack {
    pub checksum: String,
    pub pack_size: u64,
    pub idx_size: u64,
    pub object_count: u64,
    #[serde(default)]
    pub has_rev: bool,
    #[serde(default)]
    pub has_bitmap: bool,
}

/// One committed publish.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogEntry {
    /// Strictly increasing across the repository, not necessarily dense.
    pub seq: u64,
    pub kind: LogKind,
    /// Empty for `Settings`/`Compact`/`Checkpoint` entries; a ref whose tip
    /// did not change is never logged.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub txns: Vec<LogTxn>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pack: Option<LogPack>,
    /// Bundle or pack keys this batch superseded.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub supersedes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint: Option<CheckpointRef>,
    /// RFC 3339 UTC.
    pub created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub writer: Option<String>,
    /// Free-form annotations (`head`, `settings.revision`, ...).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub meta: BTreeMap<String, String>,
}

/// Compare two ref maps and produce the transaction list.
///
/// A ref present in both with the same sha is omitted: no-ops are not logged.
pub fn classify_txns(
    before: &BTreeMap<String, String>,
    after: &BTreeMap<String, String>,
) -> Vec<LogTxn> {
    let mut names: Vec<&String> = before.keys().chain(after.keys()).collect();
    names.sort();
    names.dedup();
    let mut txns = Vec::new();
    for refname in names {
        let old = before.get(refname);
        let new = after.get(refname);
        if old == new {
            continue;
        }
        txns.push(LogTxn::change(refname, old.cloned(), new.cloned()));
    }
    txns
}

/// Current time as RFC 3339 UTC.
pub fn now_rfc3339() -> String {
    super::now_rfc3339()
}

/// Encode entries as one JSON array (the segment body).
pub fn encode(entries: &[LogEntry]) -> Result<Vec<u8>, GitError> {
    serde_json::to_vec(entries).map_err(|error| GitError::Protocol(format!("log encode: {error}")))
}

/// Decode a segment body. A partial trailing frame is an error; segments are
/// only published after the whole batch is written.
pub fn decode(bytes: &[u8]) -> Result<Vec<LogEntry>, GitError> {
    serde_json::from_slice(bytes)
        .map_err(|error| GitError::Protocol(format!("log decode: {error}")))
}

fn check_order(entries: &[LogEntry]) -> Result<(), WalError> {
    let mut previous: Option<u64> = None;
    for entry in entries {
        if let Some(previous) = previous {
            if entry.seq <= previous {
                return Err(WalError::Corrupt(format!(
                    "log entry seq {} does not follow {previous}",
                    entry.seq
                )));
            }
        }
        previous = Some(entry.seq);
    }
    Ok(())
}

/// Write one segment with `PutMode::Create`.
pub(crate) async fn write_segment(
    store: &DynStore,
    key: &str,
    entries: &[LogEntry],
) -> Result<LogSegmentRef, WalError> {
    if entries.is_empty() {
        return Err(WalError::Corrupt(
            "refusing to write an empty log segment".into(),
        ));
    }
    check_order(entries)?;
    let bytes = encode(entries)?;
    let size = bytes.len() as u64;
    let first_seq = entries
        .first()
        .map(|entry| entry.seq)
        .ok_or_else(|| WalError::Corrupt("refusing to write an empty log segment".into()))?;
    let last_seq = entries
        .last()
        .map(|entry| entry.seq)
        .ok_or_else(|| WalError::Corrupt("refusing to write an empty log segment".into()))?;
    store
        .put(
            key,
            PutBody::Bytes(bytes.into()),
            PutOptions {
                mode: PutMode::Create,
                content_type: Some("application/json"),
                immutable: true,
            },
        )
        .await?;
    Ok(LogSegmentRef {
        key: key.to_string(),
        first_seq,
        last_seq,
        size,
        sealed: true,
    })
}

/// Read and validate one immutable segment.
pub(crate) async fn read_segment(
    store: &DynStore,
    segment: &LogSegmentRef,
) -> Result<Vec<LogEntry>, WalError> {
    let Some((_, bytes)) = store.get_bytes(&segment.key).await? else {
        return Err(WalError::Corrupt(format!(
            "log segment {} named by the manifest is missing",
            segment.key
        )));
    };
    let entries = decode(&bytes)?;
    check_order(&entries)?;
    if let (Some(first), Some(last)) = (entries.first(), entries.last()) {
        if first.seq != segment.first_seq || last.seq != segment.last_seq {
            return Err(WalError::Corrupt(format!(
                "log segment {} covers {}..{} but the manifest names {}..{}",
                segment.key, first.seq, last.seq, segment.first_seq, segment.last_seq
            )));
        }
    }
    Ok(entries)
}

/// Every entry with `from < seq <= to`, in sequence order.
///
/// Segments are read in `first_seq` order; a gap (burned sequence) is not an
/// error. A segment named by the manifest that cannot be read is an error, never
/// an empty range.
pub(crate) async fn read_range(
    store: &DynStore,
    segments: &[LogSegmentRef],
    from: u64,
    to: u64,
) -> Result<Vec<LogEntry>, WalError> {
    if to <= from {
        return Ok(Vec::new());
    }
    let mut candidates: Vec<&LogSegmentRef> = segments
        .iter()
        .filter(|segment| segment.last_seq > from && segment.first_seq <= to)
        .collect();
    candidates.sort_by_key(|segment| segment.first_seq);
    let mut out = Vec::new();
    let mut previous: Option<u64> = None;
    for segment in candidates {
        for entry in read_segment(store, segment).await? {
            if entry.seq <= from || entry.seq > to {
                continue;
            }
            if let Some(previous) = previous {
                if entry.seq <= previous {
                    return Err(WalError::Corrupt(format!(
                        "log seq {} is not after {previous}",
                        entry.seq
                    )));
                }
            }
            previous = Some(entry.seq);
            out.push(entry);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(seq: u64) -> LogEntry {
        LogEntry {
            seq,
            kind: LogKind::Push,
            txns: vec![LogTxn::change(
                "refs/heads/main",
                None,
                Some("a".repeat(40)),
            )],
            pack: None,
            supersedes: Vec::new(),
            checkpoint: None,
            created_at: "2026-01-01T00:00:00Z".into(),
            writer: Some("test".into()),
            meta: BTreeMap::new(),
        }
    }

    #[tokio::test]
    async fn segment_roundtrip_and_range_filter() {
        let store: DynStore = std::sync::Arc::new(crate::store::MemoryStore::new());
        let first = write_segment(&store, "git/demo/log/1.json", &[entry(1), entry(2)])
            .await
            .unwrap();
        let second = write_segment(&store, "git/demo/log/3.json", &[entry(3)])
            .await
            .unwrap();
        assert_eq!((first.first_seq, first.last_seq), (1, 2));
        assert_eq!((second.first_seq, second.last_seq), (3, 3));
        let segments = vec![first, second];
        let read = read_range(&store, &segments, 1, 3).await.unwrap();
        assert_eq!(
            read.iter().map(|entry| entry.seq).collect::<Vec<_>>(),
            vec![2, 3]
        );
        assert!(read_range(&store, &segments, 5, 9)
            .await
            .unwrap()
            .is_empty());
        assert!(read_range(&store, &segments, 2, 2)
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn create_only_and_missing_segments_are_errors() {
        let store: DynStore = std::sync::Arc::new(crate::store::MemoryStore::new());
        let segment = write_segment(&store, "log/1.json", &[entry(1)])
            .await
            .unwrap();
        let again = write_segment(&store, "log/1.json", &[entry(1)]).await;
        assert!(matches!(
            again,
            Err(WalError::Store(error)) if error.is_precondition_failed()
        ));
        store.delete(&segment.key, None).await.unwrap();
        let error = read_segment(&store, &segment).await.unwrap_err();
        assert!(matches!(error, WalError::Corrupt(_)), "{error}");
    }

    #[test]
    fn unordered_segments_are_refused() {
        assert!(check_order(&[entry(2), entry(1)]).is_err());
        assert!(decode(br#"[]"#).unwrap().is_empty());
        assert!(decode(br#"[{"seq":1}]"#).is_err());
    }

    #[test]
    fn classification_skips_no_ops() {
        let before = BTreeMap::from([
            ("refs/heads/main".to_string(), "a".repeat(40)),
            ("refs/heads/gone".to_string(), "b".repeat(40)),
        ]);
        let after = BTreeMap::from([
            ("refs/heads/main".to_string(), "c".repeat(40)),
            ("refs/heads/new".to_string(), "d".repeat(40)),
        ]);
        let txns = classify_txns(&before, &after);
        assert_eq!(txns.len(), 3);
        assert_eq!(txns[0].refname, "refs/heads/gone");
        assert_eq!(txns[0].kind, TxnKind::Delete);
        assert_eq!(txns[1].kind, TxnKind::Update);
        assert_eq!(txns[2].kind, TxnKind::Create);
        assert!(classify_txns(&after, &after).is_empty());
    }
}
