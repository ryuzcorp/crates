//! Checkpoints: a folded refs snapshot plus the metadata that makes it
//! replayable.
//!
//! A checkpoint is immutable, content addressed by the sequence it folds
//! through. Writing one is three steps:
//!
//! 1. the refs snapshot at [`crate::config::Layout::checkpoint_refs_key`],
//! 2. the checkpoint metadata at [`crate::config::Layout::checkpoint_key`],
//! 3. one CAS manifest write that points `checkpoint` at both objects and
//!    drops the log segments folded at that sequence.
//!
//! Steps 1 and 2 use `Create`, so a retry after a lost CAS sees its own bytes
//! and proceeds; steps 3 is the only commit point. A manifest whose checkpoint
//! already names the current sequence is left untouched.

use std::collections::BTreeMap;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::config::WalConfig;
use crate::error::{StoreError, WalError};
use crate::manifest::{CheckpointRef, LogSegmentRef, ManifestCodec, ManifestState, PackRef};
use crate::store::{ObjectStoreExt as _, PutBody, PutMode, PutOptions};
use crate::wal::Wal;

/// A folded refs snapshot.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    /// Highest log sequence folded into this snapshot.
    pub seq: u64,
    /// Every ref tip at `seq`.
    #[serde(default)]
    pub refs: BTreeMap<String, String>,
    /// Symbolic `HEAD` target.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub head: Option<String>,
    /// Peeled tag targets.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub peeled: BTreeMap<String, String>,
    /// Live packs at `seq`, so a reader can rehydrate from the checkpoint.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub packs: Vec<PackRef>,
}

impl Checkpoint {
    pub fn refs_len(&self) -> usize {
        self.refs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.refs.is_empty()
    }
}

/// Folded state produced by [`fold_state`]: the snapshot plus the log tail
/// after it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CheckpointState {
    /// Manifest pointer this state came from, when any.
    pub checkpoint: Option<CheckpointRef>,
    pub refs: BTreeMap<String, String>,
    pub head: Option<String>,
    pub peeled: BTreeMap<String, String>,
    pub packs: Vec<PackRef>,
    /// Highest sequence applied (checkpoint and tail included).
    pub seq: u64,
}

impl CheckpointState {
    pub fn from_checkpoint(checkpoint: &Checkpoint) -> Self {
        Self {
            checkpoint: None,
            refs: checkpoint.refs.clone(),
            head: checkpoint.head.clone(),
            peeled: checkpoint.peeled.clone(),
            packs: checkpoint.packs.clone(),
            seq: checkpoint.seq,
        }
    }
}

/// One ref change recovered from a log entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoldChange {
    pub refname: String,
    /// `None` deletes the ref.
    pub new_sha: Option<String>,
}

impl FoldChange {
    pub fn set(refname: impl Into<String>, sha: impl Into<String>) -> Self {
        Self {
            refname: refname.into(),
            new_sha: Some(sha.into()),
        }
    }

    pub fn delete(refname: impl Into<String>) -> Self {
        Self {
            refname: refname.into(),
            new_sha: None,
        }
    }
}

/// What a log entry must expose to be foldable.
///
/// Implemented by the WAL's log entry type; tests can implement it for a
/// minimal stand-in.
pub trait FoldEntry {
    fn seq(&self) -> u64;
    fn changes(&self) -> Vec<FoldChange>;
}

impl FoldEntry for crate::wal::log::LogEntry {
    fn seq(&self) -> u64 {
        self.seq
    }

    fn changes(&self) -> Vec<FoldChange> {
        self.txns
            .iter()
            .map(|txn| FoldChange {
                refname: txn.refname.clone(),
                new_sha: match txn.kind {
                    crate::wal::log::TxnKind::Delete => None,
                    _ => txn.new.clone(),
                },
            })
            .collect()
    }
}

/// Apply a checkpoint and then every log entry newer than it.
///
/// Entries at or below `checkpoint.seq` are already folded and are ignored, so
/// callers may pass a segment that overlaps the checkpoint. Entry order is
/// preserved (the log is ordered).
pub fn fold_state<L: FoldEntry>(checkpoint: Option<&Checkpoint>, entries: &[L]) -> CheckpointState {
    let mut state = match checkpoint {
        Some(checkpoint) => CheckpointState::from_checkpoint(checkpoint),
        None => CheckpointState::default(),
    };
    let folded_through = state.seq;
    for entry in entries {
        if entry.seq() <= folded_through && checkpoint.is_some() {
            continue;
        }
        for change in entry.changes() {
            match change.new_sha {
                Some(sha) => {
                    state.refs.insert(change.refname, sha);
                }
                None => {
                    state.refs.remove(&change.refname);
                }
            }
        }
        state.seq = state.seq.max(entry.seq());
    }
    state
}

/// Fold the checkpoint plus the unfolded tail of the manifest's log.
///
/// The tail is expressed by segment metadata only; no segment bytes are read.
pub async fn folded_state<C: ManifestCodec>(
    wal: &Wal<C>,
    slug: &str,
) -> Result<CheckpointState, WalError> {
    let Some((manifest, _)) = wal.load_manifest(slug).await? else {
        return Err(WalError::NotFound(slug.to_string()));
    };
    let state = wal.codec().state(&manifest);
    let checkpoint = match &state.checkpoint {
        Some(reference) => read_checkpoint(wal, slug, reference.seq).await?,
        None => None,
    };
    let from = checkpoint
        .as_ref()
        .map(|checkpoint| checkpoint.seq.saturating_add(1))
        .unwrap_or(0);
    let entries = if from <= state.seq {
        wal.read_log(slug, from, Some(state.seq)).await?
    } else {
        Vec::new()
    };
    let mut folded = fold_state(checkpoint.as_ref(), &entries);
    folded.checkpoint = state.checkpoint.clone();
    folded.head = state.head.clone();
    folded.peeled = state.peeled.clone();
    folded.packs = state.packs.clone();
    folded.seq = state.seq;
    Ok(folded)
}

/// Read the checkpoint at `seq`. `None` when the metadata object is absent.
pub async fn read_checkpoint<C: ManifestCodec>(
    wal: &Wal<C>,
    slug: &str,
    seq: u64,
) -> Result<Option<Checkpoint>, WalError> {
    let layout = &wal.config().layout;
    let key = layout.checkpoint_key(slug, seq);
    let Some((_, bytes)) = wal.store().get_bytes(&key).await? else {
        return Ok(None);
    };
    let mut checkpoint: Checkpoint = serde_json::from_slice(&bytes)?;
    checkpoint.seq = checkpoint.seq.max(seq);
    let refs_key = layout.checkpoint_refs_key(slug, seq);
    if let Some((_, refs)) = wal.store().get_bytes(&refs_key).await? {
        checkpoint.refs = serde_json::from_slice(&refs)?;
    }
    Ok(Some(checkpoint))
}

/// Read the checkpoint the manifest currently points at.
pub async fn read_current_checkpoint<C: ManifestCodec>(
    wal: &Wal<C>,
    slug: &str,
) -> Result<Option<Checkpoint>, WalError> {
    let Some(manifest) = wal.read_manifest(slug).await? else {
        return Err(WalError::NotFound(slug.to_string()));
    };
    let state = wal.codec().state(&manifest);
    match state.checkpoint {
        Some(reference) => read_checkpoint(wal, slug, reference.seq).await,
        None => Ok(None),
    }
}

/// Whether a checkpoint is due, from configuration and the unfolded tail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckpointTrigger {
    /// Unfolded entries after which a checkpoint is due. 0 disables.
    pub entries: u64,
    /// Wall-clock age after which a checkpoint is due. ZERO disables.
    pub interval: Duration,
    /// Unfolded log bytes after which a checkpoint is due. 0 disables.
    pub tail_bytes: u64,
}

impl CheckpointTrigger {
    pub fn from_config(config: &WalConfig) -> Self {
        Self {
            entries: config.checkpoint_every_entries,
            interval: config.checkpoint_interval,
            tail_bytes: config.checkpoint_tail_bytes,
        }
    }

    pub fn is_due(&self, tail: &LogTail, elapsed: Duration) -> bool {
        (self.entries > 0 && tail.entries >= self.entries)
            || (self.tail_bytes > 0 && tail.bytes >= self.tail_bytes)
            || (!self.interval.is_zero() && elapsed >= self.interval)
    }
}

/// Size of the log that is not folded into the current checkpoint.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LogTail {
    pub entries: u64,
    pub bytes: u64,
    pub first_seq: Option<u64>,
    pub last_seq: Option<u64>,
}

/// Measure the unfolded tail of `state`.
pub fn unfolded_tail(state: &ManifestState) -> LogTail {
    let folded = state.checkpoint.as_ref().map(|checkpoint| checkpoint.seq);
    let mut tail = LogTail::default();
    for segment in &state.log {
        if let Some(folded) = folded {
            if segment.last_seq <= folded {
                continue;
            }
        }
        tail.entries = tail.entries.saturating_add(
            segment
                .last_seq
                .saturating_sub(segment.first_seq)
                .saturating_add(1),
        );
        tail.bytes = tail.bytes.saturating_add(segment.size);
        tail.first_seq = Some(match tail.first_seq {
            Some(first) => first.min(segment.first_seq),
            None => segment.first_seq,
        });
        tail.last_seq = Some(match tail.last_seq {
            Some(last) => last.max(segment.last_seq),
            None => segment.last_seq,
        });
    }
    tail
}

/// Write a checkpoint for the manifest's current sequence and trim the log it
/// covered. Returns `None` only when the repository has no manifest (an error)
/// — otherwise the effective checkpoint reference, including the idempotent
/// case where one already points at `seq`.
pub async fn write_checkpoint<C: ManifestCodec>(
    wal: &Wal<C>,
    slug: &str,
) -> Result<Option<CheckpointRef>, WalError> {
    let attempts = wal.config().publish_retries.max(1);
    for _ in 0..attempts {
        let Some((manifest, version)) = wal.load_manifest(slug).await? else {
            return Err(WalError::NotFound(slug.to_string()));
        };
        let state = wal.codec().state(&manifest);
        if let Some(existing) = &state.checkpoint {
            if existing.seq >= state.seq {
                return Ok(Some(existing.clone()));
            }
        }
        let seq = state.seq;
        let checkpoint = build_checkpoint(&state, seq);
        let layout = &wal.config().layout;
        let refs_key = layout.checkpoint_refs_key(slug, seq);
        let key = layout.checkpoint_key(slug, seq);
        put_immutable_json(wal, &refs_key, &checkpoint.refs).await?;
        put_immutable_json(wal, &key, &checkpoint).await?;

        let reference = CheckpointRef { seq, key, refs_key };
        let mut next = state.clone();
        next.checkpoint = Some(reference.clone());
        next.log.retain(|segment| segment.last_seq > seq);
        let next_manifest = wal.codec().from_state(next)?;
        match wal
            .write_manifest(slug, &next_manifest, PutMode::Update(version))
            .await
        {
            Ok(_) => return Ok(Some(reference)),
            Err(WalError::Store(error)) if error.is_precondition_failed() => continue,
            Err(error) => return Err(error),
        }
    }
    Err(WalError::RetryExhausted {
        slug: slug.to_string(),
        attempts,
    })
}

fn build_checkpoint(state: &ManifestState, seq: u64) -> Checkpoint {
    Checkpoint {
        seq,
        refs: state
            .refs
            .iter()
            .map(|(refname, entry)| (refname.clone(), entry.sha.clone()))
            .collect(),
        head: state.head.clone(),
        peeled: state.peeled.clone(),
        packs: state.packs.clone(),
    }
}

/// Write immutable JSON with `Create`; an existing identical object is success.
pub(crate) async fn put_immutable_json<C: ManifestCodec, T: Serialize>(
    wal: &Wal<C>,
    key: &str,
    value: &T,
) -> Result<(), WalError> {
    let bytes = serde_json::to_vec(value)?;
    put_immutable_bytes(wal, key, bytes).await
}

/// Write immutable bytes with `Create`; an existing identical object is
/// success, different bytes under the same key are corruption.
pub(crate) async fn put_immutable_bytes<C: ManifestCodec>(
    wal: &Wal<C>,
    key: &str,
    bytes: Vec<u8>,
) -> Result<(), WalError> {
    match wal
        .store()
        .put_bytes(key, bytes.clone(), PutMode::Create)
        .await
    {
        Ok(_) => Ok(()),
        Err(error) if error.is_precondition_failed() => match wal.store().get_bytes(key).await? {
            Some((_, existing)) if existing.as_ref() == bytes.as_slice() => Ok(()),
            Some(_) => Err(WalError::Corrupt(format!(
                "immutable object {key} already exists with different bytes"
            ))),
            None => Err(WalError::Store(StoreError::precondition(key, None))),
        },
        Err(error) => Err(WalError::Store(error)),
    }
}

/// Upload an immutable local file with `Create`; an existing object with the
/// same size is accepted, so a retried upload converges.
pub(crate) async fn put_immutable_file<C: ManifestCodec>(
    wal: &Wal<C>,
    key: &str,
    path: &std::path::Path,
) -> Result<(), WalError> {
    let len = tokio::fs::metadata(path).await?.len();
    let opts = PutOptions::create().immutable();
    match wal
        .store()
        .put(key, PutBody::File(path.to_path_buf()), opts)
        .await
    {
        Ok(_) => Ok(()),
        Err(error) if error.is_precondition_failed() => match wal.store().head(key).await? {
            Some(meta) if meta.size == len => Ok(()),
            Some(meta) => Err(WalError::Corrupt(format!(
                "immutable object {key} exists with {} bytes, expected {len}",
                meta.size
            ))),
            None => Err(WalError::Store(StoreError::precondition(key, None))),
        },
        Err(error) => Err(WalError::Store(error)),
    }
}

/// Log segments that a checkpoint at `seq` makes redundant.
pub fn foldable_segments(log: &[LogSegmentRef], seq: u64) -> Vec<LogSegmentRef> {
    log.iter()
        .filter(|segment| segment.last_seq <= seq)
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Layout;
    use crate::manifest::{ManifestRef, RefsCodec, MANIFEST_VERSION};
    use crate::store::MemoryStore;
    use std::sync::Arc;

    struct Entry {
        seq: u64,
        changes: Vec<FoldChange>,
    }

    impl FoldEntry for Entry {
        fn seq(&self) -> u64 {
            self.seq
        }

        fn changes(&self) -> Vec<FoldChange> {
            self.changes.clone()
        }
    }

    fn entry(seq: u64, changes: Vec<FoldChange>) -> Entry {
        Entry { seq, changes }
    }

    fn wal() -> Wal<RefsCodec> {
        let store = Arc::new(MemoryStore::new());
        let config = Arc::new(WalConfig::new(
            std::env::temp_dir().join("s3-wal-checkpoint"),
            Layout::new("git"),
        ));
        Wal::new(store, config, Arc::new(RefsCodec))
    }

    fn state(seq: u64, refs: &[(&str, &str)], log: Vec<LogSegmentRef>) -> ManifestState {
        ManifestState {
            seq,
            revision: 7,
            refs: refs
                .iter()
                .map(|(name, sha)| (name.to_string(), ManifestRef::pack(*sha)))
                .collect(),
            head: Some("refs/heads/main".into()),
            peeled: BTreeMap::from([("refs/tags/v1".to_string(), "b".repeat(40))]),
            log,
            ..ManifestState::default()
        }
    }

    fn segment(first: u64, last: u64, size: u64) -> LogSegmentRef {
        LogSegmentRef {
            key: format!("log/{first:016x}.json"),
            first_seq: first,
            last_seq: last,
            size,
            sealed: true,
        }
    }

    #[tokio::test]
    async fn checkpoint_roundtrip_and_log_trim() {
        let wal = wal();
        let manifest = RefsCodec
            .from_state(state(
                9,
                &[
                    ("refs/heads/main", &"a".repeat(40)),
                    ("refs/tags/v1", &"b".repeat(40)),
                ],
                vec![segment(1, 3, 10), segment(4, 9, 20)],
            ))
            .unwrap();
        wal.store()
            .put_bytes(
                &wal.manifest_key("demo"),
                RefsCodec.encode(&manifest).unwrap(),
                PutMode::Create,
            )
            .await
            .unwrap();

        let reference = write_checkpoint(&wal, "demo").await.unwrap().unwrap();
        assert_eq!(reference.seq, 9);
        assert_eq!(reference.key, wal.config().layout.checkpoint_key("demo", 9));
        assert_eq!(
            reference.refs_key,
            wal.config().layout.checkpoint_refs_key("demo", 9)
        );

        let back = read_checkpoint(&wal, "demo", 9).await.unwrap().unwrap();
        assert_eq!(back.seq, 9);
        assert_eq!(back.refs["refs/heads/main"], "a".repeat(40));
        assert_eq!(back.head.as_deref(), Some("refs/heads/main"));
        assert_eq!(back.peeled["refs/tags/v1"], "b".repeat(40));

        // Manifest points at the checkpoint and dropped the folded segments.
        let stored = wal.read_manifest("demo").await.unwrap().unwrap();
        let stored = RefsCodec.state(&stored);
        assert_eq!(stored.checkpoint.as_ref().unwrap().seq, 9);
        assert!(stored.log.is_empty(), "{:?}", stored.log);
        // seq/revision are untouched by a checkpoint.
        assert_eq!(stored.seq, 9);
        assert_eq!(stored.revision, 7);

        // Idempotent: the second call writes nothing new.
        let again = write_checkpoint(&wal, "demo").await.unwrap().unwrap();
        assert_eq!(again, reference);
    }

    #[tokio::test]
    async fn checkpoint_writes_refs_snapshot_separately() {
        let wal = wal();
        let manifest = RefsCodec
            .from_state(state(2, &[("refs/heads/main", &"c".repeat(40))], vec![]))
            .unwrap();
        wal.store()
            .put_bytes(
                &wal.manifest_key("demo"),
                RefsCodec.encode(&manifest).unwrap(),
                PutMode::Create,
            )
            .await
            .unwrap();
        write_checkpoint(&wal, "demo").await.unwrap();
        let (_, refs_bytes) = wal
            .store()
            .get_bytes(&wal.config().layout.checkpoint_refs_key("demo", 2))
            .await
            .unwrap()
            .unwrap();
        let refs: BTreeMap<String, String> = serde_json::from_slice(&refs_bytes).unwrap();
        assert_eq!(refs["refs/heads/main"], "c".repeat(40));
    }

    #[tokio::test]
    async fn fold_applies_checkpoint_then_tail() {
        let checkpoint = Checkpoint {
            seq: 3,
            refs: BTreeMap::from([
                ("refs/heads/main".to_string(), "a".repeat(40)),
                ("refs/heads/gone".to_string(), "d".repeat(40)),
            ]),
            head: Some("refs/heads/main".into()),
            peeled: BTreeMap::new(),
            packs: Vec::new(),
        };
        let entries = vec![
            entry(2, vec![FoldChange::set("refs/heads/old", "e".repeat(40))]),
            entry(4, vec![FoldChange::set("refs/heads/main", "f".repeat(40))]),
            entry(
                5,
                vec![
                    FoldChange::delete("refs/heads/gone"),
                    FoldChange::set("refs/tags/v2", "1".repeat(40)),
                ],
            ),
        ];
        let folded = fold_state(Some(&checkpoint), &entries);
        assert_eq!(folded.refs["refs/heads/main"], "f".repeat(40));
        assert!(!folded.refs.contains_key("refs/heads/gone"));
        assert!(!folded.refs.contains_key("refs/heads/old"));
        assert_eq!(folded.refs["refs/tags/v2"], "1".repeat(40));
        assert_eq!(folded.seq, 5);
        assert_eq!(folded.head.as_deref(), Some("refs/heads/main"));
    }

    #[tokio::test]
    async fn fold_without_checkpoint_replays_from_empty() {
        let entries = vec![entry(
            1,
            vec![FoldChange::set("refs/heads/main", "a".repeat(40))],
        )];
        let folded = fold_state(None, &entries);
        assert_eq!(folded.refs.len(), 1);
        assert_eq!(folded.seq, 1);
    }

    #[test]
    fn tail_measurement_ignores_folded_segments() {
        let state = state(
            10,
            &[],
            vec![segment(1, 5, 100), segment(6, 8, 50), segment(9, 10, 25)],
        );
        let mut state_with_checkpoint = state.clone();
        state_with_checkpoint.checkpoint = Some(CheckpointRef {
            seq: 5,
            key: "k".into(),
            refs_key: "r".into(),
        });
        let tail = unfolded_tail(&state_with_checkpoint);
        assert_eq!(tail.entries, 5);
        assert_eq!(tail.bytes, 75);
        assert_eq!(tail.first_seq, Some(6));
        assert_eq!(tail.last_seq, Some(10));

        let trigger = CheckpointTrigger {
            entries: 5,
            interval: Duration::from_secs(3600),
            tail_bytes: 0,
        };
        assert!(trigger.is_due(&tail, Duration::ZERO));
        assert!(!trigger.is_due(&LogTail::default(), Duration::from_secs(1)));
        let interval_trigger = CheckpointTrigger {
            entries: 0,
            interval: Duration::from_secs(60),
            tail_bytes: 0,
        };
        assert!(interval_trigger.is_due(&LogTail::default(), Duration::from_secs(60)));
    }

    #[test]
    fn foldable_segments_are_the_ones_at_or_before_seq() {
        let log = vec![segment(1, 5, 10), segment(6, 10, 10)];
        assert_eq!(foldable_segments(&log, 5).len(), 1);
        assert_eq!(foldable_segments(&log, 10).len(), 2);
        assert!(foldable_segments(&log, 0).is_empty());
    }

    #[test]
    fn checkpoint_manifest_version_is_written() {
        // Guards the serialized shape other readers depend on.
        let manifest = RefsCodec
            .from_state(state(1, &[("refs/heads/main", &"a".repeat(40))], vec![]))
            .unwrap();
        let bytes = RefsCodec.encode(&manifest).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["version"], MANIFEST_VERSION);
    }
}
