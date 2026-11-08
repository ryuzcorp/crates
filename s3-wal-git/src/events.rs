//! Durable WAL-to-webhook bridge.
//!
//! Every publish appends one [`LogEntry`] to the immutable log. This module
//! turns the ref transactions in those entries into [`RefEvent`]s, batches
//! them, and delivers them through a [`WebhookSink`]. Delivery is at-least
//! once: a durable [`EventCursor`] lives under
//! [`Layout::event_cursor_key`] and only advances after the endpoint answers
//! 2xx. Receivers deduplicate with [`dedup_key`], which is stable across
//! retries.
//!
//! ```text
//! cursor ──read_log (cursor, head]──▶ LogEntry ──derive_events──▶ RefEvent
//!    ▲                                                              │
//!    └──────── advance_cursor (CAS) ◀── 2xx post (EventBatch) ◀─────┘
//! ```
//!
//! Metadata from the WAL entry is projected onto every event: `pusher` from
//! `meta.pusher`/`meta.actor`, falling back to the entry writer, and
//! `correlation_id` from `meta.correlation_id`/`meta.request_id`, falling back
//! to `{repo}:{seq}`. The webhook body carries the same values under
//! `_walgit`.

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::config::Layout;
use crate::error::{StoreError, WalError};
use crate::manifest::ManifestCodec;
use crate::store::{ObjectStore, ObjectStoreExt, PutMode, PutOptions, Version};
use crate::wal::log::{LogEntry, LogKind, TxnKind};
use crate::wal::Wal;
use crate::webhook::{WebhookError, WebhookSink};

/// Key of the batch metadata object inside the webhook JSON body.
pub const WALGIT_META_KEY: &str = "_walgit";
/// Default number of events per webhook delivery.
pub const DEFAULT_BATCH_SIZE: usize = 256;

/// What happened to one ref.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RefAction {
    Create,
    Update,
    Delete,
}

impl RefAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Update => "update",
            Self::Delete => "delete",
        }
    }
}

/// Namespace a ref lives in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RefType {
    Branch,
    Tag,
    Other,
}

impl RefType {
    /// Branch for `refs/heads/*`, tag for `refs/tags/*`, other otherwise.
    pub fn of(ref_name: &str) -> Self {
        if ref_name.starts_with("refs/heads/") {
            Self::Branch
        } else if ref_name.starts_with("refs/tags/") {
            Self::Tag
        } else {
            Self::Other
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Branch => "branch",
            Self::Tag => "tag",
            Self::Other => "other",
        }
    }
}

/// One ref change, the unit receivers act on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefEvent {
    pub action: RefAction,
    pub ref_type: RefType,
    pub ref_name: String,
    /// Previous tip; `None` for a create.
    pub old: Option<String>,
    /// New tip; `None` for a delete.
    pub new: Option<String>,
    pub pusher: String,
    pub correlation_id: String,
    pub repo: String,
    /// WAL sequence the change was committed at.
    pub seq: u64,
    /// Log entry kind that produced the event (`push`).
    pub entry_kind: String,
}

/// Durable delivery position: the highest WAL seq already delivered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct EventCursor {
    pub seq: u64,
}

/// Cursor plus the store version it was read at, for compare-and-swap.
#[derive(Debug, Clone)]
pub struct CursorState {
    pub cursor: EventCursor,
    pub version: Option<Version>,
}

/// `_walgit` block stamped into every webhook body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalgitMeta {
    /// Repository slug.
    pub repo: String,
    /// Cursor after this batch (inclusive).
    pub cursor: u64,
    /// Cursor before this batch (exclusive).
    pub from_seq: u64,
    /// Highest WAL seq covered by this batch (inclusive).
    pub to_seq: u64,
    /// Number of events.
    pub count: usize,
    /// Deterministic id over the dedup keys in this batch.
    pub delivery: String,
}

/// Webhook request body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventBatch {
    #[serde(rename = "_walgit")]
    pub meta: WalgitMeta,
    pub events: Vec<RefEvent>,
}

impl EventBatch {
    /// Build a batch and its deterministic delivery id.
    pub fn new(repo: impl Into<String>, from_seq: u64, to_seq: u64, events: Vec<RefEvent>) -> Self {
        let mut keys: Vec<String> = events
            .iter()
            .map(|event| dedup_key(&event.repo, event.seq, &event.ref_name))
            .collect();
        keys.sort_unstable();
        let mut hasher = Sha256::new();
        for key in &keys {
            hasher.update(key.as_bytes());
            hasher.update([0]);
        }
        let count = events.len();
        Self {
            meta: WalgitMeta {
                repo: repo.into(),
                cursor: to_seq,
                from_seq,
                to_seq,
                count,
                delivery: hex::encode(hasher.finalize()),
            },
            events,
        }
    }

    /// Serialize the exact webhook body.
    pub fn body(&self) -> Result<Vec<u8>, EventError> {
        Ok(serde_json::to_vec(self)?)
    }
}

/// Stable identity of one event across retries: `(repo, seq, ref_name)`.
pub fn dedup_key(repo: &str, seq: u64, ref_name: &str) -> String {
    format!("{repo}\u{1f}{seq}\u{1f}{ref_name}")
}

/// A hole in the log between the cursor and the first entry read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SeqGap {
    /// Sequence the cursor expected next.
    pub expected: u64,
    /// First sequence actually present.
    pub actual: u64,
}

impl SeqGap {
    /// Number of sequence numbers that are absent.
    pub fn missing(self) -> u64 {
        self.actual.saturating_sub(self.expected)
    }
}

/// What one [`EventBridge::catch_up`] call did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatchUpOutcome {
    /// Cursor at the start of the run.
    pub from: u64,
    /// Cursor after the run.
    pub cursor: u64,
    /// Events delivered.
    pub delivered: usize,
    /// Webhook posts made.
    pub batches: usize,
    /// First-window gap, if any. Non-dense WAL seqs make this normal after a
    /// CAS retry; it is reported, not an error, because the missing seqs were
    /// never committed.
    pub gap: Option<SeqGap>,
}

/// Event bridge failure.
#[derive(Debug, thiserror::Error)]
pub enum EventError {
    #[error("manifest for {0} not found")]
    RepoNotFound(String),
    #[error("event cursor for {0} changed concurrently")]
    CursorConflict(String),
    #[error("event cursor cannot move backwards from {current} to {next}")]
    CursorRegression { current: u64, next: u64 },
    #[error(transparent)]
    Wal(#[from] WalError),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Webhook(#[from] WebhookError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

/// True for names that must never become events: `HEAD`, `FETCH_HEAD`,
/// settings, or anything outside `refs/`.
pub fn is_symbolic_ref(ref_name: &str) -> bool {
    !ref_name.starts_with("refs/") || ref_name == "refs" || ref_name.ends_with('/')
}

/// Project one log entry into zero or more events.
///
/// Settings entries, symbolic refs and no-op transactions produce nothing.
pub fn derive_events(repo: &str, entry: &LogEntry) -> Vec<RefEvent> {
    if !produces_events(entry.kind) {
        return Vec::new();
    }
    let pusher = entry
        .meta
        .get("pusher")
        .or_else(|| entry.meta.get("actor"))
        .or_else(|| entry.meta.get("user"))
        .cloned()
        .or_else(|| entry.writer.clone())
        .unwrap_or_else(|| "unknown".to_string());
    let correlation_id = entry
        .meta
        .get("correlation_id")
        .or_else(|| entry.meta.get("request_id"))
        .cloned()
        .unwrap_or_else(|| format!("{repo}:{}", entry.seq));
    let entry_kind = log_kind_name(entry.kind);
    entry
        .txns
        .iter()
        .filter(|txn| !is_symbolic_ref(&txn.refname))
        .filter(|txn| txn.old != txn.new)
        .map(|txn| RefEvent {
            action: match txn.kind {
                TxnKind::Create => RefAction::Create,
                TxnKind::Update => RefAction::Update,
                TxnKind::Delete => RefAction::Delete,
            },
            ref_type: RefType::of(&txn.refname),
            ref_name: txn.refname.clone(),
            old: txn.old.clone(),
            new: txn.new.clone(),
            pusher: pusher.clone(),
            correlation_id: correlation_id.clone(),
            repo: repo.to_string(),
            seq: entry.seq,
            entry_kind: entry_kind.to_string(),
        })
        .collect()
}

/// Which log kinds carry ref transactions that become events.
fn produces_events(kind: LogKind) -> bool {
    matches!(kind, LogKind::Push | LogKind::RefUpdate)
}

fn log_kind_name(kind: LogKind) -> &'static str {
    match kind {
        LogKind::Push => "push",
        LogKind::RefUpdate => "ref_update",
        LogKind::Compact => "compact",
        LogKind::Checkpoint => "checkpoint",
        LogKind::Settings => "settings",
    }
}

/// Detect a hole between `cursor` and the first entry in `entries`.
pub fn detect_gap(cursor: u64, entries: &[LogEntry]) -> Option<SeqGap> {
    let min_seq = entries.iter().map(|entry| entry.seq).min()?;
    (min_seq > cursor.saturating_add(1)).then_some(SeqGap {
        expected: cursor.saturating_add(1),
        actual: min_seq,
    })
}

/// Read the persisted cursor. A missing cursor starts at zero.
pub async fn read_cursor(
    store: &dyn ObjectStore,
    layout: &Layout,
    slug: &str,
) -> Result<CursorState, EventError> {
    let key = layout.event_cursor_key(slug);
    match store.get_bytes(&key).await? {
        Some((meta, bytes)) => {
            let cursor: EventCursor = serde_json::from_slice(&bytes)?;
            Ok(CursorState {
                cursor,
                version: Some(meta.version),
            })
        }
        None => Ok(CursorState {
            cursor: EventCursor::default(),
            version: None,
        }),
    }
}

/// Conditionally persist `next` against the version in `current`.
///
/// Equal seqs are a no-op. A lost race surfaces as
/// [`EventError::CursorConflict`]; the caller re-reads and retries.
pub async fn advance_cursor(
    store: &dyn ObjectStore,
    layout: &Layout,
    slug: &str,
    current: &CursorState,
    next: EventCursor,
) -> Result<CursorState, EventError> {
    if next.seq < current.cursor.seq {
        return Err(EventError::CursorRegression {
            current: current.cursor.seq,
            next: next.seq,
        });
    }
    if next.seq == current.cursor.seq {
        return Ok(current.clone());
    }
    let key = layout.event_cursor_key(slug);
    let bytes = serde_json::to_vec(&next)?;
    let mode = match &current.version {
        Some(version) => PutMode::Update(version.clone()),
        None => PutMode::Create,
    };
    let options = PutOptions {
        mode,
        content_type: Some("application/json"),
        ..PutOptions::default()
    };
    match store.put(&key, bytes.into(), options).await {
        Ok(meta) => Ok(CursorState {
            cursor: next,
            version: Some(meta.version),
        }),
        Err(error) if error.is_precondition_failed() => {
            Err(EventError::CursorConflict(slug.to_string()))
        }
        Err(error) => Err(error.into()),
    }
}

/// WAL-to-webhook pump for one repository.
pub struct EventBridge<'a, C: ManifestCodec> {
    wal: &'a Wal<C>,
    sink: &'a dyn WebhookSink,
    url: String,
    secret: Vec<u8>,
    batch_size: usize,
}

impl<'a, C: ManifestCodec> EventBridge<'a, C> {
    pub fn new(
        wal: &'a Wal<C>,
        sink: &'a dyn WebhookSink,
        url: impl Into<String>,
        secret: impl AsRef<[u8]>,
    ) -> Self {
        Self {
            wal,
            sink,
            url: url.into(),
            secret: secret.as_ref().to_vec(),
            batch_size: DEFAULT_BATCH_SIZE,
        }
    }

    /// Maximum events per post. At least one entry is always included.
    pub fn with_batch_size(mut self, events_per_batch: usize) -> Self {
        self.batch_size = events_per_batch.max(1);
        self
    }

    pub async fn cursor(&self, slug: &str) -> Result<EventCursor, EventError> {
        Ok(read_cursor(self.store(), self.layout(), slug).await?.cursor)
    }

    /// Deliver every event committed after the cursor and advance it.
    ///
    /// Entries are read from `(cursor, head]`. A batch advances the cursor
    /// only after [`WebhookSink::post`] returns `Ok` (2xx). If a later batch
    /// fails, the cursor still names the last delivered batch, so a retry
    /// resumes there. Entries that produce no events (settings) advance the
    /// cursor without a post.
    pub async fn catch_up(&self, slug: &str) -> Result<CatchUpOutcome, EventError> {
        let mut state = read_cursor(self.store(), self.layout(), slug).await?;
        let from = state.cursor.seq;
        let Some(manifest) = self.wal.read_manifest(slug).await? else {
            return Err(EventError::RepoNotFound(slug.to_string()));
        };
        let head = self.wal.codec().seq(&manifest);
        if head <= from {
            return Ok(CatchUpOutcome {
                from,
                cursor: from,
                delivered: 0,
                batches: 0,
                gap: None,
            });
        }
        crate::metrics::events_lag(slug, head - from);
        let entries = self.wal.read_log(slug, from, Some(head)).await?;
        let gap = detect_gap(from, &entries);
        let chunks = chunk_entries(&entries, self.batch_size);
        let mut cursor = from;
        let mut delivered = 0usize;
        let mut batches = 0usize;
        for chunk in chunks {
            let to = chunk.last().map(|entry| entry.seq).unwrap_or(cursor);
            let events: Vec<RefEvent> = chunk
                .iter()
                .flat_map(|entry| derive_events(slug, entry))
                .collect();
            if !events.is_empty() {
                let batch = EventBatch::new(slug, cursor, to, events);
                let body = batch.body()?;
                match self.sink.post(&self.url, &self.secret, &body).await {
                    Ok(()) => {
                        crate::metrics::event_batch(slug, "ok");
                        crate::metrics::events_delivered(slug, batch.meta.count);
                        delivered += batch.meta.count;
                        batches += 1;
                    }
                    Err(error) => {
                        crate::metrics::event_batch(slug, "error");
                        return Err(error.into());
                    }
                }
            }
            if to > cursor {
                state = advance_cursor(
                    self.store(),
                    self.layout(),
                    slug,
                    &state,
                    EventCursor { seq: to },
                )
                .await?;
                cursor = to;
            }
        }
        // A committed seq with no readable entry (settings trims, burned seqs)
        // must still move the cursor or the bridge would retry forever.
        if head > cursor {
            advance_cursor(
                self.store(),
                self.layout(),
                slug,
                &state,
                EventCursor { seq: head },
            )
            .await?;
            cursor = head;
        }
        Ok(CatchUpOutcome {
            from,
            cursor,
            delivered,
            batches,
            gap,
        })
    }

    fn store(&self) -> &dyn ObjectStore {
        self.wal.store().as_ref()
    }

    fn layout(&self) -> &Layout {
        &self.wal.config().layout
    }
}

/// Split entries so each chunk holds at most `batch_size` projected events.
/// An entry with more transactions than the limit still forms its own chunk.
fn chunk_entries(entries: &[LogEntry], batch_size: usize) -> Vec<&[LogEntry]> {
    if entries.is_empty() {
        return Vec::new();
    }
    let mut chunks = Vec::new();
    let mut start = 0usize;
    let mut events = 0usize;
    for (index, entry) in entries.iter().enumerate() {
        let count = projected_len(entry);
        if events > 0 && events + count > batch_size {
            chunks.push(&entries[start..index]);
            start = index;
            events = 0;
        }
        events += count;
    }
    chunks.push(&entries[start..]);
    chunks
}

fn projected_len(entry: &LogEntry) -> usize {
    if !produces_events(entry.kind) {
        return 0;
    }
    entry
        .txns
        .iter()
        .filter(|txn| !is_symbolic_ref(&txn.refname) && txn.old != txn.new)
        .count()
}

#[cfg(test)]
use std::collections::BTreeMap;

/// A minimal log entry for tests and callers that build synthetic events.
/// Kept only for tests; production entries come from [`Wal::read_log`].
#[cfg(test)]
fn make_entry(
    seq: u64,
    kind: LogKind,
    txns: Vec<crate::wal::log::LogTxn>,
    meta: BTreeMap<String, String>,
) -> LogEntry {
    LogEntry {
        seq,
        kind,
        txns,
        pack: None,
        supersedes: Vec::new(),
        checkpoint: None,
        created_at: "2026-01-01T00:00:00Z".to_string(),
        writer: Some("tester".to_string()),
        meta,
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::Arc;

    use crate::config::WalConfig;
    use crate::manifest::{LogSegmentRef, RefsCodec, RefsManifest, MANIFEST_VERSION};
    use crate::store::{DynStore, MemoryStore};
    use crate::wal::log::LogTxn;
    use crate::webhook::testing::MemorySink;

    use super::*;

    fn txn(refname: &str, old: Option<&str>, new: Option<&str>, kind: TxnKind) -> LogTxn {
        LogTxn {
            refname: refname.to_string(),
            old: old.map(str::to_string),
            new: new.map(str::to_string),
            kind,
        }
    }

    #[test]
    fn derivation_maps_every_txn_and_skips_noise() {
        let meta = BTreeMap::from([
            ("pusher".to_string(), "alice".to_string()),
            ("correlation_id".to_string(), "req-1".to_string()),
        ]);
        let entry = make_entry(
            7,
            LogKind::Push,
            vec![
                txn("refs/heads/main", None, Some("aaa"), TxnKind::Create),
                txn("refs/heads/dev", Some("bbb"), Some("ccc"), TxnKind::Update),
                txn("refs/tags/v1", Some("ddd"), None, TxnKind::Delete),
                txn("refs/heads/same", Some("eee"), Some("eee"), TxnKind::Update),
                txn("HEAD", Some("fff"), Some("fff"), TxnKind::Update),
                txn(
                    "refs/notes/commits",
                    Some("111"),
                    Some("222"),
                    TxnKind::Update,
                ),
            ],
            meta,
        );
        let events = derive_events("acme/demo", &entry);
        assert_eq!(events.len(), 4);
        assert_eq!(events[0].action, RefAction::Create);
        assert_eq!(events[0].ref_type, RefType::Branch);
        assert_eq!(events[0].old, None);
        assert_eq!(events[0].new.as_deref(), Some("aaa"));
        assert_eq!(events[1].action, RefAction::Update);
        assert_eq!(events[2].action, RefAction::Delete);
        assert_eq!(events[2].ref_type, RefType::Tag);
        assert_eq!(events[3].ref_type, RefType::Other);
        for event in &events {
            assert_eq!(event.repo, "acme/demo");
            assert_eq!(event.seq, 7);
            assert_eq!(event.pusher, "alice");
            assert_eq!(event.correlation_id, "req-1");
            assert_eq!(event.entry_kind, "push");
        }
    }

    #[test]
    fn settings_entries_and_missing_metadata() {
        let entry = make_entry(3, LogKind::Settings, Vec::new(), BTreeMap::new());
        assert!(derive_events("acme/demo", &entry).is_empty());

        let entry = make_entry(
            4,
            LogKind::Push,
            vec![txn(
                "refs/heads/main",
                Some("a"),
                Some("b"),
                TxnKind::Update,
            )],
            BTreeMap::new(),
        );
        let event = &derive_events("acme/demo", &entry)[0];
        assert_eq!(event.pusher, "tester");
        assert_eq!(event.correlation_id, "acme/demo:4");
    }

    #[test]
    fn event_json_has_the_documented_shape() {
        let event = RefEvent {
            action: RefAction::Update,
            ref_type: RefType::Branch,
            ref_name: "refs/heads/main".into(),
            old: Some("a".repeat(40)),
            new: Some("b".repeat(40)),
            pusher: "alice".into(),
            correlation_id: "req".into(),
            repo: "acme/demo".into(),
            seq: 5,
            entry_kind: "push".into(),
        };
        let value = serde_json::to_value(&event).unwrap();
        assert_eq!(value["action"], "update");
        assert_eq!(value["ref_type"], "branch");
        assert_eq!(value["ref_name"], "refs/heads/main");
        assert_eq!(value["seq"], 5);
        let batch = EventBatch::new(
            "acme/demo",
            4,
            5,
            vec![event.clone(), RefEvent { seq: 5, ..event }],
        );
        let json = serde_json::to_value(&batch).unwrap();
        assert_eq!(json["_walgit"]["repo"], "acme/demo");
        assert_eq!(json["_walgit"]["cursor"], 5);
        assert_eq!(json["_walgit"]["from_seq"], 4);
        assert_eq!(json["_walgit"]["count"], 2);
        assert_eq!(json["events"][0]["ref_name"], "refs/heads/main");
        assert_eq!(json["_walgit"]["delivery"].as_str().unwrap().len(), 64);
    }

    #[test]
    fn delivery_id_is_deterministic_and_order_independent() {
        let a = RefEvent {
            action: RefAction::Create,
            ref_type: RefType::Branch,
            ref_name: "refs/heads/a".into(),
            old: None,
            new: Some("a".into()),
            pusher: "p".into(),
            correlation_id: "c".into(),
            repo: "r".into(),
            seq: 2,
            entry_kind: "push".into(),
        };
        let b = RefEvent {
            ref_name: "refs/heads/b".into(),
            ..a.clone()
        };
        let left = EventBatch::new("r", 1, 2, vec![a.clone(), b.clone()]);
        let right = EventBatch::new("r", 1, 2, vec![b, a]);
        assert_eq!(left.meta.delivery, right.meta.delivery);
        assert_eq!(
            dedup_key("r", 2, "refs/heads/a"),
            dedup_key("r", 2, "refs/heads/a")
        );
        assert_ne!(dedup_key("r", 2, "x"), dedup_key("r", 3, "x"));
    }

    #[test]
    fn gap_detection() {
        let entry = make_entry(4, LogKind::Push, Vec::new(), BTreeMap::new());
        assert_eq!(detect_gap(0, &[]), None);
        assert_eq!(
            detect_gap(0, std::slice::from_ref(&entry)),
            Some(SeqGap {
                expected: 1,
                actual: 4
            })
        );
        assert_eq!(detect_gap(3, std::slice::from_ref(&entry)), None);
        assert_eq!(
            detect_gap(1, std::slice::from_ref(&entry)),
            Some(SeqGap {
                expected: 2,
                actual: 4
            })
        );
        assert_eq!(
            detect_gap(1, std::slice::from_ref(&entry))
                .unwrap()
                .missing(),
            2
        );
    }

    #[test]
    fn chunking_respects_the_batch_size() {
        let entries: Vec<LogEntry> = (0..5)
            .map(|index| {
                make_entry(
                    index + 1,
                    LogKind::Push,
                    vec![
                        txn("refs/heads/a", None, Some("a"), TxnKind::Create),
                        txn("refs/heads/b", None, Some("b"), TxnKind::Create),
                    ],
                    BTreeMap::new(),
                )
            })
            .collect();
        let chunks = chunk_entries(&entries, 3);
        // Two events per entry and a cap of three means one entry per chunk.
        assert_eq!(chunks.len(), 5);
        assert!(chunks.iter().all(|chunk| projected_len_of(chunk) <= 3));
        assert_eq!(chunks.iter().map(|chunk| chunk.len()).sum::<usize>(), 5);
    }

    fn projected_len_of(entries: &[LogEntry]) -> usize {
        entries.iter().map(projected_len).sum()
    }

    #[tokio::test]
    async fn cursor_advance_success_and_conflict() {
        let store = MemoryStore::new();
        let layout = Layout::default();
        let state = read_cursor(&store, &layout, "acme/demo").await.unwrap();
        assert_eq!(state.cursor.seq, 0);
        assert!(state.version.is_none());

        let state = advance_cursor(&store, &layout, "acme/demo", &state, EventCursor { seq: 5 })
            .await
            .unwrap();
        assert_eq!(state.cursor.seq, 5);
        let read = read_cursor(&store, &layout, "acme/demo").await.unwrap();
        assert_eq!(read.cursor.seq, 5);
        assert!(read.version.is_some());

        // Same seq is a no-op, not a write.
        let same = advance_cursor(&store, &layout, "acme/demo", &state, EventCursor { seq: 5 })
            .await
            .unwrap();
        assert_eq!(same.cursor.seq, 5);

        // A stale handle loses the CAS.
        let stale = CursorState {
            cursor: EventCursor { seq: 0 },
            version: None,
        };
        let error = advance_cursor(&store, &layout, "acme/demo", &stale, EventCursor { seq: 9 })
            .await
            .unwrap_err();
        assert!(matches!(error, EventError::CursorConflict(_)));
        assert_eq!(
            read_cursor(&store, &layout, "acme/demo")
                .await
                .unwrap()
                .cursor
                .seq,
            5
        );

        let backwards = advance_cursor(&store, &layout, "acme/demo", &read, EventCursor { seq: 1 })
            .await
            .unwrap_err();
        assert!(matches!(backwards, EventError::CursorRegression { .. }));
    }

    fn config(layout: Layout) -> WalConfig {
        WalConfig::new(PathBuf::from("/nonexistent"), layout)
    }

    async fn seed_repo(store: &MemoryStore, layout: &Layout, slug: &str, log_entry: &LogEntry) {
        let segment_key = layout.log_key(slug, log_entry.seq);
        store
            .put(
                &segment_key,
                crate::wal::log::encode(std::slice::from_ref(log_entry))
                    .unwrap()
                    .into(),
                PutOptions::create(),
            )
            .await
            .unwrap();
        let manifest = RefsManifest {
            version: MANIFEST_VERSION,
            seq: log_entry.seq,
            log: vec![LogSegmentRef {
                key: segment_key,
                first_seq: log_entry.seq,
                last_seq: log_entry.seq,
                size: 1,
                sealed: true,
            }],
            ..RefsManifest::default()
        };
        store
            .put(
                &layout.manifest_key(slug),
                RefsCodec.encode(&manifest).unwrap().into(),
                PutOptions::create(),
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn catch_up_delivers_then_advances_and_redelivers_nothing() {
        let layout = Layout::new("git");
        let memory = MemoryStore::new();
        let store: DynStore = Arc::new(memory.clone());
        let wal = Wal::new(store, Arc::new(config(layout.clone())), Arc::new(RefsCodec));
        let slug = "acme/demo";
        let log_entry = make_entry(
            3,
            LogKind::Push,
            vec![txn("refs/heads/main", None, Some("abc"), TxnKind::Create)],
            BTreeMap::from([("pusher".to_string(), "alice".to_string())]),
        );
        seed_repo(&memory, &layout, slug, &log_entry).await;

        let sink = MemorySink::new();
        let bridge = EventBridge::new(&wal, &sink, "https://hook.test/events", b"secret");
        let outcome = bridge.catch_up(slug).await.unwrap();
        assert_eq!(outcome.from, 0);
        assert_eq!(outcome.cursor, 3);
        assert_eq!(outcome.delivered, 1);
        assert_eq!(outcome.batches, 1);
        assert_eq!(
            outcome.gap,
            Some(SeqGap {
                expected: 1,
                actual: 3
            })
        );
        assert_eq!(sink.len(), 1);
        let delivery = &sink.deliveries()[0];
        assert_eq!(delivery.url, "https://hook.test/events");
        assert_eq!(delivery.secret, b"secret");
        let body: EventBatch = serde_json::from_slice(&delivery.body).unwrap();
        assert_eq!(body.meta.cursor, 3);
        assert_eq!(body.events.len(), 1);
        assert_eq!(body.events[0].pusher, "alice");
        assert_eq!(body.events[0].old, None);

        let outcome = bridge.catch_up(slug).await.unwrap();
        assert_eq!(outcome.from, 3);
        assert_eq!(outcome.cursor, 3);
        assert_eq!(outcome.delivered, 0);
        assert_eq!(sink.len(), 1);
    }

    #[tokio::test]
    async fn catch_up_does_not_advance_on_non_2xx() {
        let layout = Layout::new("git");
        let memory = MemoryStore::new();
        let store: DynStore = Arc::new(memory.clone());
        let wal = Wal::new(store, Arc::new(config(layout.clone())), Arc::new(RefsCodec));
        let slug = "acme/demo";
        let log_entry = make_entry(
            1,
            LogKind::Push,
            vec![txn(
                "refs/heads/main",
                Some("a"),
                Some("b"),
                TxnKind::Update,
            )],
            BTreeMap::new(),
        );
        seed_repo(&memory, &layout, slug, &log_entry).await;

        let sink = MemorySink::new();
        sink.fail_with(503);
        let bridge = EventBridge::new(&wal, &sink, "https://hook.test/events", b"");
        let error = bridge.catch_up(slug).await.unwrap_err();
        assert!(matches!(
            error,
            EventError::Webhook(WebhookError::Status { status: 503, .. })
        ));
        assert_eq!(bridge.cursor(slug).await.unwrap().seq, 0);

        sink.clear_failure();
        let outcome = bridge.catch_up(slug).await.unwrap();
        assert_eq!(outcome.cursor, 1);
        assert_eq!(outcome.delivered, 1);
        assert_eq!(sink.len(), 1);
    }

    #[tokio::test]
    async fn catch_up_without_a_manifest_is_a_typed_error() {
        let layout = Layout::new("git");
        let store: DynStore = Arc::new(MemoryStore::new());
        let wal = Wal::new(store, Arc::new(config(layout)), Arc::new(RefsCodec));
        let sink = MemorySink::new();
        let bridge = EventBridge::new(&wal, &sink, "https://hook.test", b"");
        let error = bridge.catch_up("acme/missing").await.unwrap_err();
        assert!(matches!(error, EventError::RepoNotFound(_)));
        assert_eq!(sink.len(), 0);
    }
}
