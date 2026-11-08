//! Metrics facade.
//!
//! Every helper is a no-op unless the `metrics` feature is enabled. With the
//! feature on it emits through the [`metrics`] crate, so any installed
//! recorder (Prometheus, OTLP, ...) exports them.
//!
//! Recorder names are stable and all start with `walgit_`:
//!
//! | Name | Type | Labels |
//! | --- | --- | --- |
//! | `walgit_pushes_total` | counter | `repo`, `result` |
//! | `walgit_push_bytes` | histogram | `repo` |
//! | `walgit_cas_conflicts_total` | counter | `repo` |
//! | `walgit_cas_retries_total` | counter | `repo` |
//! | `walgit_store_operations_total` | counter | `backend`, `op`, `result` |
//! | `walgit_store_latency_seconds` | histogram | `backend`, `op` |
//! | `walgit_refs` | gauge | `repo` |
//! | `walgit_events_lag_entries` | gauge | `repo` |
//! | `walgit_events_delivered_total` | counter | `repo` |
//! | `walgit_event_batches_total` | counter | `repo`, `result` |
//! | `walgit_lfs_bytes_total` | counter | `direction` |
//! | `walgit_lfs_operations_total` | counter | `op`, `result` |
//!
//! `result` is one of `ok`, `rejected`, `conflict`, `error`. `op` is the store
//! or LFS operation (`get`, `put`, `delete`, `list`, `download`, `upload`,
//! `verify`). `direction` is `upload` or `download`. Lag is measured in WAL
//! sequence entries, not wall-clock time, so it stays meaningful across clock
//! skew.

/// Every metric name this crate emits.
pub const METRIC_NAMES: &[&str] = &[
    "walgit_pushes_total",
    "walgit_push_bytes",
    "walgit_cas_conflicts_total",
    "walgit_cas_retries_total",
    "walgit_store_operations_total",
    "walgit_store_latency_seconds",
    "walgit_refs",
    "walgit_events_lag_entries",
    "walgit_events_delivered_total",
    "walgit_event_batches_total",
    "walgit_lfs_bytes_total",
    "walgit_lfs_operations_total",
];

/// One push attempt finished. `result` ∈ `ok`, `rejected`, `error`.
pub fn push(repo: &str, result: &str) {
    #[cfg(feature = "metrics")]
    ::metrics::counter!(
        "walgit_pushes_total",
        "repo" => repo.to_string(),
        "result" => result.to_string()
    )
    .increment(1);
    #[cfg(not(feature = "metrics"))]
    {
        let _ = (repo, result);
    }
}

/// Bytes accepted or produced by a push.
pub fn push_bytes(repo: &str, bytes: u64) {
    #[cfg(feature = "metrics")]
    ::metrics::histogram!("walgit_push_bytes", "repo" => repo.to_string()).record(bytes as f64);
    #[cfg(not(feature = "metrics"))]
    {
        let _ = (repo, bytes);
    }
}

/// A manifest compare-and-swap lost against another writer.
pub fn cas_conflict(repo: &str) {
    #[cfg(feature = "metrics")]
    ::metrics::counter!("walgit_cas_conflicts_total", "repo" => repo.to_string()).increment(1);
    #[cfg(not(feature = "metrics"))]
    {
        let _ = repo;
    }
}

/// One retry after a CAS conflict or transient store error.
pub fn cas_retry(repo: &str) {
    #[cfg(feature = "metrics")]
    ::metrics::counter!("walgit_cas_retries_total", "repo" => repo.to_string()).increment(1);
    #[cfg(not(feature = "metrics"))]
    {
        let _ = repo;
    }
}

/// One object-store operation finished.
pub fn store_op(backend: &str, op: &str, result: &str) {
    #[cfg(feature = "metrics")]
    ::metrics::counter!(
        "walgit_store_operations_total",
        "backend" => backend.to_string(),
        "op" => op.to_string(),
        "result" => result.to_string()
    )
    .increment(1);
    #[cfg(not(feature = "metrics"))]
    {
        let _ = (backend, op, result);
    }
}

/// Wall-clock latency of one object-store operation.
pub fn store_latency(backend: &str, op: &str, seconds: f64) {
    #[cfg(feature = "metrics")]
    ::metrics::histogram!(
        "walgit_store_latency_seconds",
        "backend" => backend.to_string(),
        "op" => op.to_string()
    )
    .record(seconds);
    #[cfg(not(feature = "metrics"))]
    {
        let _ = (backend, op, seconds);
    }
}

/// Current number of live refs in a repository.
pub fn refs(repo: &str, count: usize) {
    #[cfg(feature = "metrics")]
    ::metrics::gauge!("walgit_refs", "repo" => repo.to_string()).set(count as f64);
    #[cfg(not(feature = "metrics"))]
    {
        let _ = (repo, count);
    }
}

/// Distance between the persisted event cursor and the manifest head.
pub fn events_lag(repo: &str, entries: u64) {
    #[cfg(feature = "metrics")]
    ::metrics::gauge!("walgit_events_lag_entries", "repo" => repo.to_string()).set(entries as f64);
    #[cfg(not(feature = "metrics"))]
    {
        let _ = (repo, entries);
    }
}

/// Events accepted by a webhook endpoint.
pub fn events_delivered(repo: &str, count: usize) {
    #[cfg(feature = "metrics")]
    ::metrics::counter!("walgit_events_delivered_total", "repo" => repo.to_string())
        .increment(count as u64);
    #[cfg(not(feature = "metrics"))]
    {
        let _ = (repo, count);
    }
}

/// One webhook batch delivery finished. `result` ∈ `ok`, `rejected`, `error`.
pub fn event_batch(repo: &str, result: &str) {
    #[cfg(feature = "metrics")]
    ::metrics::counter!(
        "walgit_event_batches_total",
        "repo" => repo.to_string(),
        "result" => result.to_string()
    )
    .increment(1);
    #[cfg(not(feature = "metrics"))]
    {
        let _ = (repo, result);
    }
}

/// Bytes transferred through LFS. `direction` ∈ `upload`, `download`.
pub fn lfs_bytes(direction: &str, bytes: u64) {
    #[cfg(feature = "metrics")]
    ::metrics::counter!("walgit_lfs_bytes_total", "direction" => direction.to_string())
        .increment(bytes);
    #[cfg(not(feature = "metrics"))]
    {
        let _ = (direction, bytes);
    }
}

/// One LFS batch or transfer finished. `result` ∈ `ok`, `rejected`, `error`.
pub fn lfs_operation(op: &str, result: &str) {
    #[cfg(feature = "metrics")]
    ::metrics::counter!(
        "walgit_lfs_operations_total",
        "op" => op.to_string(),
        "result" => result.to_string()
    )
    .increment(1);
    #[cfg(not(feature = "metrics"))]
    {
        let _ = (op, result);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_helper_is_callable_with_and_without_the_feature() {
        push("acme/demo", "ok");
        push_bytes("acme/demo", 42);
        cas_conflict("acme/demo");
        cas_retry("acme/demo");
        store_op("memory", "put", "ok");
        store_latency("memory", "get", 0.001);
        refs("acme/demo", 3);
        events_lag("acme/demo", 7);
        events_delivered("acme/demo", 2);
        event_batch("acme/demo", "ok");
        lfs_bytes("upload", 1024);
        lfs_operation("upload", "ok");
    }

    #[test]
    fn names_are_prefixed_and_unique() {
        assert!(!METRIC_NAMES.is_empty());
        for name in METRIC_NAMES {
            assert!(name.starts_with("walgit_"), "{name}");
        }
        let mut sorted = METRIC_NAMES.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), METRIC_NAMES.len());
    }
}
