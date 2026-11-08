//! Backend contract suite. Every [`ObjectStore`] implementation must pass it.
//!
//! Call from a backend's tests with a unique prefix:
//! ```ignore
//! #[tokio::test]
//! async fn contract() {
//!     let store = MyStore::new();
//!     s3_wal_git::store::contract::run(&store, "contract/").await;
//! }
//! ```
//!
//! The suite is deterministic and leaves no keys behind on success.

use std::time::Duration;

use bytes::Bytes;
use futures::StreamExt as _;

use super::{
    ByteStream, GetOptions, GetResult, ObjectStore, ObjectStoreExt, PutBody, PutOptions, StoreError,
};

fn stream_of(chunks: &[&'static [u8]]) -> ByteStream {
    let chunks: Vec<Result<Bytes, StoreError>> = chunks
        .iter()
        .map(|chunk| Ok(Bytes::from_static(chunk)))
        .collect();
    Box::pin(futures::stream::iter(chunks))
}

async fn listed(store: &dyn ObjectStore, prefix: &str, start_after: Option<&str>) -> Vec<String> {
    let mut stream = store.list(prefix, start_after);
    let mut out = Vec::new();
    while let Some(item) = stream.next().await {
        out.push(item.expect("list item").key);
    }
    out
}

/// Run the full contract under `prefix` (must be unique per run and end in
/// `/`, or be empty).
pub async fn run(store: &dyn ObjectStore, prefix: &str) {
    assert!(
        prefix.is_empty() || prefix.ends_with('/'),
        "contract prefix must end in '/': {prefix:?}"
    );
    let key = format!("{prefix}object");
    let stream_key = format!("{prefix}stream");
    let child = format!("{prefix}child/one");
    for stale in [&key, &stream_key, &child] {
        store.delete(stale, None).await.expect("pre-clean");
    }

    // Create is conditional on absence, and a second create loses.
    let created = store
        .put(
            &key,
            Bytes::from_static(b"hello world").into(),
            PutOptions::create(),
        )
        .await
        .expect("create");
    assert_eq!(created.key, key);
    assert_eq!(created.size, 11);
    assert!(created.checksum.is_none() || created.checksum.as_deref() != Some(""));

    let duplicate = store
        .put(
            &key,
            Bytes::from_static(b"again").into(),
            PutOptions::create(),
        )
        .await;
    assert!(
        matches!(duplicate, Err(StoreError::PreconditionFailed { .. })),
        "create over an existing key must fail: {duplicate:?}"
    );

    let (meta, bytes) = store.get_bytes(&key).await.expect("get").expect("present");
    assert_eq!(bytes, Bytes::from_static(b"hello world"));
    assert_eq!(meta.version, created.version);
    assert_eq!(meta.size, 11);

    let head = store.head(&key).await.expect("head").expect("present");
    assert_eq!(head.key, key);
    // Compare the observable metadata; `Prefixed::get` currently keeps the
    // backend key in `ObjectMeta.key`, which is reported as an interface gap.
    assert_eq!(head.size, meta.size);
    assert_eq!(head.version, meta.version);
    assert_eq!(head.checksum, meta.checksum);

    // Cheap freshness check.
    let unchanged = store
        .get(
            &key,
            GetOptions {
                if_none_match: Some(created.version.clone()),
                ..GetOptions::default()
            },
        )
        .await
        .expect("conditional get");
    assert!(matches!(unchanged, GetResult::NotModified { .. }));
    assert_eq!(unchanged.version(), &created.version);

    // If-Match succeeds only for the current version.
    let matched = store
        .get(
            &key,
            GetOptions {
                if_match: Some(created.version.clone()),
                ..GetOptions::default()
            },
        )
        .await
        .expect("if-match get")
        .bytes()
        .await
        .expect("if-match bytes")
        .expect("if-match object");
    assert_eq!(matched.1, Bytes::from_static(b"hello world"));

    // Range reads return a slice and keep the whole-object size.
    let range = store
        .get(
            &key,
            GetOptions {
                range: Some(6..11),
                ..GetOptions::default()
            },
        )
        .await
        .expect("range get")
        .bytes()
        .await
        .expect("range bytes")
        .expect("range object");
    assert_eq!(range.1, Bytes::from_static(b"world"));
    assert_eq!(range.0.size, 11);

    let empty = store
        .get(
            &key,
            GetOptions {
                range: Some(5..5),
                ..GetOptions::default()
            },
        )
        .await
        .expect("empty range get")
        .bytes()
        .await
        .expect("empty range bytes")
        .expect("empty range object");
    assert!(empty.1.is_empty());
    assert_eq!(empty.0.size, 11);

    // Update is a CAS; a stale update never applies.
    let updated = store
        .put(
            &key,
            Bytes::from_static(b"second").into(),
            PutOptions::update(created.version.clone()),
        )
        .await
        .expect("update");
    assert_ne!(updated.version, created.version);
    let stale = store
        .put(
            &key,
            Bytes::from_static(b"third").into(),
            PutOptions::update(created.version.clone()),
        )
        .await;
    assert!(
        matches!(stale, Err(StoreError::PreconditionFailed { .. })),
        "stale update must fail: {stale:?}"
    );
    let stale_get = store
        .get(
            &key,
            GetOptions {
                if_match: Some(created.version.clone()),
                ..GetOptions::default()
            },
        )
        .await;
    assert!(
        matches!(stale_get, Err(StoreError::PreconditionFailed { .. })),
        "stale if-match get must fail: {stale_get:?}"
    );
    let head = store.head(&key).await.expect("head").expect("present");
    assert_eq!(head.version, updated.version);
    assert_eq!(head.size, 6);

    // Missing objects are reported, never silently empty.
    let missing = store
        .get_bytes(&format!("{prefix}absent"))
        .await
        .expect("missing get");
    assert!(missing.is_none());
    assert!(store
        .head(&format!("{prefix}absent"))
        .await
        .unwrap()
        .is_none());

    // Streaming bodies must match their declared length, both ways.
    let streamed = store
        .put(
            &stream_key,
            PutBody::Stream {
                len: 6,
                stream: stream_of(&[b"abc", b"def"]),
            },
            PutOptions::create(),
        )
        .await
        .expect("stream put");
    assert_eq!(streamed.size, 6);
    assert_eq!(
        store.get_bytes(&stream_key).await.unwrap().unwrap().1,
        Bytes::from_static(b"abcdef")
    );

    let mismatch_cases: [(usize, &'static [&'static [u8]]); 2] =
        [(6, &[b"abc" as &[u8]]), (6, &[b"abcdefg" as &[u8]])];
    for (len, chunks) in mismatch_cases {
        let bad = store
            .put(
                &stream_key,
                PutBody::Stream {
                    len: len as u64,
                    stream: stream_of(chunks),
                },
                PutOptions::default(),
            )
            .await;
        assert!(
            matches!(bad, Err(StoreError::InvalidArgument(_))),
            "length mismatch must be rejected: {bad:?}"
        );
    }
    // The failed stream puts must not have replaced the good object.
    assert_eq!(
        store.get_bytes(&stream_key).await.unwrap().unwrap().1,
        Bytes::from_static(b"abcdef")
    );

    // Listing is sorted, honours start_after, and reports only the prefix.
    let keys = listed(store, prefix, None).await;
    assert!(keys.contains(&key), "{keys:?}");
    assert!(keys.contains(&stream_key), "{keys:?}");
    assert!(keys.windows(2).all(|pair| pair[0] <= pair[1]), "{keys:?}");
    let after = listed(store, prefix, Some(&key)).await;
    assert!(!after.contains(&key), "{after:?}");
    assert!(after.iter().all(|item| item.as_str() > key.as_str()));
    let absent = listed(store, &format!("{prefix}absent/"), None).await;
    assert!(absent.is_empty(), "{absent:?}");

    // Delimited listing returns direct child prefixes only.
    store
        .put(
            &child,
            Bytes::from_static(b"x").into(),
            PutOptions::create(),
        )
        .await
        .expect("child put");
    let prefixes = store.list_prefixes(prefix).await.expect("prefixes");
    assert!(
        prefixes.iter().any(|item| item.ends_with("child/")),
        "{prefixes:?}"
    );
    assert!(
        !prefixes.iter().any(|item| item == &key),
        "objects must not appear as prefixes: {prefixes:?}"
    );

    // A signed URL is optional, but when produced it must be non-empty.
    let signed = store
        .signed_get_url(&key, Duration::from_secs(60))
        .await
        .expect("signed url");
    if let Some(url) = signed {
        assert!(
            url.starts_with("http") || url.starts_with("memory://"),
            "{url:?}"
        );
    }

    // Conditional delete: wrong version fails, right version removes, a
    // second unconditional delete is a no-op.
    let wrong = store.delete(&key, Some(created.version)).await;
    assert!(
        matches!(wrong, Err(StoreError::PreconditionFailed { .. })),
        "stale conditional delete must fail: {wrong:?}"
    );
    store
        .delete(&key, Some(updated.version.clone()))
        .await
        .expect("conditional delete");
    assert!(store.head(&key).await.unwrap().is_none());
    store
        .delete(&key, None)
        .await
        .expect("missing delete is ok");
    assert!(
        store
            .delete(&key, Some(updated.version.clone()))
            .await
            .is_err(),
        "conditional delete of a missing key must fail"
    );

    store
        .delete(&stream_key, None)
        .await
        .expect("stream cleanup");
    store.delete(&child, None).await.expect("child cleanup");
}
