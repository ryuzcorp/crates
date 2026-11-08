//! WAL integration tests: manifest CAS, retries, mirror cache, bundles, packs,
//! log segments and purge. All git objects are real; nothing sleeps to wait for
//! background work.

use std::collections::VecDeque;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use futures::StreamExt as _;

use crate::config::{Layout, StorageMode, WalConfig};
use crate::error::{StoreError, WalError};
use crate::git::{self, RefSnapshot};
use crate::manifest::{ManifestCodec, RefsCodec, RepoSetting};
use crate::store::{
    BoxStream, DynStore, GetOptions, GetResult, MemoryStore, ObjectMeta, ObjectStore,
    ObjectStoreExt, PutBody, PutMode, PutOptions, Version,
};
use crate::wal::{GitSync, LogKind, LogTxn, RecordOutcome, RefUpdate, TxnKind, Wal};

type TestWal = Wal<RefsCodec>;

fn config(root: &Path, storage: StorageMode) -> Arc<WalConfig> {
    let mut config = WalConfig::new(root.join("repos"), Layout::new("git"));
    config.storage = storage;
    config.batch_window = Duration::ZERO;
    config.publish_retries = 4;
    config.publish_retry_base = Duration::ZERO;
    config.publish_retry_max = Duration::ZERO;
    Arc::new(config)
}

fn test_wal(store: DynStore, config: Arc<WalConfig>) -> TestWal {
    Wal::new(store, config, Arc::new(RefsCodec))
}

async fn commit(bare: &Path, parent: Option<&str>, message: &str) -> String {
    let git_dir = format!("--git-dir={}", bare.display());
    let tree = git::run_git_stdin(&[&git_dir, "mktree"], b"", &[], git::QUICK_TIMEOUT)
        .await
        .unwrap();
    let tree = String::from_utf8(tree).unwrap().trim().to_string();
    let mut args = vec![
        git_dir.as_str(),
        "commit-tree",
        tree.as_str(),
        "-m",
        message,
    ];
    if let Some(parent) = parent {
        args.push("-p");
        args.push(parent);
    }
    let env = [
        ("GIT_AUTHOR_NAME", "wal-test"),
        ("GIT_AUTHOR_EMAIL", "wal-test@example.com"),
        ("GIT_COMMITTER_NAME", "wal-test"),
        ("GIT_COMMITTER_EMAIL", "wal-test@example.com"),
    ];
    git::run_git(&args, &env, git::QUICK_TIMEOUT)
        .await
        .unwrap()
        .trim()
        .to_string()
}

async fn keys(store: &DynStore, prefix: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut stream = store.list(prefix, None);
    while let Some(item) = stream.next().await {
        out.push(item.unwrap().key);
    }
    out
}

#[tokio::test]
async fn init_is_create_only_and_updates_are_versioned() {
    let store: DynStore = Arc::new(MemoryStore::new());
    let dir = tempfile::tempdir().unwrap();
    let wal = test_wal(store.clone(), config(dir.path(), StorageMode::Bundle));

    wal.init_repo("demo").await.unwrap();
    let (manifest, version) = wal.load_manifest("demo").await.unwrap().unwrap();
    assert_eq!(manifest.seq, 0);
    assert!(manifest.refs.is_empty());
    assert!(matches!(
        wal.init_repo("demo").await,
        Err(WalError::AlreadyExists(_))
    ));

    let mut state = wal.codec().state(&manifest);
    state.seq = 7;
    let next = wal.codec().from_state(state).unwrap();
    let meta = wal
        .write_manifest("demo", &next, PutMode::Update(version.clone()))
        .await
        .unwrap();
    assert!(meta.version != version);
    let stale = wal
        .write_manifest("demo", &next, PutMode::Update(version))
        .await
        .unwrap_err();
    assert!(matches!(
        stale,
        WalError::Store(error) if error.is_precondition_failed()
    ));
    let create = wal
        .write_manifest("demo", &next, PutMode::Create)
        .await
        .unwrap_err();
    assert!(matches!(
        create,
        WalError::Store(error) if error.is_precondition_failed()
    ));
}

#[tokio::test]
async fn two_writers_on_disjoint_refs_both_survive() {
    let store: DynStore = Arc::new(MemoryStore::new());
    let dir1 = tempfile::tempdir().unwrap();
    let dir2 = tempfile::tempdir().unwrap();
    let first = test_wal(store.clone(), config(dir1.path(), StorageMode::Bundle));
    let second = test_wal(store.clone(), config(dir2.path(), StorageMode::Bundle));

    first.init_repo("demo").await.unwrap();
    let bare1 = first.mirror_path("demo");
    let one = commit(&bare1, None, "one").await;
    first
        .publish(
            "demo",
            &[RefUpdate::set("refs/heads/a", None::<String>, &one)],
        )
        .await
        .unwrap();

    let bare2 = second.ensure_synced("demo").await.unwrap();
    let two = commit(&bare2, None, "two").await;
    second
        .publish(
            "demo",
            &[RefUpdate::set("refs/heads/b", None::<String>, &two)],
        )
        .await
        .unwrap();

    let manifest = first.read_manifest("demo").await.unwrap().unwrap();
    assert_eq!(manifest.refs["refs/heads/a"].sha, one);
    assert_eq!(manifest.refs["refs/heads/b"].sha, two);
    assert_eq!(manifest.seq, 2);
    assert!(!keys(&store, "git/demo/").await.is_empty());
}

#[tokio::test]
async fn same_ref_stale_publish_is_a_ref_conflict() {
    let store: DynStore = Arc::new(MemoryStore::new());
    let dir1 = tempfile::tempdir().unwrap();
    let dir2 = tempfile::tempdir().unwrap();
    let first = test_wal(store.clone(), config(dir1.path(), StorageMode::Bundle));
    let second = test_wal(store.clone(), config(dir2.path(), StorageMode::Bundle));

    first.init_repo("demo").await.unwrap();
    let bare1 = first.mirror_path("demo");
    let one = commit(&bare1, None, "one").await;
    first
        .publish(
            "demo",
            &[RefUpdate::set("refs/heads/main", None::<String>, &one)],
        )
        .await
        .unwrap();

    let bare2 = second.ensure_synced("demo").await.unwrap();
    let two = commit(&bare2, None, "two").await;
    let error = second
        .publish(
            "demo",
            &[RefUpdate::set("refs/heads/main", None::<String>, &two)],
        )
        .await
        .unwrap_err();
    match error {
        WalError::RefConflict {
            name,
            expected,
            actual,
        } => {
            assert_eq!(name, "refs/heads/main");
            assert_eq!(expected, None);
            assert_eq!(actual.as_deref(), Some(one.as_str()));
        }
        other => panic!("unexpected error: {other}"),
    }
    let manifest = first.read_manifest("demo").await.unwrap().unwrap();
    assert_eq!(manifest.refs["refs/heads/main"].sha, one);
    assert_eq!(manifest.seq, 1);
}

#[tokio::test]
async fn no_op_publish_writes_nothing() {
    let store: DynStore = Arc::new(MemoryStore::new());
    let dir = tempfile::tempdir().unwrap();
    let wal = test_wal(store.clone(), config(dir.path(), StorageMode::Bundle));
    wal.init_repo("demo").await.unwrap();
    let bare = wal.mirror_path("demo");
    let one = commit(&bare, None, "one").await;
    wal.publish(
        "demo",
        &[RefUpdate::set("refs/heads/main", None::<String>, &one)],
    )
    .await
    .unwrap();
    let (before, version) = wal.load_manifest("demo").await.unwrap().unwrap();
    let outcome = wal
        .publish(
            "demo",
            &[RefUpdate::set("refs/heads/main", Some(one.clone()), &one)],
        )
        .await
        .unwrap();
    assert!(outcome.moved.is_empty());
    assert_eq!(outcome.seq, before.seq);
    let (after, after_version) = wal.load_manifest("demo").await.unwrap().unwrap();
    assert_eq!(after.seq, before.seq);
    assert_eq!(after_version, version);
    assert_eq!(after.log.len(), before.log.len());
}

#[tokio::test]
async fn deletes_remove_refs_and_bundles() {
    let store: DynStore = Arc::new(MemoryStore::new());
    let dir = tempfile::tempdir().unwrap();
    let wal = test_wal(store.clone(), config(dir.path(), StorageMode::Bundle));
    wal.init_repo("demo").await.unwrap();
    let bare = wal.mirror_path("demo");
    let one = commit(&bare, None, "one").await;
    wal.publish(
        "demo",
        &[RefUpdate::set("refs/heads/main", None::<String>, &one)],
    )
    .await
    .unwrap();
    let bundle = keyword(&store, "git/demo/refs/heads/main").await;
    assert_eq!(bundle.len(), 1);

    let outcome = wal
        .publish(
            "demo",
            &[RefUpdate::delete("refs/heads/main", Some(one.clone()))],
        )
        .await
        .unwrap();
    assert_eq!(outcome.deleted, vec!["refs/heads/main".to_string()]);
    let manifest = wal.read_manifest("demo").await.unwrap().unwrap();
    assert!(manifest.refs.is_empty());
    assert!(keyword(&store, "git/demo/refs/heads/main").await.is_empty());
}

async fn keyword(store: &DynStore, prefix: &str) -> Vec<String> {
    keys(store, prefix)
        .await
        .into_iter()
        .filter(|key| key.ends_with(".bundle"))
        .collect()
}

#[tokio::test]
async fn bundle_mode_publish_rehydrate_and_prune() {
    let store: DynStore = Arc::new(MemoryStore::new());
    let dir = tempfile::tempdir().unwrap();
    let wal = test_wal(store.clone(), config(dir.path(), StorageMode::Bundle));
    wal.init_repo("demo").await.unwrap();
    let bare = wal.mirror_path("demo");
    let one = commit(&bare, None, "one").await;
    let two = commit(&bare, Some(&one), "two").await;

    let first = wal
        .publish(
            "demo",
            &[RefUpdate::set("refs/heads/main", None::<String>, &one)],
        )
        .await
        .unwrap();
    let first_key = refs_bundle(wal.config(), "demo", "refs/heads/main", &one);
    assert!(store.head(&first_key).await.unwrap().is_some());
    assert_eq!(first.moved[0].bundle.as_deref(), Some(first_key.as_str()));

    wal.publish(
        "demo",
        &[RefUpdate::set("refs/heads/main", Some(one.clone()), &two)],
    )
    .await
    .unwrap();
    let second_key = refs_bundle(wal.config(), "demo", "refs/heads/main", &two);
    assert!(store.head(&second_key).await.unwrap().is_some());
    assert!(
        store.head(&first_key).await.unwrap().is_none(),
        "the superseded bundle is pruned after the flip"
    );

    let other_dir = tempfile::tempdir().unwrap();
    let fresh = test_wal(store.clone(), config(other_dir.path(), StorageMode::Bundle));
    let refs = fresh.rehydrate("demo").await.unwrap();
    assert_eq!(
        refs.get("refs/heads/main").map(String::as_str),
        Some(two.as_str())
    );
    assert_eq!(
        fresh.head_of("demo", "refs/heads/main").await.unwrap(),
        Some(two.clone())
    );
    assert!(fresh.is_fast_forward("demo", &one, &two).await.unwrap());
    assert!(!fresh.is_fast_forward("demo", &two, &one).await.unwrap());
}

fn refs_bundle(config: &WalConfig, slug: &str, refname: &str, sha: &str) -> String {
    config.layout.bundle_key(slug, refname, sha)
}

#[tokio::test]
async fn missing_bundle_is_an_error_not_an_empty_repo() {
    let store: DynStore = Arc::new(MemoryStore::new());
    let dir = tempfile::tempdir().unwrap();
    let wal = test_wal(store.clone(), config(dir.path(), StorageMode::Bundle));
    wal.init_repo("demo").await.unwrap();
    let bare = wal.mirror_path("demo");
    let one = commit(&bare, None, "one").await;
    wal.publish(
        "demo",
        &[RefUpdate::set("refs/heads/main", None::<String>, &one)],
    )
    .await
    .unwrap();
    let key = refs_bundle(wal.config(), "demo", "refs/heads/main", &one);
    store.delete(&key, None).await.unwrap();

    let other_dir = tempfile::tempdir().unwrap();
    let fresh = test_wal(store.clone(), config(other_dir.path(), StorageMode::Bundle));
    let error = fresh.rehydrate("demo").await.unwrap_err();
    assert!(matches!(error, WalError::Corrupt(_)), "{error}");
    let manifest = fresh.read_manifest("demo").await.unwrap().unwrap();
    assert_eq!(manifest.refs["refs/heads/main"].sha, one);
}

#[tokio::test]
async fn unreadable_manifest_leaves_the_mirror_untouched() {
    let store: DynStore = Arc::new(MemoryStore::new());
    let dir = tempfile::tempdir().unwrap();
    let wal = test_wal(store.clone(), config(dir.path(), StorageMode::Bundle));
    wal.init_repo("demo").await.unwrap();
    let bare = wal.mirror_path("demo");
    let one = commit(&bare, None, "one").await;
    store
        .put(
            &wal.manifest_key("demo"),
            Bytes::from_static(b"{not json").into(),
            PutOptions::default(),
        )
        .await
        .unwrap();
    let error = wal
        .publish(
            "demo",
            &[RefUpdate::set("refs/heads/main", None::<String>, &one)],
        )
        .await
        .unwrap_err();
    assert!(matches!(error, WalError::Corrupt(_)), "{error}");
    assert!(git::head_of_ref(&bare, "refs/heads/main")
        .await
        .unwrap()
        .is_none());
    assert!(keyword(&store, "git/demo/refs/heads/main").await.is_empty());
}

#[tokio::test]
async fn pack_mode_publishes_and_rehydrates_from_packs() {
    let store: DynStore = Arc::new(MemoryStore::new());
    let dir = tempfile::tempdir().unwrap();
    let wal = test_wal(store.clone(), config(dir.path(), StorageMode::Pack));
    wal.init_repo("demo").await.unwrap();
    let bare = wal.mirror_path("demo");
    let one = commit(&bare, None, "one").await;
    let two = commit(&bare, Some(&one), "two").await;

    let first = wal
        .publish(
            "demo",
            &[RefUpdate::set("refs/heads/main", None::<String>, &one)],
        )
        .await
        .unwrap();
    let manifest = wal.read_manifest("demo").await.unwrap().unwrap();
    assert_eq!(manifest.packs.len(), 1);
    assert!(manifest.refs["refs/heads/main"].bundle.is_none());
    let checksum = manifest.packs[0].checksum.clone();
    assert_eq!(first.moved[0].pack.as_deref(), Some(checksum.as_str()));
    let pack_key = wal.config().layout.pack_key("demo", &checksum, "pack");
    assert!(store.head(&pack_key).await.unwrap().is_some());

    wal.publish(
        "demo",
        &[RefUpdate::set("refs/heads/main", Some(one.clone()), &two)],
    )
    .await
    .unwrap();
    let manifest = wal.read_manifest("demo").await.unwrap().unwrap();
    assert_eq!(manifest.packs.len(), 1);
    assert_eq!(manifest.retired_packs.len(), 1);
    assert_eq!(manifest.retired_packs[0].checksum, checksum);
    assert!(
        store.head(&pack_key).await.unwrap().is_some(),
        "retired pack bytes stay downloadable"
    );

    let other_dir = tempfile::tempdir().unwrap();
    let fresh = test_wal(store.clone(), config(other_dir.path(), StorageMode::Pack));
    let refs = fresh.rehydrate("demo").await.unwrap();
    assert_eq!(
        refs.get("refs/heads/main").map(String::as_str),
        Some(two.as_str())
    );
    let live = &fresh.read_manifest("demo").await.unwrap().unwrap().packs[0].checksum;
    assert!(fresh
        .mirror_path("demo")
        .join("objects")
        .join("pack")
        .join(format!("pack-{live}.pack"))
        .exists());
}

#[tokio::test]
async fn log_entries_are_appended_and_read_in_order() {
    let store: DynStore = Arc::new(MemoryStore::new());
    let dir = tempfile::tempdir().unwrap();
    let wal = test_wal(store.clone(), config(dir.path(), StorageMode::Bundle));
    wal.init_repo("demo").await.unwrap();
    let bare = wal.mirror_path("demo");
    let one = commit(&bare, None, "one").await;
    let two = commit(&bare, Some(&one), "two").await;
    wal.publish(
        "demo",
        &[RefUpdate::set("refs/heads/main", None::<String>, &one)],
    )
    .await
    .unwrap();
    wal.publish(
        "demo",
        &[RefUpdate::set("refs/heads/main", Some(one.clone()), &two)],
    )
    .await
    .unwrap();
    wal.publish_settings(
        "demo",
        RepoSetting {
            toml: "[maintenance]\n".into(),
            revision: 0,
            author: "tester".into(),
            updated_at: "2026-01-01T00:00:00Z".into(),
            message: "settings".into(),
        },
    )
    .await
    .unwrap();

    let all = wal.read_log("demo", 0, Some(u64::MAX)).await.unwrap();
    assert_eq!(
        all.iter().map(|entry| entry.seq).collect::<Vec<_>>(),
        vec![1, 2, 3]
    );
    assert_eq!(all[0].kind, LogKind::Push);
    assert_eq!(
        all[0].txns,
        vec![LogTxn::change("refs/heads/main", None, Some(one.clone()))]
    );
    assert_eq!(all[1].txns[0].kind, TxnKind::Update);
    assert_eq!(all[2].kind, LogKind::Settings);
    assert!(all[2].txns.is_empty());

    let tail = wal.read_log("demo", 1, Some(2)).await.unwrap();
    assert_eq!(tail.len(), 1);
    assert_eq!(tail[0].seq, 2);
    assert!(wal.read_log("demo", 3, Some(3)).await.unwrap().is_empty());
    assert!(wal.read_log("demo", 9, Some(2)).await.unwrap().is_empty());

    let manifest = wal.read_manifest("demo").await.unwrap().unwrap();
    assert_eq!(manifest.seq, 3);
    assert_eq!(manifest.settings.as_ref().unwrap().revision, 1);
    assert_eq!(manifest.log.len(), 3);
}

#[tokio::test]
async fn purge_removes_mirror_manifest_and_prefix() {
    let store: DynStore = Arc::new(MemoryStore::new());
    let dir = tempfile::tempdir().unwrap();
    let wal = test_wal(store.clone(), config(dir.path(), StorageMode::Bundle));
    wal.init_repo("demo").await.unwrap();
    let bare = wal.mirror_path("demo");
    let one = commit(&bare, None, "one").await;
    wal.publish(
        "demo",
        &[RefUpdate::set("refs/heads/main", None::<String>, &one)],
    )
    .await
    .unwrap();
    wal.purge("demo").await.unwrap();
    assert!(wal.read_manifest("demo").await.unwrap().is_none());
    assert!(!wal.mirror_path("demo").exists());
    assert!(keys(&store, "git/demo/").await.is_empty());
    assert_eq!(wal.sync().applied_seq("demo").await, None);
    // A recreated repository starts at seq 0 again.
    wal.init_repo("demo").await.unwrap();
    let manifest = wal.read_manifest("demo").await.unwrap().unwrap();
    assert_eq!(manifest.seq, 0);
    assert!(manifest.refs.is_empty());
}

#[tokio::test]
async fn record_push_lazily_creates_the_manifest_and_records_deletes() {
    let store: DynStore = Arc::new(MemoryStore::new());
    let dir = tempfile::tempdir().unwrap();
    let wal = test_wal(store.clone(), config(dir.path(), StorageMode::Bundle));
    let bare = wal.ensure_synced("demo").await.unwrap();
    assert!(wal.read_manifest("demo").await.unwrap().is_none());
    let before = RefSnapshot::default();
    let one = commit(&bare, None, "one").await;
    git::set_ref(&bare, "refs/heads/main", Some(&one))
        .await
        .unwrap();

    let outcome = wal.record_push("demo", &before, None).await.unwrap();
    assert_eq!(outcome.moved.len(), 1);
    let manifest = wal.read_manifest("demo").await.unwrap().unwrap();
    assert_eq!(manifest.seq, 1);
    assert_eq!(manifest.refs["refs/heads/main"].sha, one);

    let before = git::snapshot_refs(&bare, &[]).await.unwrap();
    git::set_ref(&bare, "refs/heads/main", None).await.unwrap();
    let outcome = wal.record_push("demo", &before, None).await.unwrap();
    assert_eq!(outcome.deleted, vec!["refs/heads/main".to_string()]);
    let manifest = wal.read_manifest("demo").await.unwrap().unwrap();
    assert!(manifest.refs.is_empty());
    assert!(wal.read_log("demo", 0, Some(u64::MAX)).await.unwrap().len() == 2);
}

#[tokio::test]
async fn record_push_uses_the_supplied_ingested_pack() {
    let store: DynStore = Arc::new(MemoryStore::new());
    let dir = tempfile::tempdir().unwrap();
    let wal = test_wal(store.clone(), config(dir.path(), StorageMode::Pack));
    let bare = wal.ensure_synced("demo").await.unwrap();
    let before = RefSnapshot::default();
    let one = commit(&bare, None, "one").await;
    git::set_ref(&bare, "refs/heads/main", Some(&one))
        .await
        .unwrap();
    let git_dir = format!("--git-dir={}", bare.display());
    let pack = git::run_git_raw(
        &[&git_dir, "pack-objects", "--all", "--stdout"],
        &[],
        Duration::from_secs(60),
    )
    .await
    .unwrap();
    let ingested = git::ingest_pack(
        &bare,
        &pack,
        &git::IngestOptions {
            fsck: true,
            max_bytes: None,
            thin: false,
        },
    )
    .await
    .unwrap()
    .expect("pack");

    wal.record_push("demo", &before, Some(ingested.clone()))
        .await
        .unwrap();
    let manifest = wal.read_manifest("demo").await.unwrap().unwrap();
    assert_eq!(manifest.packs.len(), 1);
    assert_eq!(manifest.packs[0].checksum, ingested.checksum);
    assert!(!wal
        .config()
        .layout
        .pack_key("demo", &ingested.checksum, "idx")
        .is_empty());
    assert!(store
        .head(
            &wal.config()
                .layout
                .pack_key("demo", &ingested.checksum, "idx")
        )
        .await
        .unwrap()
        .is_some());

    let other_dir = tempfile::tempdir().unwrap();
    let fresh = test_wal(store.clone(), config(other_dir.path(), StorageMode::Pack));
    let refs = fresh.rehydrate("demo").await.unwrap();
    assert_eq!(
        refs.get("refs/heads/main").map(String::as_str),
        Some(one.as_str())
    );
}

#[tokio::test]
async fn group_commit_coalesces_concurrent_publishes() {
    let store: DynStore = Arc::new(MemoryStore::new());
    let dir = tempfile::tempdir().unwrap();
    let mut settings = WalConfig::new(dir.path().join("repos"), Layout::new("git"));
    settings.storage = StorageMode::Bundle;
    settings.batch_window = Duration::from_millis(25);
    settings.publish_retries = 4;
    settings.publish_retry_base = Duration::ZERO;
    settings.publish_retry_max = Duration::ZERO;
    let config = Arc::new(settings);
    let wal = test_wal(store.clone(), config);
    wal.init_repo("demo").await.unwrap();
    let bare = wal.mirror_path("demo");
    let one = commit(&bare, None, "one").await;
    let two = commit(&bare, None, "two").await;

    let first = {
        let wal = wal.clone();
        let one = one.clone();
        tokio::spawn(async move {
            wal.publish(
                "demo",
                &[RefUpdate::set("refs/heads/a", None::<String>, &one)],
            )
            .await
        })
    };
    let second = {
        let wal = wal.clone();
        let two = two.clone();
        tokio::spawn(async move {
            wal.publish(
                "demo",
                &[RefUpdate::set("refs/heads/b", None::<String>, &two)],
            )
            .await
        })
    };
    first.await.unwrap().unwrap();
    second.await.unwrap().unwrap();

    let manifest = wal.read_manifest("demo").await.unwrap().unwrap();
    assert_eq!(manifest.refs["refs/heads/a"].sha, one);
    assert_eq!(manifest.refs["refs/heads/b"].sha, two);
    assert_eq!(manifest.seq, 2);
    assert_eq!(
        manifest.revision, 1,
        "both requests were committed by one manifest flip"
    );
    assert_eq!(manifest.log.len(), 1);
    assert_eq!(
        wal.read_log("demo", 0, Some(u64::MAX)).await.unwrap().len(),
        2
    );
}

#[tokio::test]
async fn precondition_retry_refills_and_burns_the_sequence() {
    let store = Arc::new(ScriptedStore::new());
    let dir = tempfile::tempdir().unwrap();
    let wal = test_wal(store.clone(), config(dir.path(), StorageMode::Bundle));
    wal.init_repo("demo").await.unwrap();
    let bare = wal.mirror_path("demo");
    let one = commit(&bare, None, "one").await;
    store.script(Script::RaceManifest);

    let outcome = wal
        .publish(
            "demo",
            &[RefUpdate::set("refs/heads/main", None::<String>, &one)],
        )
        .await
        .unwrap();
    assert_eq!(outcome.seq, 2, "the raced sequence is burned");
    let manifest = wal.read_manifest("demo").await.unwrap().unwrap();
    assert_eq!(manifest.seq, 2);
    assert_eq!(manifest.refs["refs/heads/main"].sha, one);
    let log = wal.read_log("demo", 0, Some(u64::MAX)).await.unwrap();
    assert_eq!(
        log.iter().map(|entry| entry.seq).collect::<Vec<_>>(),
        vec![2]
    );
}

#[tokio::test]
async fn ambiguous_write_adopts_only_exact_tips() {
    let store = Arc::new(ScriptedStore::new());
    let dir = tempfile::tempdir().unwrap();
    let wal = test_wal(store.clone(), config(dir.path(), StorageMode::Bundle));
    wal.init_repo("demo").await.unwrap();
    let bare = wal.mirror_path("demo");
    let one = commit(&bare, None, "one").await;

    store.script(Script::LostResponse);
    let outcome = wal
        .publish(
            "demo",
            &[RefUpdate::set("refs/heads/main", None::<String>, &one)],
        )
        .await
        .unwrap();
    assert_eq!(outcome.seq, 1);
    assert_eq!(
        wal.read_manifest("demo").await.unwrap().unwrap().refs["refs/heads/main"].sha,
        one
    );

    let two = commit(&bare, Some(&one), "two").await;
    store.script(Script::FailWithoutApply);
    let error = wal
        .publish(
            "demo",
            &[RefUpdate::set("refs/heads/main", Some(one.clone()), &two)],
        )
        .await
        .unwrap_err();
    assert!(
        matches!(error, WalError::Store(_) | WalError::Other(_)),
        "{error}"
    );
    let manifest = wal.read_manifest("demo").await.unwrap().unwrap();
    assert_eq!(manifest.seq, 1);
    assert_eq!(manifest.refs["refs/heads/main"].sha, one);
    assert_eq!(
        git::head_of_ref(&bare, "refs/heads/main").await.unwrap(),
        Some(one)
    );
}

#[tokio::test]
async fn policy_roundtrip_and_missing_default() {
    let store: DynStore = Arc::new(MemoryStore::new());
    let dir = tempfile::tempdir().unwrap();
    let wal = test_wal(store.clone(), config(dir.path(), StorageMode::Bundle));
    let missing = wal.read_policy("demo").await.unwrap();
    assert_eq!(
        serde_json::to_vec(&missing).unwrap(),
        serde_json::to_vec(&crate::policy::Policy::default()).unwrap()
    );
    let policy = crate::policy::Policy::default();
    wal.write_policy("demo", &policy).await.unwrap();
    let read = wal.read_policy("demo").await.unwrap();
    assert_eq!(read.version, policy.version);
    assert_eq!(read.rules.len(), policy.rules.len());
}

// ---------------------------------------------------------------------------
// Fault and race injection
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
enum Script {
    /// Write a competing manifest (bumped seq/revision) and report 412.
    RaceManifest,
    /// Apply the put, then report a non-412 failure (lost response).
    LostResponse,
    /// Report a non-412 failure without writing (hard failure).
    FailWithoutApply,
}

/// Delegates to [`MemoryStore`] and plays one scripted fault on the next
/// manifest put.
struct ScriptedStore {
    inner: MemoryStore,
    script: Mutex<VecDeque<Script>>,
}

impl ScriptedStore {
    fn new() -> Self {
        Self {
            inner: MemoryStore::new(),
            script: Mutex::new(VecDeque::new()),
        }
    }

    fn script(&self, script: Script) {
        self.script
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .push_back(script);
    }

    fn next_script(&self, key: &str) -> Option<Script> {
        if !key.ends_with("MANIFEST.json") {
            return None;
        }
        self.script
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .pop_front()
    }

    async fn race_manifest(&self, key: &str) -> Result<(), StoreError> {
        let Some((_, bytes)) = self.inner.get_bytes(key).await? else {
            return Err(StoreError::not_found(key));
        };
        let manifest = RefsCodec.decode(&bytes).map_err(StoreError::Other)?;
        let mut state = RefsCodec.state(&manifest);
        state.seq += 1;
        state.revision += 1;
        let raced = RefsCodec.from_state(state).map_err(StoreError::Other)?;
        let bytes = RefsCodec.encode(&raced).map_err(StoreError::Other)?;
        self.inner
            .put(key, bytes.into(), PutOptions::default())
            .await?;
        Ok(())
    }
}

#[async_trait]
impl ObjectStore for ScriptedStore {
    fn backend(&self) -> &'static str {
        "scripted"
    }

    async fn get(&self, key: &str, opts: GetOptions) -> Result<GetResult, StoreError> {
        self.inner.get(key, opts).await
    }

    async fn head(&self, key: &str) -> Result<Option<ObjectMeta>, StoreError> {
        self.inner.head(key).await
    }

    async fn put(
        &self,
        key: &str,
        body: PutBody,
        opts: PutOptions,
    ) -> Result<ObjectMeta, StoreError> {
        match self.next_script(key) {
            None => self.inner.put(key, body, opts).await,
            Some(Script::RaceManifest) => {
                self.race_manifest(key).await?;
                Err(StoreError::precondition(key, None))
            }
            Some(Script::LostResponse) => {
                self.inner.put(key, body, opts).await?;
                Err(StoreError::Other(anyhow::anyhow!("response lost")))
            }
            Some(Script::FailWithoutApply) => {
                Err(StoreError::Other(anyhow::anyhow!("write failed")))
            }
        }
    }

    async fn delete(&self, key: &str, if_version: Option<Version>) -> Result<(), StoreError> {
        self.inner.delete(key, if_version).await
    }

    fn list(
        &self,
        prefix: &str,
        start_after: Option<&str>,
    ) -> BoxStream<'static, Result<ObjectMeta, StoreError>> {
        self.inner.list(prefix, start_after)
    }

    async fn list_prefixes(&self, prefix: &str) -> Result<Vec<String>, StoreError> {
        self.inner.list_prefixes(prefix).await
    }

    async fn signed_get_url(&self, key: &str, ttl: Duration) -> Result<Option<String>, StoreError> {
        self.inner.signed_get_url(key, ttl).await
    }
}

/// Keep `GitSync` and `RecordOutcome` imports honest for the test module.
#[allow(dead_code)]
fn _types(_: GitSync, _: RecordOutcome, _: PutMode) {}
