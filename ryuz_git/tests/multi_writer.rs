//! Two independent writers over one bucket. This is the regression that the
//! conditional manifest exists for: without CAS, the second publish overwrites
//! the first writer's refs.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use ryuz_git::git::run_git;
use ryuz_git::{Layout, MemoryStore, RefUpdate, RefsCodec, Wal, WalConfig};

async fn commit_on_empty_tree(bare: &Path, parent: Option<&str>) -> String {
    let git_dir = format!("--git-dir={}", bare.display());
    let tree = run_git(&[&git_dir, "mktree"], &[], Duration::from_secs(15))
        .await
        .unwrap()
        .trim()
        .to_string();
    let mut args = vec![git_dir.as_str(), "commit-tree", tree.as_str(), "-m", "test"];
    if let Some(parent) = parent {
        args.extend(["-p", parent]);
    }
    run_git(
        &args,
        &[
            ("GIT_AUTHOR_NAME", "wal-test"),
            ("GIT_AUTHOR_EMAIL", "wal-test@example.com"),
            ("GIT_COMMITTER_NAME", "wal-test"),
            ("GIT_COMMITTER_EMAIL", "wal-test@example.com"),
        ],
        Duration::from_secs(15),
    )
    .await
    .unwrap()
    .trim()
    .to_string()
}

fn wal(store: Arc<MemoryStore>, dir: &Path) -> Wal<RefsCodec> {
    let config = WalConfig::new(dir, Layout::new("git"));
    Wal::new(store, Arc::new(config), Arc::new(RefsCodec))
}

#[tokio::test]
async fn stale_writer_retries_and_preserves_the_other_writers_ref() {
    let bucket = Arc::new(MemoryStore::new());
    let one_dir = tempfile::tempdir().unwrap();
    let two_dir = tempfile::tempdir().unwrap();
    let one = wal(bucket.clone(), one_dir.path());
    let two = wal(bucket.clone(), two_dir.path());

    one.init_repo("app").await.unwrap();
    let bare_one = one.ensure_synced("app").await.unwrap();
    let main = commit_on_empty_tree(&bare_one, None).await;
    one.publish(
        "app",
        &[RefUpdate::set("refs/heads/main", None::<String>, &main)],
    )
    .await
    .unwrap();

    // Writer two starts from seq 1 and will publish a feature branch.
    two.ensure_synced("app").await.unwrap();
    let bare_two = two.mirror_path("app");
    let feature = commit_on_empty_tree(&bare_two, Some(&main)).await;

    // Writer one moves main while writer two's view is stale.
    let main_two = commit_on_empty_tree(&bare_one, Some(&main)).await;
    one.publish(
        "app",
        &[RefUpdate::set(
            "refs/heads/main",
            Some(main.clone()),
            &main_two,
        )],
    )
    .await
    .unwrap();

    // Writer two publishes against the stale manifest. CAS must retry and
    // keep main at main_two.
    two.publish(
        "app",
        &[RefUpdate::set(
            "refs/heads/feature",
            None::<String>,
            &feature,
        )],
    )
    .await
    .unwrap();

    let manifest = two.read_manifest("app").await.unwrap().unwrap();
    assert_eq!(
        manifest.refs["refs/heads/main"].sha, main_two,
        "the stale writer must not drop main"
    );
    assert_eq!(
        manifest.refs["refs/heads/feature"].sha, feature,
        "the stale writer's ref must land"
    );
    assert_eq!(manifest.seq, 3);
}

#[tokio::test]
async fn a_stale_cas_on_the_same_ref_is_refused() {
    let bucket = Arc::new(MemoryStore::new());
    let one_dir = tempfile::tempdir().unwrap();
    let two_dir = tempfile::tempdir().unwrap();
    let one = wal(bucket.clone(), one_dir.path());
    let two = wal(bucket.clone(), two_dir.path());

    one.init_repo("app").await.unwrap();
    let bare = one.ensure_synced("app").await.unwrap();
    let first = commit_on_empty_tree(&bare, None).await;
    one.publish(
        "app",
        &[RefUpdate::set("refs/heads/main", None::<String>, &first)],
    )
    .await
    .unwrap();

    let second = commit_on_empty_tree(&bare, Some(&first)).await;
    one.publish(
        "app",
        &[RefUpdate::set(
            "refs/heads/main",
            Some(first.clone()),
            &second,
        )],
    )
    .await
    .unwrap();

    let two_bare = two.ensure_synced("app").await.unwrap();
    let third = commit_on_empty_tree(&two_bare, Some(&second)).await;
    let error = two
        .publish(
            "app",
            &[RefUpdate::set(
                "refs/heads/main",
                Some(first.clone()),
                &third,
            )],
        )
        .await
        .unwrap_err();
    assert!(format!("{error:#}").contains("conflict"), "{error:#}");

    let manifest = two.read_manifest("app").await.unwrap().unwrap();
    assert_eq!(manifest.refs["refs/heads/main"].sha, second);
}
