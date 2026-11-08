//! Namespaced repositories (`owner/name`) must survive the temp-path, key and
//! route layers end to end.

use std::path::Path;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ryuz_git::http::{router, Access, AuthError, GitHooks, GitHttp, Grant};
use ryuz_git::{Layout, MemoryStore, RefsCodec, StorageMode, Wal, WalConfig};
use tower::ServiceExt;

struct AllowAll;

#[async_trait::async_trait]
impl GitHooks for AllowAll {
    async fn authorize(&self, _repo: &str, _need: Access) -> Result<Grant, AuthError> {
        Ok(Grant::admin())
    }
}

fn config(dir: &Path) -> Arc<WalConfig> {
    Arc::new(WalConfig::new(dir.join("git"), Layout::new("git")))
}

async fn git(args: &[String], cwd: Option<&Path>) -> String {
    let mut cmd = tokio::process::Command::new("git");
    cmd.args(args)
        .env_clear()
        .env("PATH", "/usr/local/bin:/usr/bin:/bin")
        .env("HOME", "/nonexistent")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_AUTHOR_NAME", "namespace-test")
        .env("GIT_AUTHOR_EMAIL", "namespace-test@example.com")
        .env("GIT_COMMITTER_NAME", "namespace-test")
        .env("GIT_COMMITTER_EMAIL", "namespace-test@example.com");
    if let Some(cwd) = cwd {
        cmd.current_dir(cwd);
    }
    let output = cmd.output().await.unwrap();
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

#[tokio::test]
async fn namespaced_repository_pushes_and_clones() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(dir.path());
    let store = Arc::new(MemoryStore::new());
    let state = Arc::new(GitHttp::new(
        store.clone(),
        cfg.clone(),
        Arc::new(RefsCodec),
        AllowAll,
    ));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, router(state)).await;
    });

    let source = dir.path().join("source");
    git(
        &[
            "init".into(),
            "-b".into(),
            "main".into(),
            source.display().to_string(),
        ],
        None,
    )
    .await;
    tokio::fs::write(source.join("README.md"), "# namespaced\n")
        .await
        .unwrap();
    git(&["add".into(), "-A".into()], Some(&source)).await;
    git(&["commit".into(), "-m".into(), "one".into()], Some(&source)).await;
    let sha = git(&["rev-parse".into(), "HEAD".into()], Some(&source)).await;
    git(
        &[
            "push".into(),
            format!("http://{addr}/acme/demo"),
            "refs/heads/main:refs/heads/main".into(),
        ],
        Some(&source),
    )
    .await;

    let wal = Wal::new(store, cfg, Arc::new(RefsCodec));
    let manifest = wal.read_manifest("acme/demo").await.unwrap().unwrap();
    assert_eq!(manifest.refs["refs/heads/main"].sha, sha);

    let clone = dir.path().join("clone");
    git(
        &[
            "clone".into(),
            format!("http://{addr}/acme/demo"),
            clone.display().to_string(),
        ],
        None,
    )
    .await;
    assert_eq!(
        tokio::fs::read_to_string(clone.join("README.md"))
            .await
            .unwrap(),
        "# namespaced\n"
    );

    // A flat slug remains a distinct repository.
    let response = router(Arc::new(GitHttp::new(
        Arc::new(MemoryStore::new()),
        config(dir.path()),
        Arc::new(RefsCodec),
        AllowAll,
    )))
    .oneshot(
        Request::builder()
            .uri("/acme/demo/info/refs?service=git-upload-pack")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    server.abort();
}

#[tokio::test]
async fn pack_mode_rehydrates_a_cold_mirror() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = WalConfig::new(dir.path().join("git"), Layout::new("git"));
    cfg.storage = StorageMode::Pack;
    let cfg = Arc::new(cfg);
    let store = Arc::new(MemoryStore::new());
    let state = Arc::new(GitHttp::new(
        store.clone(),
        cfg.clone(),
        Arc::new(RefsCodec),
        AllowAll,
    ));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, router(state)).await;
    });

    let source = dir.path().join("source");
    git(
        &[
            "init".into(),
            "-b".into(),
            "main".into(),
            source.display().to_string(),
        ],
        None,
    )
    .await;
    tokio::fs::write(source.join("README.md"), "# cold\n")
        .await
        .unwrap();
    git(&["add".into(), "-A".into()], Some(&source)).await;
    git(&["commit".into(), "-m".into(), "one".into()], Some(&source)).await;
    let sha = git(&["rev-parse".into(), "HEAD".into()], Some(&source)).await;
    git(
        &[
            "push".into(),
            format!("http://{addr}/cold/repo"),
            "refs/heads/main:refs/heads/main".into(),
        ],
        Some(&source),
    )
    .await;

    let wal = Wal::new(store, cfg.clone(), Arc::new(RefsCodec));
    let manifest = wal.read_manifest("cold/repo").await.unwrap().unwrap();
    assert!(!manifest.packs.is_empty(), "pack mode must store packs");
    assert_eq!(manifest.refs["refs/heads/main"].sha, sha);

    // Drop the local mirror and clone again: the server must rebuild it from
    // the stored packs, not just the bytes still in process memory.
    tokio::fs::remove_dir_all(cfg.mirror_path("cold/repo"))
        .await
        .unwrap();
    let clone = dir.path().join("clone");
    git(
        &[
            "clone".into(),
            format!("http://{addr}/cold/repo"),
            clone.display().to_string(),
        ],
        None,
    )
    .await;
    assert_eq!(
        tokio::fs::read_to_string(clone.join("README.md"))
            .await
            .unwrap(),
        "# cold\n"
    );

    server.abort();
}
