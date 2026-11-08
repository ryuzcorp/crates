use std::sync::Arc;

use s3_wal_git::store::{contract, FaultStore, FsStore, MemoryStore};

#[tokio::test]
async fn memory_store_passes_the_contract() {
    let store = MemoryStore::new();
    contract::run(&store, "contract/").await;
}

#[tokio::test]
async fn fs_store_passes_the_contract() {
    let dir = tempfile::tempdir().unwrap();
    let store = FsStore::open(dir.path()).await.unwrap();
    contract::run(&store, "contract/").await;
}

#[tokio::test]
async fn fault_store_delegates_the_contract() {
    let inner = Arc::new(MemoryStore::new());
    let store = FaultStore::new(inner);
    contract::run(&store, "contract/").await;
    assert!(store.stats().put > 0);
}

#[tokio::test]
async fn prefixed_store_passes_the_contract() {
    let inner: s3_wal_git::DynStore = Arc::new(MemoryStore::new());
    let store = s3_wal_git::Prefixed::new(inner, "tenant/");
    contract::run(&store, "contract/").await;
}
