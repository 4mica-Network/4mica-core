use std::sync::Arc;
use std::time::Instant;

use tokio::sync::RwLock;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Snapshot {
    pub users_total: u64,
    pub active_users_1h: u64,
    pub active_users_24h: u64,
    pub active_users_7d: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct SnapshotMeta {
    pub captured_at: Instant,
    pub query_duration_ms: u64,
}

#[derive(Debug, Clone)]
pub struct SnapshotEnvelope {
    pub snapshot: Snapshot,
    pub meta: SnapshotMeta,
}

#[derive(Debug, Default)]
struct SnapshotState {
    latest: Option<SnapshotEnvelope>,
}

#[derive(Clone, Debug, Default)]
pub struct SnapshotStore {
    inner: Arc<RwLock<SnapshotState>>,
}

impl SnapshotStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn latest(&self) -> Option<SnapshotEnvelope> {
        self.inner.read().await.latest.clone()
    }

    #[cfg(test)]
    pub async fn update(&self, snapshot: Snapshot, meta: SnapshotMeta) {
        let mut state = self.inner.write().await;
        state.latest = Some(SnapshotEnvelope { snapshot, meta });
    }
}

#[cfg(test)]
mod tests {
    use super::{Snapshot, SnapshotMeta, SnapshotStore};
    use std::time::Instant;

    #[tokio::test]
    async fn starts_empty() {
        let store = SnapshotStore::new();
        assert!(store.latest().await.is_none());
    }

    #[tokio::test]
    async fn update_sets_latest_and_last_success() {
        let store = SnapshotStore::new();
        let captured_at = Instant::now();
        let snapshot = Snapshot {
            users_total: 11,
            active_users_1h: 4,
            active_users_24h: 8,
            active_users_7d: 10,
        };
        let meta = SnapshotMeta {
            captured_at,
            query_duration_ms: 42,
        };

        store.update(snapshot.clone(), meta).await;

        let latest = store.latest().await.expect("snapshot should be present");
        assert_eq!(latest.snapshot, snapshot);
        assert_eq!(latest.meta.query_duration_ms, 42);
        assert_eq!(latest.meta.captured_at, captured_at);
    }
}
