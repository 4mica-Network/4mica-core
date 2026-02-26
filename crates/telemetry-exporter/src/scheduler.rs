use std::time::{Duration, Instant};

use log::info;
use tokio::time::MissedTickBehavior;

use crate::snapshot::{Snapshot, SnapshotMeta, SnapshotStore};

pub fn spawn_snapshot_scheduler(
    snapshots: SnapshotStore,
    snapshot_interval_sec: u64,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        run_scheduler_loop(snapshots, snapshot_interval_sec).await;
    })
}

async fn run_scheduler_loop(snapshots: SnapshotStore, snapshot_interval_sec: u64) {
    let interval_duration = Duration::from_secs(snapshot_interval_sec.max(1));
    info!(
        "starting snapshot scheduler with interval {}s",
        interval_duration.as_secs()
    );

    // Seed first snapshot immediately so readiness can become healthy quickly.
    run_snapshot_tick(&snapshots).await;

    let mut ticker = tokio::time::interval(interval_duration);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        ticker.tick().await;
        run_snapshot_tick(&snapshots).await;
    }
}

pub async fn run_snapshot_tick(snapshots: &SnapshotStore) {
    let started = Instant::now();
    let snapshot = Snapshot::default();
    let query_duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    let meta = SnapshotMeta {
        captured_at: Instant::now(),
        query_duration_ms,
    };
    snapshots.update(snapshot, meta).await;
}

#[cfg(test)]
mod tests {
    use super::run_snapshot_tick;
    use crate::snapshot::SnapshotStore;

    #[tokio::test]
    async fn snapshot_tick_updates_store() {
        let snapshots = SnapshotStore::new();
        assert!(snapshots.latest().await.is_none());

        run_snapshot_tick(&snapshots).await;

        let latest = snapshots
            .latest()
            .await
            .expect("snapshot should be present after a tick");
        assert_eq!(latest.snapshot.users_total, 0);
        assert!(latest.meta.query_duration_ms <= 5_000);
    }
}
