use std::time::{Duration, Instant};

use anyhow::Context;
use log::{error, info};
use sea_orm::DatabaseConnection;
use tokio::time::MissedTickBehavior;

use crate::snapshot::{Snapshot, SnapshotMeta, SnapshotStore};
use crate::telemetry;

pub fn spawn_snapshot_scheduler(
    snapshots: SnapshotStore,
    snapshot_interval_sec: u64,
    readonly_db: DatabaseConnection,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        run_scheduler_loop(snapshots, snapshot_interval_sec, readonly_db).await;
    })
}

async fn run_scheduler_loop(
    snapshots: SnapshotStore,
    snapshot_interval_sec: u64,
    _readonly_db: DatabaseConnection,
) {
    let interval_duration = Duration::from_secs(snapshot_interval_sec.max(1));
    info!(
        "starting snapshot scheduler with interval {}s",
        interval_duration.as_secs()
    );

    // Seed first snapshot immediately so readiness can become healthy quickly.
    run_and_publish_snapshot_tick(&snapshots).await;

    let mut ticker = tokio::time::interval(interval_duration);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        ticker.tick().await;
        publish_snapshot_age(&snapshots).await;
        run_and_publish_snapshot_tick(&snapshots).await;
    }
}

async fn run_and_publish_snapshot_tick(snapshots: &SnapshotStore) {
    match run_snapshot_tick(snapshots).await {
        Ok(meta) => {
            telemetry::record_query_duration(Duration::from_millis(meta.query_duration_ms));
            telemetry::set_snapshot_age_seconds(0.0);
        }
        Err(err) => {
            telemetry::increment_query_failures();
            error!("snapshot tick failed: {err:#}");
        }
    }
}

async fn publish_snapshot_age(snapshots: &SnapshotStore) {
    if let Some(latest) = snapshots.latest().await {
        telemetry::set_snapshot_age_seconds(latest.meta.captured_at.elapsed().as_secs_f64());
    }
}

pub async fn run_snapshot_tick(snapshots: &SnapshotStore) -> anyhow::Result<SnapshotMeta> {
    let started = Instant::now();
    let snapshot = Snapshot::default();
    let query_duration_ms =
        u64::try_from(started.elapsed().as_millis()).context("snapshot query duration overflow")?;
    let meta = SnapshotMeta {
        captured_at: Instant::now(),
        query_duration_ms,
    };
    snapshots.update(snapshot, meta).await;
    Ok(meta)
}

#[cfg(test)]
mod tests {
    use super::run_snapshot_tick;
    use crate::snapshot::SnapshotStore;

    #[tokio::test]
    async fn snapshot_tick_updates_store() {
        let snapshots = SnapshotStore::new();
        assert!(snapshots.latest().await.is_none());

        let tick_meta = run_snapshot_tick(&snapshots)
            .await
            .expect("snapshot tick should succeed");

        let latest = snapshots
            .latest()
            .await
            .expect("snapshot should be present after a tick");
        assert_eq!(latest.snapshot.users_total, 0);
        assert!(latest.meta.query_duration_ms <= 5_000);
        assert_eq!(latest.meta.query_duration_ms, tick_meta.query_duration_ms);
    }
}
