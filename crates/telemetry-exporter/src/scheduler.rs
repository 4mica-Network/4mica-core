use std::time::{Duration, Instant};

use log::{error, info};
use sea_orm::DatabaseConnection;
use tokio::time::MissedTickBehavior;

use crate::db::{self, ActiveUsersWindowCounts, QueryExecutionError};
use crate::snapshot::{Snapshot, SnapshotMeta, SnapshotStore};
use crate::telemetry;

pub fn spawn_snapshot_scheduler(
    snapshots: SnapshotStore,
    snapshot_interval_sec: u64,
    query_timeout_ms: u64,
    probe_query_sql: String,
    readonly_db: DatabaseConnection,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        run_scheduler_loop(
            snapshots,
            snapshot_interval_sec,
            query_timeout_ms,
            probe_query_sql,
            readonly_db,
        )
        .await;
    })
}

async fn run_scheduler_loop(
    snapshots: SnapshotStore,
    snapshot_interval_sec: u64,
    query_timeout_ms: u64,
    probe_query_sql: String,
    readonly_db: DatabaseConnection,
) {
    let interval_duration = Duration::from_secs(snapshot_interval_sec.max(1));
    info!(
        "starting snapshot scheduler with interval {}s",
        interval_duration.as_secs()
    );

    // Seed first snapshot immediately so readiness can become healthy quickly.
    run_and_publish_snapshot_tick(&snapshots, &readonly_db, query_timeout_ms, &probe_query_sql)
        .await;

    let mut ticker = tokio::time::interval(interval_duration);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        ticker.tick().await;
        publish_snapshot_age(&snapshots).await;
        run_and_publish_snapshot_tick(&snapshots, &readonly_db, query_timeout_ms, &probe_query_sql)
            .await;
    }
}

async fn run_and_publish_snapshot_tick(
    snapshots: &SnapshotStore,
    readonly_db: &DatabaseConnection,
    query_timeout_ms: u64,
    probe_query_sql: &str,
) {
    match run_snapshot_tick(snapshots, readonly_db, query_timeout_ms, probe_query_sql).await {
        Ok((snapshot, meta)) => {
            telemetry::record_query_duration(Duration::from_millis(meta.query_duration_ms));
            telemetry::set_users_total(snapshot.users_total);
            telemetry::set_active_users_1h(snapshot.active_users_1h);
            telemetry::set_active_users_24h(snapshot.active_users_24h);
            telemetry::set_active_users_7d(snapshot.active_users_7d);
            telemetry::set_snapshot_age_seconds(0.0);
        }
        Err(err) => {
            telemetry::increment_query_failures();
            if err.is_timeout() {
                error!("snapshot tick timed out: {err:#}");
            } else {
                error!("snapshot tick failed: {err:#}");
            }
        }
    }
}

async fn publish_snapshot_age(snapshots: &SnapshotStore) {
    if let Some(latest) = snapshots.latest().await {
        telemetry::set_snapshot_age_seconds(latest.meta.captured_at.elapsed().as_secs_f64());
    }
}

pub async fn run_snapshot_tick(
    snapshots: &SnapshotStore,
    readonly_db: &DatabaseConnection,
    query_timeout_ms: u64,
    probe_query_sql: &str,
) -> Result<(Snapshot, SnapshotMeta), QueryExecutionError> {
    let started = Instant::now();
    db::query_one_with_timeout(readonly_db, probe_query_sql, query_timeout_ms).await?;
    let users_total = db::fetch_users_total(readonly_db, query_timeout_ms).await?;
    let ActiveUsersWindowCounts {
        active_users_1h,
        active_users_24h,
        active_users_7d,
    } = db::fetch_active_users_window_counts(readonly_db, query_timeout_ms).await?;
    let snapshot = Snapshot {
        users_total,
        active_users_1h,
        active_users_24h,
        active_users_7d,
    };
    let query_duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    let meta = SnapshotMeta {
        captured_at: Instant::now(),
        query_duration_ms,
    };
    snapshots.update(snapshot.clone(), meta).await;
    Ok((snapshot, meta))
}
