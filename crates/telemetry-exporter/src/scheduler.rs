use std::time::{Duration, Instant};

use log::{error, info};
use sea_orm::DatabaseConnection;
use tokio::time::MissedTickBehavior;

use crate::db::{
    self, ActiveUsersWindowCounts, QueryExecutionError, StatusAmountAggregate, TabStatusAggregate,
    UserTxWindowStats,
};
use crate::snapshot::{Snapshot, SnapshotMeta, SnapshotStore};
use crate::telemetry;

const SETTLED_USER_TX_STATUSES: [&str; 1] = ["FINALIZED"];

struct SnapshotTickResult {
    snapshot: Snapshot,
    meta: SnapshotMeta,
    tabs_status_aggregates: Vec<TabStatusAggregate>,
    guarantee_status_aggregates: Vec<StatusAmountAggregate>,
    settlement_status_aggregates: Vec<StatusAmountAggregate>,
    user_tx_window_stats: UserTxWindowStats,
    tx_concentration_share_24h: f64,
}

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
        Ok(result) => {
            telemetry::record_query_duration(Duration::from_millis(result.meta.query_duration_ms));
            telemetry::set_users_total(result.snapshot.users_total);
            telemetry::set_active_users_1h(result.snapshot.active_users_1h);
            telemetry::set_active_users_24h(result.snapshot.active_users_24h);
            telemetry::set_active_users_7d(result.snapshot.active_users_7d);
            for aggregate in &result.tabs_status_aggregates {
                telemetry::set_tabs_status_aggregate(
                    &aggregate.status,
                    aggregate.tabs_count,
                    aggregate.total_amount_sum,
                    aggregate.paid_amount_sum,
                );
            }
            for aggregate in &result.guarantee_status_aggregates {
                telemetry::set_guarantees_status_aggregate(
                    &aggregate.status,
                    aggregate.count,
                    aggregate.amount_sum,
                );
            }
            for aggregate in &result.settlement_status_aggregates {
                telemetry::set_settlements_status_aggregate(
                    &aggregate.status,
                    aggregate.count,
                    aggregate.amount_sum,
                );
            }

            let guaranteed_amount_total = sum_status_amount(&result.guarantee_status_aggregates);
            let settled_amount_total = sum_status_amount_for(
                &result.settlement_status_aggregates,
                &SETTLED_USER_TX_STATUSES,
            );
            telemetry::set_reconciliation_totals(
                guaranteed_amount_total,
                settled_amount_total,
                guaranteed_amount_total - settled_amount_total,
            );

            let velocity_spike_score = compute_spike_score(
                result.user_tx_window_stats.tx_count_1h as f64,
                result.user_tx_window_stats.tx_count_24h as f64,
            );
            let amount_spike_score = compute_spike_score(
                result.user_tx_window_stats.tx_amount_1h,
                result.user_tx_window_stats.tx_amount_24h,
            );
            let status_churn_score = compute_fraction(
                result.user_tx_window_stats.reverted_count_24h as f64,
                result.user_tx_window_stats.tx_count_24h as f64,
            );
            telemetry::set_fraud_signal_scores(
                velocity_spike_score,
                amount_spike_score,
                status_churn_score,
                result.tx_concentration_share_24h,
            );
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

async fn run_snapshot_tick(
    snapshots: &SnapshotStore,
    readonly_db: &DatabaseConnection,
    query_timeout_ms: u64,
    probe_query_sql: &str,
) -> Result<SnapshotTickResult, QueryExecutionError> {
    let started = Instant::now();
    db::query_one_with_timeout(readonly_db, probe_query_sql, query_timeout_ms).await?;
    let users_total = db::fetch_users_total(readonly_db, query_timeout_ms).await?;
    let ActiveUsersWindowCounts {
        active_users_1h,
        active_users_24h,
        active_users_7d,
    } = db::fetch_active_users_window_counts(readonly_db, query_timeout_ms).await?;
    let tabs_status_aggregates =
        db::fetch_tabs_status_aggregates(readonly_db, query_timeout_ms).await?;
    let guarantee_status_aggregates =
        db::fetch_guarantee_status_aggregates(readonly_db, query_timeout_ms).await?;
    let settlement_status_aggregates =
        db::fetch_settlement_status_aggregates(readonly_db, query_timeout_ms).await?;
    let user_tx_window_stats =
        db::fetch_user_tx_window_stats(readonly_db, query_timeout_ms).await?;
    let tx_concentration_share_24h =
        db::fetch_tx_concentration_share_24h(readonly_db, query_timeout_ms).await?;
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
    Ok(SnapshotTickResult {
        snapshot,
        meta,
        tabs_status_aggregates,
        guarantee_status_aggregates,
        settlement_status_aggregates,
        user_tx_window_stats,
        tx_concentration_share_24h,
    })
}

fn sum_status_amount(aggregates: &[StatusAmountAggregate]) -> f64 {
    aggregates
        .iter()
        .map(|aggregate| aggregate.amount_sum)
        .sum()
}

fn sum_status_amount_for(aggregates: &[StatusAmountAggregate], statuses: &[&str]) -> f64 {
    aggregates
        .iter()
        .filter(|aggregate| statuses.contains(&aggregate.status.as_str()))
        .map(|aggregate| aggregate.amount_sum)
        .sum()
}

fn compute_spike_score(last_1h: f64, last_24h: f64) -> f64 {
    let stable_1h = last_1h.max(0.0);
    let stable_24h = last_24h.max(0.0);
    let previous_23h = (stable_24h - stable_1h).max(0.0);
    let baseline_per_hour = (previous_23h / 23.0).max(1.0);
    stable_1h / baseline_per_hour
}

fn compute_fraction(numerator: f64, denominator: f64) -> f64 {
    let denominator = denominator.max(0.0);
    if denominator == 0.0 {
        return 0.0;
    }
    (numerator.max(0.0) / denominator).clamp(0.0, 1.0)
}

#[cfg(test)]
mod tests {
    use super::{compute_fraction, compute_spike_score, sum_status_amount, sum_status_amount_for};
    use crate::db::StatusAmountAggregate;

    #[test]
    fn sums_all_status_amounts() {
        let aggregates = vec![
            StatusAmountAggregate {
                status: "A".to_owned(),
                count: 1,
                amount_sum: 10.0,
            },
            StatusAmountAggregate {
                status: "B".to_owned(),
                count: 1,
                amount_sum: 5.5,
            },
        ];
        assert_eq!(sum_status_amount(&aggregates), 15.5);
    }

    #[test]
    fn sums_selected_status_amounts() {
        let aggregates = vec![
            StatusAmountAggregate {
                status: "FINALIZED".to_owned(),
                count: 1,
                amount_sum: 7.0,
            },
            StatusAmountAggregate {
                status: "PENDING".to_owned(),
                count: 1,
                amount_sum: 9.0,
            },
        ];
        assert_eq!(
            sum_status_amount_for(&aggregates, &["FINALIZED", "RECORDED"]),
            7.0
        );
    }

    #[test]
    fn computes_spike_score_against_previous_baseline() {
        let score = compute_spike_score(12.0, 60.0);
        assert!(score > 5.7 && score < 5.8);
    }

    #[test]
    fn computes_fraction_with_zero_denominator() {
        assert_eq!(compute_fraction(5.0, 0.0), 0.0);
    }

    #[test]
    fn clamps_fraction_to_unit_interval() {
        assert_eq!(compute_fraction(15.0, 10.0), 1.0);
        assert_eq!(compute_fraction(-2.0, 10.0), 0.0);
    }
}
