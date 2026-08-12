//! Database harness: config loading, migrations, and table cleanup shared by
//! every DB-backed test layer.

use anyhow::{Result, anyhow};
use core_service::{config::AppConfig, persist::PersistCtx};
use migration::{Migrator, MigratorTrait};
use sea_orm::{ConnectionTrait, Statement};
use tokio::sync::OnceCell;

static MIGRATIONS: OnceCell<()> = OnceCell::const_new();

pub async fn ensure_migrations(ctx: &PersistCtx) -> Result<()> {
    MIGRATIONS
        .get_or_try_init(|| async {
            Migrator::up(ctx.db.as_ref(), None)
                .await
                .map_err(|err| anyhow!("failed to run migrations: {err}"))?;
            Ok::<(), anyhow::Error>(())
        })
        .await?;
    Ok(())
}

/// Pins the settlement timeline every core test runs under, whatever the ambient environment says.
///
/// `CoreService::new` refuses to start unless
/// `cycle + resolution_cutoff + commit_delay + finality_window + seizure_margin` is under the
/// deployed `withdrawalGracePeriod`. Development deployments set that to 60s so withdrawals are
/// testable at all, which the shipped defaults — a day-long cycle, 144900s in total — miss by four
/// orders of magnitude. Inheriting the environment therefore makes every test that builds a service
/// pass or fail on whether a generated `.env` happens to be present, which is the difference
/// between a developer's machine and a CI checkout.
///
/// These total 47s, leaving headroom under 60s. Raise them only against that budget.
pub fn apply_test_settlement_windows(cfg: &mut AppConfig) {
    let settlement = &mut cfg.settlement_cycle;
    settlement.cycle_secs = 20;
    settlement.resolution_cutoff_secs = 5;
    settlement.clearing_commit_delay_secs = 2;
    settlement.payment_submission_window_secs = 5;
    settlement.payment_finality_window_secs = 10;
    settlement.seizure_margin_secs = 10;
    settlement.shortfall_grace_secs = 10;
}

pub fn init_config() -> Result<AppConfig> {
    dotenv::dotenv().ok();
    dotenv::from_filename("../.env").ok();
    let mut cfg = AppConfig::fetch()?;
    apply_test_settlement_windows(&mut cfg);
    Ok(cfg)
}

pub async fn setup_db_test_env() -> Result<(AppConfig, PersistCtx)> {
    let cfg = init_config()?;
    let ctx = PersistCtx::new().await?;
    ensure_migrations(&ctx).await?;
    Ok((cfg, ctx))
}

pub async fn clear_tables(ctx: &PersistCtx, tables: &[&str]) -> Result<()> {
    for table in tables {
        ctx.db
            .as_ref()
            .execute_raw(Statement::from_string(
                ctx.db.get_database_backend(),
                format!(r#"DELETE FROM "{table}";"#),
            ))
            .await?;
    }
    Ok(())
}

pub async fn clear_all_tables(ctx: &PersistCtx) -> Result<()> {
    // Use a single TRUNCATE so FK relationships are handled atomically.
    ctx.db
        .as_ref()
        .execute_raw(Statement::from_string(
            ctx.db.get_database_backend(),
            r#"
TRUNCATE TABLE
    "UserTransaction",
    "Withdrawal",
    "Guarantee",
    "CycleParticipantPosition",
    "CycleExposureEdge",
    "ClearingBatch",
    "SettlementCycle",
    "CollateralEvent",
    "UserAssetBalance",
    "User",
    "AuthNonce",
    "AuthRefreshToken",
    "WalletRole",
    "BlockchainEvent",
    "BlockchainEventCursor",
    "BlockchainBlock",
    "ChainCursor"
RESTART IDENTITY CASCADE;
"#,
        ))
        .await?;

    Ok(())
}
