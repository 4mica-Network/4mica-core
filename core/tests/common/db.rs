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

pub fn init_config() -> Result<AppConfig> {
    dotenv::dotenv().ok();
    dotenv::from_filename("../.env").ok();
    AppConfig::fetch()
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
