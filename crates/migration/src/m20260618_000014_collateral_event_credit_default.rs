use sea_orm_migration::prelude::*;

/// Add the `CREDIT` and `DEFAULT` values to the `collateral_event_type` enum,
/// used by finality settlement (funding creditors / seizing defaulters).
/// Additive and idempotent; a no-op on a fresh DB where the enum is created
/// with both values already present.
#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(
                r#"
ALTER TYPE collateral_event_type ADD VALUE IF NOT EXISTS 'CREDIT' AFTER 'REMUNERATE';
ALTER TYPE collateral_event_type ADD VALUE IF NOT EXISTS 'DEFAULT' AFTER 'CREDIT';
"#,
            )
            .await?;

        Ok(())
    }

    async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        // PostgreSQL cannot drop enum values without rebuilding the type and every dependent
        // column. Leave the additive values in place on rollback.
        Ok(())
    }
}
