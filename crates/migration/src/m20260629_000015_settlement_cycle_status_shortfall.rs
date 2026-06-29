use sea_orm_migration::prelude::*;

/// Add the `SHORTFALL` value to the `settlement_cycle_status` enum: the terminal state for a
/// cycle whose recovered collateral cannot fully cover creditor claims.
/// `ADD VALUE IF NOT EXISTS` is idempotent and a no-op on a DB that already has it.
#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(
                "ALTER TYPE settlement_cycle_status ADD VALUE IF NOT EXISTS 'SHORTFALL';",
            )
            .await?;
        Ok(())
    }

    async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        // PostgreSQL does not support removing a value from an enum type, so this is a no-op.
        // Rolling back would require recreating the type and rewriting every dependent column.
        Ok(())
    }
}
