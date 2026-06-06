use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(
                r#"
ALTER TYPE user_transaction_status ADD VALUE IF NOT EXISTS 'RECORDING' AFTER 'CONFIRMED';
"#,
            )
            .await?;

        Ok(())
    }

    async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        // PostgreSQL cannot drop enum values without rebuilding the type and every dependent
        // column. Leave the additive value in place on rollback.
        Ok(())
    }
}
