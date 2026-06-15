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
                ALTER TABLE "Guarantee"
                DROP CONSTRAINT IF EXISTS "Guarantee_tab_id_fkey";

                ALTER TABLE "CollateralEvent"
                DROP CONSTRAINT IF EXISTS "CollateralEvent_tab_id_fkey";

                DROP INDEX IF EXISTS uniq_tab_remunerate_event;
                DROP INDEX IF EXISTS uniq_collateral_unlock_tx_id;
                DROP INDEX IF EXISTS uniq_active_tab_identity;

                ALTER TABLE "Guarantee"
                DROP COLUMN IF EXISTS tab_id;

                ALTER TABLE "CollateralEvent"
                DROP COLUMN IF EXISTS tab_id;

                ALTER TABLE "UserTransaction"
                DROP COLUMN IF EXISTS tab_id;

                DROP TABLE IF EXISTS "Tabs";
                DROP TYPE IF EXISTS tab_status;
                DROP TYPE IF EXISTS settlement_status;
                "#,
            )
            .await?;

        Ok(())
    }

    async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        Err(DbErr::Migration(
            "m20260423_000011_drop_tabs is destructive and cannot be reversed".to_string(),
        ))
    }
}
