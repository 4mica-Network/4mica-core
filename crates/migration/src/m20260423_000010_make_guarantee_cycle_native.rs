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
                DELETE FROM "Guarantee"
                WHERE guarantee_id IS NULL OR cycle_id IS NULL;

                ALTER TABLE "Guarantee"
                DROP CONSTRAINT IF EXISTS "Guarantee_pkey";

                ALTER TABLE "Guarantee"
                DROP CONSTRAINT IF EXISTS fk_guarantee_settlement_cycle;

                ALTER TABLE "Guarantee"
                ALTER COLUMN guarantee_id SET NOT NULL,
                ALTER COLUMN cycle_id SET NOT NULL,
                ALTER COLUMN tab_id DROP NOT NULL;

                ALTER TABLE "Guarantee"
                ADD CONSTRAINT "Guarantee_pkey" PRIMARY KEY (guarantee_id);

                ALTER TABLE "Guarantee"
                ADD CONSTRAINT fk_guarantee_settlement_cycle
                FOREIGN KEY (cycle_id) REFERENCES "SettlementCycle"(id)
                ON UPDATE CASCADE
                ON DELETE RESTRICT;
                "#,
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(
                r#"
                ALTER TABLE "Guarantee"
                DROP CONSTRAINT IF EXISTS fk_guarantee_settlement_cycle;

                ALTER TABLE "Guarantee"
                DROP CONSTRAINT IF EXISTS "Guarantee_pkey";

                ALTER TABLE "Guarantee"
                ALTER COLUMN cycle_id DROP NOT NULL,
                ALTER COLUMN guarantee_id DROP NOT NULL;

                ALTER TABLE "Guarantee"
                ADD CONSTRAINT "Guarantee_pkey" PRIMARY KEY (tab_id, req_id);

                ALTER TABLE "Guarantee"
                ADD CONSTRAINT fk_guarantee_settlement_cycle
                FOREIGN KEY (cycle_id) REFERENCES "SettlementCycle"(id)
                ON UPDATE CASCADE
                ON DELETE SET NULL;
                "#,
            )
            .await?;

        Ok(())
    }
}
