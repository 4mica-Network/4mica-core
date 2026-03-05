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
CREATE UNIQUE INDEX IF NOT EXISTS uniq_collateral_unlock_tx_id
ON "CollateralEvent" (tx_id)
WHERE event_type = 'UNLOCK' AND tx_id IS NOT NULL;

ALTER TABLE "Tabs"
ADD CONSTRAINT chk_tabs_total_amount_numeric
CHECK (total_amount ~ '^[0-9]+$') NOT VALID;

ALTER TABLE "Tabs"
ADD CONSTRAINT chk_tabs_paid_amount_numeric
CHECK (paid_amount ~ '^[0-9]+$') NOT VALID;

ALTER TABLE "Tabs"
ADD CONSTRAINT chk_tabs_paid_not_above_total
CHECK (
  CASE
    WHEN total_amount ~ '^[0-9]+$' AND paid_amount ~ '^[0-9]+$'
      THEN paid_amount::numeric <= total_amount::numeric
    ELSE false
  END
) NOT VALID;
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
ALTER TABLE "Tabs"
DROP CONSTRAINT IF EXISTS chk_tabs_paid_not_above_total;

ALTER TABLE "Tabs"
DROP CONSTRAINT IF EXISTS chk_tabs_paid_amount_numeric;

ALTER TABLE "Tabs"
DROP CONSTRAINT IF EXISTS chk_tabs_total_amount_numeric;

DROP INDEX IF EXISTS uniq_collateral_unlock_tx_id;
"#,
            )
            .await?;

        Ok(())
    }
}
