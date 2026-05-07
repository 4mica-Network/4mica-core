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
DELETE FROM "CollateralEvent" newer
USING "CollateralEvent" older
WHERE newer.event_chain_id IS NOT NULL
  AND newer.event_block_hash IS NOT NULL
  AND newer.event_tx_hash IS NOT NULL
  AND newer.event_log_index IS NOT NULL
  AND newer.event_chain_id = older.event_chain_id
  AND newer.event_block_hash = older.event_block_hash
  AND newer.event_tx_hash = older.event_tx_hash
  AND newer.event_log_index = older.event_log_index
  AND (
    newer.created_at > older.created_at
    OR (newer.created_at = older.created_at AND newer.id > older.id)
  );

CREATE UNIQUE INDEX IF NOT EXISTS uniq_collateral_event_identity
ON "CollateralEvent" (
    event_chain_id,
    event_block_hash,
    event_tx_hash,
    event_log_index
)
WHERE event_chain_id IS NOT NULL
  AND event_block_hash IS NOT NULL
  AND event_tx_hash IS NOT NULL
  AND event_log_index IS NOT NULL;
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
DROP INDEX IF EXISTS uniq_collateral_event_identity;
"#,
            )
            .await?;

        Ok(())
    }
}
