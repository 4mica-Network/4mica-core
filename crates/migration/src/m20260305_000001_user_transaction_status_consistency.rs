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
UPDATE "UserTransaction"
SET status = 'FINALIZED'::user_transaction_status,
    updated_at = NOW()
WHERE finalized = true
  AND failed = false
  AND status <> 'FINALIZED'::user_transaction_status;

ALTER TABLE "UserTransaction"
ADD CONSTRAINT chk_ut_finalized_nonfailed_implies_status_finalized
CHECK (
  NOT (finalized = true AND failed = false)
  OR status = 'FINALIZED'::user_transaction_status
) NOT VALID;

ALTER TABLE "UserTransaction"
ADD CONSTRAINT chk_ut_status_finalized_implies_flags
CHECK (
  status <> 'FINALIZED'::user_transaction_status
  OR (finalized = true AND failed = false)
) NOT VALID;

ALTER TABLE "UserTransaction"
ADD CONSTRAINT chk_ut_failed_implies_finalized
CHECK (NOT failed OR finalized) NOT VALID;

ALTER TABLE "UserTransaction"
ADD CONSTRAINT chk_ut_failed_implies_status_reverted
CHECK (
  NOT failed
  OR status = 'REVERTED'::user_transaction_status
) NOT VALID;

ALTER TABLE "UserTransaction"
VALIDATE CONSTRAINT chk_ut_finalized_nonfailed_implies_status_finalized;

ALTER TABLE "UserTransaction"
VALIDATE CONSTRAINT chk_ut_status_finalized_implies_flags;

ALTER TABLE "UserTransaction"
VALIDATE CONSTRAINT chk_ut_failed_implies_finalized;

ALTER TABLE "UserTransaction"
VALIDATE CONSTRAINT chk_ut_failed_implies_status_reverted;
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
ALTER TABLE "UserTransaction"
DROP CONSTRAINT IF EXISTS chk_ut_failed_implies_finalized;

ALTER TABLE "UserTransaction"
DROP CONSTRAINT IF EXISTS chk_ut_status_finalized_implies_flags;

ALTER TABLE "UserTransaction"
DROP CONSTRAINT IF EXISTS chk_ut_finalized_nonfailed_implies_status_finalized;

ALTER TABLE "UserTransaction"
DROP CONSTRAINT IF EXISTS chk_ut_failed_implies_status_reverted;
"#,
            )
            .await?;

        Ok(())
    }
}
