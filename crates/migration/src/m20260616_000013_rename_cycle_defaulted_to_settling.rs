use sea_orm_migration::prelude::*;

/// Rename the `settlement_cycle_status` enum value `DEFAULTED` to `SETTLING`.
/// Guarded so it's a no-op on a fresh DB (where the enum is created as `SETTLING`).
#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(
                r#"
                DO $$
                BEGIN
                    IF EXISTS (
                        SELECT 1 FROM pg_enum e
                        JOIN pg_type t ON e.enumtypid = t.oid
                        WHERE t.typname = 'settlement_cycle_status' AND e.enumlabel = 'DEFAULTED'
                    ) AND NOT EXISTS (
                        SELECT 1 FROM pg_enum e
                        JOIN pg_type t ON e.enumtypid = t.oid
                        WHERE t.typname = 'settlement_cycle_status' AND e.enumlabel = 'SETTLING'
                    ) THEN
                        ALTER TYPE settlement_cycle_status RENAME VALUE 'DEFAULTED' TO 'SETTLING';
                    END IF;
                END$$;
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
                DO $$
                BEGIN
                    IF EXISTS (
                        SELECT 1 FROM pg_enum e
                        JOIN pg_type t ON e.enumtypid = t.oid
                        WHERE t.typname = 'settlement_cycle_status' AND e.enumlabel = 'SETTLING'
                    ) AND NOT EXISTS (
                        SELECT 1 FROM pg_enum e
                        JOIN pg_type t ON e.enumtypid = t.oid
                        WHERE t.typname = 'settlement_cycle_status' AND e.enumlabel = 'DEFAULTED'
                    ) THEN
                        ALTER TYPE settlement_cycle_status RENAME VALUE 'SETTLING' TO 'DEFAULTED';
                    END IF;
                END$$;
                "#,
            )
            .await?;
        Ok(())
    }
}
