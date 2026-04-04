use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

const UNIQUE_ACTIVE_TAB_IDENTITY_INDEX: &str = "uniq_active_tab_identity";

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(
                r#"
                WITH ranked_tabs AS (
                    SELECT
                        id,
                        ROW_NUMBER() OVER (
                            PARTITION BY user_address, server_address, asset_address, accepted_guarantee_version
                            ORDER BY updated_at DESC, created_at DESC, id DESC
                        ) AS row_num
                    FROM "Tabs"
                    WHERE status IN ('PENDING', 'OPEN')
                      AND settlement_status NOT IN ('SETTLED', 'REMUNERATED')
                      AND accepted_guarantee_version IS NOT NULL
                )
                UPDATE "Tabs" t
                SET status = 'CLOSED',
                    updated_at = CURRENT_TIMESTAMP
                FROM ranked_tabs r
                WHERE t.id = r.id
                  AND r.row_num > 1
                "#,
            )
            .await?;

        manager
            .get_connection()
            .execute_unprepared(&format!(
                r#"
                CREATE UNIQUE INDEX {UNIQUE_ACTIVE_TAB_IDENTITY_INDEX}
                ON "Tabs" (user_address, server_address, asset_address, accepted_guarantee_version)
                WHERE status IN ('PENDING', 'OPEN')
                  AND settlement_status NOT IN ('SETTLED', 'REMUNERATED')
                "#
            ))
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(&format!(
                r#"DROP INDEX IF EXISTS {UNIQUE_ACTIVE_TAB_IDENTITY_INDEX};"#
            ))
            .await?;

        Ok(())
    }
}
