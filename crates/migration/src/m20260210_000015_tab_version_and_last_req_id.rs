use sea_orm::entity::prelude::DeriveIden;
use sea_orm_migration::prelude::*;

const DEFAULT_REQ_ID: &str = "0x0";
const DEFAULT_VERSION: i32 = 1;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Tabs::Table)
                    .add_column_if_not_exists(
                        ColumnDef::new(Tabs::LastReqId)
                            .string()
                            .not_null()
                            .default(DEFAULT_REQ_ID),
                    )
                    .add_column_if_not_exists(
                        ColumnDef::new(Tabs::Version)
                            .integer()
                            .not_null()
                            .default(DEFAULT_VERSION),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .get_connection()
            .execute_unprepared(
                r#"
                UPDATE "Tabs" t
                SET last_req_id = COALESCE(
                    (
                        SELECT g.req_id
                        FROM "Guarantee" g
                        WHERE g.tab_id = t.id
                        ORDER BY decode(lpad(regexp_replace(g.req_id, '^0x', '', 'i'), 64, '0'), 'hex') DESC
                        LIMIT 1
                    ),
                    '0x0'
                )
                "#,
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Tabs::Table)
                    .drop_column(Tabs::Version)
                    .drop_column(Tabs::LastReqId)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
pub enum Tabs {
    #[sea_orm(iden = "Tabs")]
    Table,
    LastReqId,
    Version,
}
