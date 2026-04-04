use sea_orm::entity::prelude::DeriveIden;
use sea_orm_migration::prelude::*;

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
                        ColumnDef::new(Tabs::AcceptedGuaranteeVersion).integer(),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .get_connection()
            .execute_unprepared(
                r#"
                UPDATE "Tabs" t
                SET accepted_guarantee_version = COALESCE(
                    (
                        SELECT CASE
                            WHEN lower((g.request::jsonb #>> '{claims,version}')) = 'v2' THEN 2
                            ELSE 1
                        END
                        FROM "Guarantee" g
                        WHERE g.tab_id = t.id
                        ORDER BY g.created_at DESC
                        LIMIT 1
                    ),
                    1
                )
                WHERE accepted_guarantee_version IS NULL
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
                    .drop_column(Tabs::AcceptedGuaranteeVersion)
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum Tabs {
    #[sea_orm(iden = "Tabs")]
    Table,
    AcceptedGuaranteeVersion,
}
