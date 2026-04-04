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
                    .table(Guarantee::Table)
                    .add_column_if_not_exists(
                        ColumnDef::new(Guarantee::Version)
                            .integer()
                            .not_null()
                            .default(1),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .get_connection()
            .execute_unprepared(
                r#"
                UPDATE "Guarantee"
                SET version = CASE
                    WHEN lower((request::jsonb #>> '{claims,version}')) = 'v2' THEN 2
                    ELSE 1
                END
                WHERE request IS NOT NULL
                "#,
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Guarantee::Table)
                    .drop_column(Guarantee::Version)
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum Guarantee {
    #[sea_orm(iden = "Guarantee")]
    Table,
    Version,
}
