use sea_orm::entity::prelude::DeriveIden;
use sea_orm_migration::prelude::*;

const ZERO_AMOUNT: &str = "0";

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
                        ColumnDef::new(Tabs::TotalAmount)
                            .string()
                            .not_null()
                            .default(ZERO_AMOUNT),
                    )
                    .add_column_if_not_exists(
                        ColumnDef::new(Tabs::PaidAmount)
                            .string()
                            .not_null()
                            .default(ZERO_AMOUNT),
                    )
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Tabs::Table)
                    .drop_column(Tabs::PaidAmount)
                    .drop_column(Tabs::TotalAmount)
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
    TotalAmount,
    PaidAmount,
}
