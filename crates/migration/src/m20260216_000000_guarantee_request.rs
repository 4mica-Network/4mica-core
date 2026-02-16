use sea_orm::entity::prelude::DeriveIden;
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
enum Guarantee {
    #[sea_orm(iden = "Guarantee")]
    Table,
    Request,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Guarantee::Table)
                    .add_column_if_not_exists(ColumnDef::new(Guarantee::Request).string().null())
                    .to_owned(),
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Guarantee::Table)
                    .drop_column(Guarantee::Request)
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
}
