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
                    .table(UserTransaction::Table)
                    .add_column(
                        ColumnDef::new(UserTransaction::RecordTxHash)
                            .string()
                            .null(),
                    )
                    .add_column(
                        ColumnDef::new(UserTransaction::RecordTxBlockNumber)
                            .big_integer()
                            .null(),
                    )
                    .add_column(
                        ColumnDef::new(UserTransaction::RecordTxBlockHash)
                            .string()
                            .null(),
                    )
                    .add_column(
                        ColumnDef::new(UserTransaction::RecordedAt)
                            .timestamp()
                            .null(),
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
                    .table(UserTransaction::Table)
                    .drop_column(UserTransaction::RecordedAt)
                    .drop_column(UserTransaction::RecordTxBlockHash)
                    .drop_column(UserTransaction::RecordTxBlockNumber)
                    .drop_column(UserTransaction::RecordTxHash)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum UserTransaction {
    #[sea_orm(iden = "UserTransaction")]
    Table,
    RecordTxHash,
    RecordTxBlockNumber,
    RecordTxBlockHash,
    RecordedAt,
}
