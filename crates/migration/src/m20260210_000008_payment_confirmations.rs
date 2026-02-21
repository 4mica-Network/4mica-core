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
                        ColumnDef::new(UserTransaction::BlockNumber)
                            .big_integer()
                            .null(),
                    )
                    .add_column(ColumnDef::new(UserTransaction::BlockHash).string().null())
                    .add_column(
                        ColumnDef::new(UserTransaction::Status)
                            .string()
                            .not_null()
                            .default("CONFIRMED"),
                    )
                    .add_column(
                        ColumnDef::new(UserTransaction::ConfirmedAt)
                            .timestamp()
                            .null(),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_user_tx_status_block")
                    .table(UserTransaction::Table)
                    .col(UserTransaction::Status)
                    .col(UserTransaction::BlockNumber)
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(ChainCursor::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(ChainCursor::ChainId)
                            .big_integer()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(ChainCursor::LastConfirmedBlockNumber)
                            .big_integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ChainCursor::LastConfirmedBlockHash)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ChainCursor::CreatedAt)
                            .timestamp()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ChainCursor::UpdatedAt)
                            .timestamp()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(ChainCursor::Table).to_owned())
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .name("idx_user_tx_status_block")
                    .table(UserTransaction::Table)
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(UserTransaction::Table)
                    .drop_column(UserTransaction::ConfirmedAt)
                    .drop_column(UserTransaction::Status)
                    .drop_column(UserTransaction::BlockHash)
                    .drop_column(UserTransaction::BlockNumber)
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
    BlockNumber,
    BlockHash,
    Status,
    ConfirmedAt,
}

#[derive(DeriveIden)]
enum ChainCursor {
    #[sea_orm(iden = "ChainCursor")]
    Table,
    ChainId,
    LastConfirmedBlockNumber,
    LastConfirmedBlockHash,
    CreatedAt,
    UpdatedAt,
}
