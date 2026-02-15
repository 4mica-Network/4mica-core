use sea_orm::entity::prelude::DeriveIden;
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(BlockchainEventCursor::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(BlockchainEventCursor::ChainId)
                            .big_integer()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(BlockchainEventCursor::LastConfirmedBlockNumber)
                            .big_integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(BlockchainEventCursor::CreatedAt)
                            .timestamp()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(BlockchainEventCursor::UpdatedAt)
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
            .drop_table(Table::drop().table(BlockchainEventCursor::Table).to_owned())
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum BlockchainEventCursor {
    #[sea_orm(iden = "BlockchainEventCursor")]
    Table,
    ChainId,
    LastConfirmedBlockNumber,
    CreatedAt,
    UpdatedAt,
}
