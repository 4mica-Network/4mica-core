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
                    .table(BlockchainEvent::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(BlockchainEvent::BlockNumber)
                            .big_integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(BlockchainEvent::LogIndex)
                            .big_integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(BlockchainEvent::Signature)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(BlockchainEvent::CreatedAt)
                            .timestamp()
                            .not_null(),
                    )
                    .primary_key(
                        Index::create()
                            .col(BlockchainEvent::BlockNumber)
                            .col(BlockchainEvent::LogIndex),
                    )
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(BlockchainEvent::Table).to_owned())
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
pub enum BlockchainEvent {
    #[sea_orm(iden = "BlockchainEvent")]
    Table,
    BlockNumber,
    LogIndex,
    Signature,
    CreatedAt,
}

