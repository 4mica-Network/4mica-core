use sea_orm::entity::prelude::DeriveIden;
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(
                Table::drop()
                    .table(BlockchainEvent::Table)
                    .if_exists()
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(BlockchainEvent::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(BlockchainEvent::ChainId)
                            .big_integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(BlockchainEvent::BlockNumber)
                            .big_integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(BlockchainEvent::BlockHash)
                            .string()
                            .not_null(),
                    )
                    .col(ColumnDef::new(BlockchainEvent::TxHash).string().not_null())
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
                    .col(ColumnDef::new(BlockchainEvent::Address).string().not_null())
                    .col(ColumnDef::new(BlockchainEvent::Data).text().not_null())
                    .col(
                        ColumnDef::new(BlockchainEvent::CreatedAt)
                            .timestamp()
                            .not_null(),
                    )
                    .primary_key(
                        Index::create()
                            .col(BlockchainEvent::ChainId)
                            .col(BlockchainEvent::BlockHash)
                            .col(BlockchainEvent::LogIndex),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_blockchain_event_chain_block")
                    .table(BlockchainEvent::Table)
                    .col(BlockchainEvent::ChainId)
                    .col(BlockchainEvent::BlockNumber)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_blockchain_event_chain_tx")
                    .table(BlockchainEvent::Table)
                    .col(BlockchainEvent::ChainId)
                    .col(BlockchainEvent::TxHash)
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(BlockchainBlock::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(BlockchainBlock::ChainId)
                            .big_integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(BlockchainBlock::BlockNumber)
                            .big_integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(BlockchainBlock::BlockHash)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(BlockchainBlock::CreatedAt)
                            .timestamp()
                            .not_null(),
                    )
                    .primary_key(
                        Index::create()
                            .col(BlockchainBlock::ChainId)
                            .col(BlockchainBlock::BlockNumber),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_blockchain_block_chain_hash")
                    .table(BlockchainBlock::Table)
                    .col(BlockchainBlock::ChainId)
                    .col(BlockchainBlock::BlockHash)
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(BlockchainEventCursor::Table)
                    .add_column(
                        ColumnDef::new(BlockchainEventCursor::LastConfirmedBlockHash)
                            .string()
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
                    .table(BlockchainEventCursor::Table)
                    .drop_column(BlockchainEventCursor::LastConfirmedBlockHash)
                    .to_owned(),
            )
            .await?;

        manager
            .drop_table(
                Table::drop()
                    .table(BlockchainBlock::Table)
                    .if_exists()
                    .to_owned(),
            )
            .await?;

        manager
            .drop_table(
                Table::drop()
                    .table(BlockchainEvent::Table)
                    .if_exists()
                    .to_owned(),
            )
            .await?;

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
}

#[derive(DeriveIden)]
pub enum BlockchainEvent {
    #[sea_orm(iden = "BlockchainEvent")]
    Table,
    ChainId,
    BlockNumber,
    BlockHash,
    TxHash,
    LogIndex,
    Signature,
    Address,
    Data,
    CreatedAt,
}

#[derive(DeriveIden)]
pub enum BlockchainBlock {
    #[sea_orm(iden = "BlockchainBlock")]
    Table,
    ChainId,
    BlockNumber,
    BlockHash,
    CreatedAt,
}

#[derive(DeriveIden)]
enum BlockchainEventCursor {
    #[sea_orm(iden = "BlockchainEventCursor")]
    Table,
    LastConfirmedBlockHash,
}
