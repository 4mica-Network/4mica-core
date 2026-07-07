use sea_orm::entity::prelude::DeriveIden;
use sea_orm_migration::prelude::*;

/// give the scanner a durable place to record an event whose handler fails
/// *deterministically*, so a single un-handleable ("poison") event can be dead-lettered and
/// skipped instead of wedging the whole indexing pipeline. All columns are nullable and additive:
/// a normally-handled event leaves them NULL, and only genuine deterministic failures are marked
/// (transient failures are retried, never dead-lettered). `status` distinguishes a dead-lettered
/// row for a `WHERE status = 'DEAD_LETTERED'` operator query and alerting; `attempts`/`last_error`/
/// `failed_at` capture the diagnostics needed to investigate and later replay.
#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(BlockchainEvent::Table)
                    .add_column(ColumnDef::new(BlockchainEvent::Status).text().null())
                    .add_column(ColumnDef::new(BlockchainEvent::Attempts).integer().null())
                    .add_column(ColumnDef::new(BlockchainEvent::LastError).text().null())
                    .add_column(ColumnDef::new(BlockchainEvent::FailedAt).timestamp().null())
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(BlockchainEvent::Table)
                    .drop_column(BlockchainEvent::FailedAt)
                    .drop_column(BlockchainEvent::LastError)
                    .drop_column(BlockchainEvent::Attempts)
                    .drop_column(BlockchainEvent::Status)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum BlockchainEvent {
    #[sea_orm(iden = "BlockchainEvent")]
    Table,
    Status,
    Attempts,
    LastError,
    FailedAt,
}
