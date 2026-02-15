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
                    .table(CollateralEvent::Table)
                    .add_column(
                        ColumnDef::new(CollateralEvent::EventChainId)
                            .big_integer()
                            .null(),
                    )
                    .add_column(
                        ColumnDef::new(CollateralEvent::EventBlockHash)
                            .string()
                            .null(),
                    )
                    .add_column(ColumnDef::new(CollateralEvent::EventTxHash).string().null())
                    .add_column(
                        ColumnDef::new(CollateralEvent::EventLogIndex)
                            .big_integer()
                            .null(),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Withdrawal::Table)
                    .add_column(
                        ColumnDef::new(Withdrawal::RequestEventChainId)
                            .big_integer()
                            .null(),
                    )
                    .add_column(
                        ColumnDef::new(Withdrawal::RequestEventBlockHash)
                            .string()
                            .null(),
                    )
                    .add_column(
                        ColumnDef::new(Withdrawal::RequestEventTxHash)
                            .string()
                            .null(),
                    )
                    .add_column(
                        ColumnDef::new(Withdrawal::RequestEventLogIndex)
                            .big_integer()
                            .null(),
                    )
                    .add_column(
                        ColumnDef::new(Withdrawal::CancelEventChainId)
                            .big_integer()
                            .null(),
                    )
                    .add_column(
                        ColumnDef::new(Withdrawal::CancelEventBlockHash)
                            .string()
                            .null(),
                    )
                    .add_column(
                        ColumnDef::new(Withdrawal::CancelEventTxHash)
                            .string()
                            .null(),
                    )
                    .add_column(
                        ColumnDef::new(Withdrawal::CancelEventLogIndex)
                            .big_integer()
                            .null(),
                    )
                    .add_column(
                        ColumnDef::new(Withdrawal::ExecuteEventChainId)
                            .big_integer()
                            .null(),
                    )
                    .add_column(
                        ColumnDef::new(Withdrawal::ExecuteEventBlockHash)
                            .string()
                            .null(),
                    )
                    .add_column(
                        ColumnDef::new(Withdrawal::ExecuteEventTxHash)
                            .string()
                            .null(),
                    )
                    .add_column(
                        ColumnDef::new(Withdrawal::ExecuteEventLogIndex)
                            .big_integer()
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
                    .table(Withdrawal::Table)
                    .drop_column(Withdrawal::ExecuteEventLogIndex)
                    .drop_column(Withdrawal::ExecuteEventTxHash)
                    .drop_column(Withdrawal::ExecuteEventBlockHash)
                    .drop_column(Withdrawal::ExecuteEventChainId)
                    .drop_column(Withdrawal::CancelEventLogIndex)
                    .drop_column(Withdrawal::CancelEventTxHash)
                    .drop_column(Withdrawal::CancelEventBlockHash)
                    .drop_column(Withdrawal::CancelEventChainId)
                    .drop_column(Withdrawal::RequestEventLogIndex)
                    .drop_column(Withdrawal::RequestEventTxHash)
                    .drop_column(Withdrawal::RequestEventBlockHash)
                    .drop_column(Withdrawal::RequestEventChainId)
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(CollateralEvent::Table)
                    .drop_column(CollateralEvent::EventLogIndex)
                    .drop_column(CollateralEvent::EventTxHash)
                    .drop_column(CollateralEvent::EventBlockHash)
                    .drop_column(CollateralEvent::EventChainId)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum CollateralEvent {
    #[sea_orm(iden = "CollateralEvent")]
    Table,
    EventChainId,
    EventBlockHash,
    EventTxHash,
    EventLogIndex,
}

#[derive(DeriveIden)]
enum Withdrawal {
    #[sea_orm(iden = "Withdrawal")]
    Table,
    RequestEventChainId,
    RequestEventBlockHash,
    RequestEventTxHash,
    RequestEventLogIndex,
    CancelEventChainId,
    CancelEventBlockHash,
    CancelEventTxHash,
    CancelEventLogIndex,
    ExecuteEventChainId,
    ExecuteEventBlockHash,
    ExecuteEventTxHash,
    ExecuteEventLogIndex,
}
