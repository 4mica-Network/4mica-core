use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
enum SettlementCycle {
    #[sea_orm(iden = "SettlementCycle")]
    Table,
    OnchainCycleIdHash,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(SettlementCycle::Table)
                    .add_column(
                        ColumnDef::new(SettlementCycle::OnchainCycleIdHash)
                            .string()
                            .null(),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_settlement_cycle_onchain_hash")
                    .table(SettlementCycle::Table)
                    .col(SettlementCycle::OnchainCycleIdHash)
                    .unique()
                    .to_owned(),
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_index(
                Index::drop()
                    .name("idx_settlement_cycle_onchain_hash")
                    .table(SettlementCycle::Table)
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(SettlementCycle::Table)
                    .drop_column(SettlementCycle::OnchainCycleIdHash)
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
}
