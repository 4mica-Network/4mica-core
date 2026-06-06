use entities::sea_orm_active_enums;
use sea_orm::entity::prelude::DeriveIden;
use sea_orm_migration::prelude::*;
use sea_orm_migration::sea_orm::ActiveEnum;
use sea_query::Alias;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
enum Guarantee {
    #[sea_orm(iden = "Guarantee")]
    Table,
    FromAddress,
    ToAddress,
    AssetAddress,
    Version,
    CycleId,
    #[sea_orm(iden = "guarantee_id")]
    IdValue,
    SettlementStatus,
    DisputeDeadline,
    FinalizedAt,
    NettedAt,
    SettledAt,
}

#[derive(DeriveIden)]
enum SettlementCycle {
    #[sea_orm(iden = "SettlementCycle")]
    Table,
    Id,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Guarantee::Table)
                    .add_column_if_not_exists(ColumnDef::new(Guarantee::CycleId).string().null())
                    .add_column_if_not_exists(ColumnDef::new(Guarantee::IdValue).string().null())
                    .add_column_if_not_exists(
                        ColumnDef::new(Guarantee::SettlementStatus)
                            .custom(Alias::new(
                                sea_orm_active_enums::GuaranteeSettlementStatus::name().to_string(),
                            ))
                            .not_null()
                            .default("ISSUED"),
                    )
                    .add_column_if_not_exists(
                        ColumnDef::new(Guarantee::DisputeDeadline)
                            .timestamp()
                            .null(),
                    )
                    .add_column_if_not_exists(
                        ColumnDef::new(Guarantee::FinalizedAt).timestamp().null(),
                    )
                    .add_column_if_not_exists(
                        ColumnDef::new(Guarantee::NettedAt).timestamp().null(),
                    )
                    .add_column_if_not_exists(
                        ColumnDef::new(Guarantee::SettledAt).timestamp().null(),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_foreign_key(
                ForeignKey::create()
                    .name("fk_guarantee_settlement_cycle")
                    .from(Guarantee::Table, Guarantee::CycleId)
                    .to(SettlementCycle::Table, SettlementCycle::Id)
                    .on_delete(ForeignKeyAction::SetNull)
                    .on_update(ForeignKeyAction::Cascade)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_guarantee_cycle_settlement_status")
                    .table(Guarantee::Table)
                    .col(Guarantee::CycleId)
                    .col(Guarantee::SettlementStatus)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_guarantee_from_asset_settlement_status")
                    .table(Guarantee::Table)
                    .col(Guarantee::FromAddress)
                    .col(Guarantee::AssetAddress)
                    .col(Guarantee::SettlementStatus)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_guarantee_to_asset_settlement_status")
                    .table(Guarantee::Table)
                    .col(Guarantee::ToAddress)
                    .col(Guarantee::AssetAddress)
                    .col(Guarantee::SettlementStatus)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_guarantee_version_settlement_status")
                    .table(Guarantee::Table)
                    .col(Guarantee::Version)
                    .col(Guarantee::SettlementStatus)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_guarantee_id")
                    .table(Guarantee::Table)
                    .col(Guarantee::IdValue)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_index(Index::drop().name("idx_guarantee_id").to_owned())
            .await?;
        manager
            .drop_index(
                Index::drop()
                    .name("idx_guarantee_version_settlement_status")
                    .to_owned(),
            )
            .await?;
        manager
            .drop_index(
                Index::drop()
                    .name("idx_guarantee_to_asset_settlement_status")
                    .to_owned(),
            )
            .await?;
        manager
            .drop_index(
                Index::drop()
                    .name("idx_guarantee_from_asset_settlement_status")
                    .to_owned(),
            )
            .await?;
        manager
            .drop_index(
                Index::drop()
                    .name("idx_guarantee_cycle_settlement_status")
                    .to_owned(),
            )
            .await?;
        manager
            .drop_foreign_key(
                ForeignKey::drop()
                    .name("fk_guarantee_settlement_cycle")
                    .table(Guarantee::Table)
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(Guarantee::Table)
                    .drop_column(Guarantee::SettledAt)
                    .drop_column(Guarantee::NettedAt)
                    .drop_column(Guarantee::FinalizedAt)
                    .drop_column(Guarantee::DisputeDeadline)
                    .drop_column(Guarantee::SettlementStatus)
                    .drop_column(Guarantee::IdValue)
                    .drop_column(Guarantee::CycleId)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}
