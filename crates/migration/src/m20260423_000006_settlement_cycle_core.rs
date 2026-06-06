use entities::sea_orm_active_enums;
use sea_orm::entity::prelude::DeriveIden;
use sea_orm_migration::prelude::extension::postgres::Type;
use sea_orm_migration::sea_orm::ActiveEnum;
use sea_orm_migration::{prelude::*, sea_orm::Schema};
use sea_query::Alias;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
enum SettlementCycle {
    #[sea_orm(iden = "SettlementCycle")]
    Table,
    Id,
    AssetAddress,
    PeriodStart,
    PeriodEnd,
    ResolutionCutoff,
    ClearingCommitDeadline,
    PaymentSubmissionDeadline,
    PaymentFinalityDeadline,
    Status,
    GrossPayableAmount,
    GrossReceivableAmount,
    NetSettlementAmount,
    ClearingBatchHash,
    CommitTxHash,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
enum CycleExposureEdge {
    #[sea_orm(iden = "CycleExposureEdge")]
    Table,
    CycleId,
    Payer,
    Payee,
    AssetAddress,
    GrossAmount,
    FinalizedPayableAmount,
    DisputedAmount,
    CancelledAmount,
    GuaranteeCount,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
enum CycleParticipantPosition {
    #[sea_orm(iden = "CycleParticipantPosition")]
    Table,
    CycleId,
    Participant,
    AssetAddress,
    GrossOutgoing,
    GrossIncoming,
    NetDebit,
    NetCredit,
    Role,
    Status,
    SettlementTxHash,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
enum ClearingBatch {
    #[sea_orm(iden = "ClearingBatch")]
    Table,
    CycleId,
    AssetAddress,
    BatchHash,
    MerkleRoot,
    TotalNetDebit,
    TotalNetCredit,
    DebtorCount,
    CreditorCount,
    CommittedAt,
    CommitTxHash,
    CreatedAt,
    UpdatedAt,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db_backend = manager.get_database_backend();
        let schema = Schema::new(db_backend);

        create_enum_if_missing::<sea_orm_active_enums::GuaranteeSettlementStatus>(manager, &schema)
            .await?;
        create_enum_if_missing::<sea_orm_active_enums::SettlementCycleStatus>(manager, &schema)
            .await?;
        create_enum_if_missing::<sea_orm_active_enums::ParticipantCycleRole>(manager, &schema)
            .await?;
        create_enum_if_missing::<sea_orm_active_enums::ParticipantCycleStatus>(manager, &schema)
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(SettlementCycle::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(SettlementCycle::Id)
                            .string()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(SettlementCycle::AssetAddress)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(SettlementCycle::PeriodStart)
                            .timestamp()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(SettlementCycle::PeriodEnd)
                            .timestamp()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(SettlementCycle::ResolutionCutoff)
                            .timestamp()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(SettlementCycle::ClearingCommitDeadline)
                            .timestamp()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(SettlementCycle::PaymentSubmissionDeadline)
                            .timestamp()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(SettlementCycle::PaymentFinalityDeadline)
                            .timestamp()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(SettlementCycle::Status)
                            .custom(Alias::new(
                                sea_orm_active_enums::SettlementCycleStatus::name().to_string(),
                            ))
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(SettlementCycle::GrossPayableAmount)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(SettlementCycle::GrossReceivableAmount)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(SettlementCycle::NetSettlementAmount)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(SettlementCycle::ClearingBatchHash)
                            .string()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(SettlementCycle::CommitTxHash)
                            .string()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(SettlementCycle::CreatedAt)
                            .timestamp()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(SettlementCycle::UpdatedAt)
                            .timestamp()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_settlement_cycle_asset_status")
                    .table(SettlementCycle::Table)
                    .col(SettlementCycle::AssetAddress)
                    .col(SettlementCycle::Status)
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(CycleExposureEdge::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(CycleExposureEdge::CycleId)
                            .string()
                            .not_null(),
                    )
                    .col(ColumnDef::new(CycleExposureEdge::Payer).string().not_null())
                    .col(ColumnDef::new(CycleExposureEdge::Payee).string().not_null())
                    .col(
                        ColumnDef::new(CycleExposureEdge::AssetAddress)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(CycleExposureEdge::GrossAmount)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(CycleExposureEdge::FinalizedPayableAmount)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(CycleExposureEdge::DisputedAmount)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(CycleExposureEdge::CancelledAmount)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(CycleExposureEdge::GuaranteeCount)
                            .big_integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(CycleExposureEdge::CreatedAt)
                            .timestamp()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(CycleExposureEdge::UpdatedAt)
                            .timestamp()
                            .not_null(),
                    )
                    .primary_key(
                        Index::create()
                            .col(CycleExposureEdge::CycleId)
                            .col(CycleExposureEdge::Payer)
                            .col(CycleExposureEdge::Payee)
                            .col(CycleExposureEdge::AssetAddress),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_cycle_exposure_edge_cycle")
                            .from(CycleExposureEdge::Table, CycleExposureEdge::CycleId)
                            .to(SettlementCycle::Table, SettlementCycle::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_cycle_exposure_edge_cycle_asset")
                    .table(CycleExposureEdge::Table)
                    .col(CycleExposureEdge::CycleId)
                    .col(CycleExposureEdge::AssetAddress)
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(CycleParticipantPosition::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(CycleParticipantPosition::CycleId)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(CycleParticipantPosition::Participant)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(CycleParticipantPosition::AssetAddress)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(CycleParticipantPosition::GrossOutgoing)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(CycleParticipantPosition::GrossIncoming)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(CycleParticipantPosition::NetDebit)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(CycleParticipantPosition::NetCredit)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(CycleParticipantPosition::Role)
                            .custom(Alias::new(
                                sea_orm_active_enums::ParticipantCycleRole::name().to_string(),
                            ))
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(CycleParticipantPosition::Status)
                            .custom(Alias::new(
                                sea_orm_active_enums::ParticipantCycleStatus::name().to_string(),
                            ))
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(CycleParticipantPosition::SettlementTxHash)
                            .string()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(CycleParticipantPosition::CreatedAt)
                            .timestamp()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(CycleParticipantPosition::UpdatedAt)
                            .timestamp()
                            .not_null(),
                    )
                    .primary_key(
                        Index::create()
                            .col(CycleParticipantPosition::CycleId)
                            .col(CycleParticipantPosition::Participant)
                            .col(CycleParticipantPosition::AssetAddress),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_cycle_participant_position_cycle")
                            .from(
                                CycleParticipantPosition::Table,
                                CycleParticipantPosition::CycleId,
                            )
                            .to(SettlementCycle::Table, SettlementCycle::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_cycle_participant_position_cycle_status")
                    .table(CycleParticipantPosition::Table)
                    .col(CycleParticipantPosition::CycleId)
                    .col(CycleParticipantPosition::Status)
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(ClearingBatch::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(ClearingBatch::CycleId)
                            .string()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(ClearingBatch::AssetAddress)
                            .string()
                            .not_null(),
                    )
                    .col(ColumnDef::new(ClearingBatch::BatchHash).string().not_null())
                    .col(
                        ColumnDef::new(ClearingBatch::MerkleRoot)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ClearingBatch::TotalNetDebit)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ClearingBatch::TotalNetCredit)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ClearingBatch::DebtorCount)
                            .big_integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ClearingBatch::CreditorCount)
                            .big_integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ClearingBatch::CommittedAt)
                            .timestamp()
                            .not_null(),
                    )
                    .col(ColumnDef::new(ClearingBatch::CommitTxHash).string().null())
                    .col(
                        ColumnDef::new(ClearingBatch::CreatedAt)
                            .timestamp()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ClearingBatch::UpdatedAt)
                            .timestamp()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_clearing_batch_cycle")
                            .from(ClearingBatch::Table, ClearingBatch::CycleId)
                            .to(SettlementCycle::Table, SettlementCycle::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(ClearingBatch::Table).to_owned())
            .await?;
        manager
            .drop_table(
                Table::drop()
                    .table(CycleParticipantPosition::Table)
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(Table::drop().table(CycleExposureEdge::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(SettlementCycle::Table).to_owned())
            .await?;

        drop_type_if_exists(
            manager,
            sea_orm_active_enums::ParticipantCycleStatus::name(),
        )
        .await?;
        drop_type_if_exists(manager, sea_orm_active_enums::ParticipantCycleRole::name()).await?;
        drop_type_if_exists(manager, sea_orm_active_enums::SettlementCycleStatus::name()).await?;
        drop_type_if_exists(
            manager,
            sea_orm_active_enums::GuaranteeSettlementStatus::name(),
        )
        .await?;

        Ok(())
    }
}

async fn create_enum_if_missing<T>(
    manager: &SchemaManager<'_>,
    schema: &Schema,
) -> Result<(), DbErr>
where
    T: ActiveEnum,
{
    if let Err(err) = manager
        .create_type(schema.create_enum_from_active_enum::<T>())
        .await
        && !is_duplicate_type_error(&err)
    {
        return Err(err);
    }
    Ok(())
}

async fn drop_type_if_exists(manager: &SchemaManager<'_>, type_name: DynIden) -> Result<(), DbErr> {
    manager
        .drop_type(Type::drop().if_exists().name(type_name).to_owned())
        .await
}

fn is_duplicate_type_error(err: &DbErr) -> bool {
    err.to_string().contains("already exists")
}
