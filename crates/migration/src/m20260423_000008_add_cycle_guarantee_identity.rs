use sea_orm::entity::prelude::DeriveIden;
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
enum Guarantee {
    #[sea_orm(iden = "Guarantee")]
    Table,
    FromAddress,
    ReqId,
    Version,
    CycleId,
    #[sea_orm(iden = "guarantee_id")]
    IdValue,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_index(
                Index::create()
                    .name("uniq_guarantee_id")
                    .table(Guarantee::Table)
                    .col(Guarantee::IdValue)
                    .unique()
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_guarantee_from_req_version_cycle")
                    .table(Guarantee::Table)
                    .col(Guarantee::FromAddress)
                    .col(Guarantee::ReqId)
                    .col(Guarantee::Version)
                    .col(Guarantee::CycleId)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_index(
                Index::drop()
                    .name("idx_guarantee_from_req_version_cycle")
                    .to_owned(),
            )
            .await?;
        manager
            .drop_index(Index::drop().name("uniq_guarantee_id").to_owned())
            .await?;

        Ok(())
    }
}
