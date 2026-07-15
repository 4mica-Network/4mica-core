use sea_orm_migration::prelude::*;

/// Add `status_confirmed` to `SettlementCycle`, marking whether an optimistic
/// chain-driven transition has been confirmed by its chain event. Existing rows
/// default to `true` so historical cycles are never re-driven by the migration.
#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
enum SettlementCycle {
    #[sea_orm(iden = "SettlementCycle")]
    Table,
    StatusConfirmed,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(SettlementCycle::Table)
                    .add_column(
                        ColumnDef::new(SettlementCycle::StatusConfirmed)
                            .boolean()
                            .not_null()
                            .default(true),
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
                    .table(SettlementCycle::Table)
                    .drop_column(SettlementCycle::StatusConfirmed)
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
}
