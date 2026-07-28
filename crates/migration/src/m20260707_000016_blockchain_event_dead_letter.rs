use entities::sea_orm_active_enums;
use sea_orm::entity::prelude::DeriveIden;
use sea_orm_migration::prelude::extension::postgres::Type;
use sea_orm_migration::sea_orm::ActiveEnum;
use sea_orm_migration::{prelude::*, sea_orm::Schema};
use sea_query::Alias;

/// Give the scanner a durable place to record an event's processing state, so a
/// single un-handleable ("poison") event can be dead-lettered and skipped instead of wedging the
/// whole indexing pipeline. All columns are nullable and additive: a normally-handled event
/// (predating this column) leaves them NULL, and only genuine deterministic failures are marked
/// `DEAD_LETTERED`. `status` uses the `blockchain_event_status` enum so it stays in sync with the
/// `BlockchainEventStatus` type; `attempts`/`last_error`/`failed_at` capture diagnostics for
/// operator investigation and replay.
#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let schema = Schema::new(manager.get_database_backend());
        create_enum_if_missing::<sea_orm_active_enums::BlockchainEventStatus>(manager, &schema)
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(BlockchainEvent::Table)
                    .add_column(
                        ColumnDef::new(BlockchainEvent::Status)
                            .custom(Alias::new(
                                sea_orm_active_enums::BlockchainEventStatus::name().to_string(),
                            ))
                            .null(),
                    )
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

        drop_type_if_exists(manager, sea_orm_active_enums::BlockchainEventStatus::name()).await?;

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
    let Some(create) = schema.create_enum_from_active_enum::<T>() else {
        return Ok(());
    };
    if let Err(err) = manager.create_type(create).await
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

#[derive(DeriveIden)]
enum BlockchainEvent {
    #[sea_orm(iden = "BlockchainEvent")]
    Table,
    Status,
    Attempts,
    LastError,
    FailedAt,
}
