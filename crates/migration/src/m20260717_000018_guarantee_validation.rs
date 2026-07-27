use entities::sea_orm_active_enums;
use sea_orm::entity::prelude::DeriveIden;
use sea_orm_migration::prelude::extension::postgres::Type;
use sea_orm_migration::sea_orm::ActiveEnum;
use sea_orm_migration::{prelude::*, sea_orm::Schema};
use sea_query::Alias;

/// Side table holding the validation requirement of a validation-gated guarantee. Separate from
/// `Guarantee` so the far more common un-validated path stays narrow.
///
/// `subject` is globally unique so that one validator verdict can never satisfy two guarantees.
#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let schema = Schema::new(manager.get_database_backend());
        create_enum_if_missing::<sea_orm_active_enums::GuaranteeValidationStatus>(manager, &schema)
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(GuaranteeValidation::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(GuaranteeValidation::GuaranteeId)
                            .text()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(GuaranteeValidation::Validator)
                            .text()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(GuaranteeValidation::Subject)
                            .text()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(GuaranteeValidation::Deadline)
                            .timestamp()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(GuaranteeValidation::Params)
                            .binary()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(GuaranteeValidation::Status)
                            .custom(Alias::new(
                                sea_orm_active_enums::GuaranteeValidationStatus::name().to_string(),
                            ))
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(GuaranteeValidation::Evidence)
                            .binary()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(GuaranteeValidation::LastPolledAt)
                            .timestamp()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(GuaranteeValidation::DecidedAt)
                            .timestamp()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(GuaranteeValidation::CreatedAt)
                            .timestamp()
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .col(
                        ColumnDef::new(GuaranteeValidation::UpdatedAt)
                            .timestamp()
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_guarantee_validation_guarantee")
                            .from(GuaranteeValidation::Table, GuaranteeValidation::GuaranteeId)
                            .to(Guarantee::Table, Guarantee::GuaranteeId)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .unique()
                    .name("uniq_guarantee_validation_subject")
                    .table(GuaranteeValidation::Table)
                    .col(GuaranteeValidation::Subject)
                    .to_owned(),
            )
            .await?;

        // Drives the sweep: pending requirements ordered by when they expire.
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_guarantee_validation_status_deadline")
                    .table(GuaranteeValidation::Table)
                    .col(GuaranteeValidation::Status)
                    .col(GuaranteeValidation::Deadline)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(GuaranteeValidation::Table).to_owned())
            .await?;
        drop_type_if_exists(
            manager,
            sea_orm_active_enums::GuaranteeValidationStatus::name(),
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

#[derive(DeriveIden)]
enum GuaranteeValidation {
    #[sea_orm(iden = "GuaranteeValidation")]
    Table,
    GuaranteeId,
    Validator,
    Subject,
    Deadline,
    Params,
    Status,
    Evidence,
    LastPolledAt,
    DecidedAt,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
enum Guarantee {
    #[sea_orm(iden = "Guarantee")]
    Table,
    GuaranteeId,
}
