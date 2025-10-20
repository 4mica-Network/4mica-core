use entities::sea_orm_active_enums;
use sea_orm::entity::prelude::DeriveIden;
use sea_orm_migration::prelude::extension::postgres::Type;
use sea_orm_migration::sea_orm::ActiveEnum;
use sea_orm_migration::{prelude::*, sea_orm::Schema};
use sea_query::Alias;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db_backend = manager.get_database_backend();
        let schema = Schema::new(db_backend);

        // ----- Enums (must be created before tables use them) -----
        manager
            .create_type(
                schema.create_enum_from_active_enum::<sea_orm_active_enums::CollateralEventType>(),
            )
            .await?;
        manager
            .create_type(
                schema.create_enum_from_active_enum::<sea_orm_active_enums::SettlementStatus>(),
            )
            .await?;
        manager
            .create_type(schema.create_enum_from_active_enum::<sea_orm_active_enums::TabStatus>())
            .await?;
        manager
            .create_type(
                schema.create_enum_from_active_enum::<sea_orm_active_enums::WithdrawalStatus>(),
            )
            .await?;

        // ----- User -----
        manager
            .create_table(
                Table::create()
                    .table(User::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(User::Address)
                            .string()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(User::Version).integer().not_null())
                    .col(ColumnDef::new(User::CreatedAt).timestamp().not_null())
                    .col(ColumnDef::new(User::UpdatedAt).timestamp().not_null())
                    .col(ColumnDef::new(User::Collateral).string().not_null())
                    .col(ColumnDef::new(User::LockedCollateral).string().not_null())
                    .to_owned(),
            )
            .await?;
        manager
            .get_connection()
            .execute_unprepared(
                r#"
        ALTER TABLE "User"
        ADD CONSTRAINT user_locked_not_greater_than_total
        CHECK ((locked_collateral::numeric) <= (collateral::numeric));
        "#,
            )
            .await?;
        // ----- Tabs -----
        manager
            .create_table(
                Table::create()
                    .table(Tabs::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(Tabs::Id).string().not_null().primary_key())
                    .col(ColumnDef::new(Tabs::UserAddress).string().not_null())
                    .col(ColumnDef::new(Tabs::ServerAddress).string().not_null())
                    .col(ColumnDef::new(Tabs::StartTs).timestamp().not_null())
                    .col(
                        ColumnDef::new(Tabs::Status)
                            .custom(Alias::new(
                                sea_orm_active_enums::TabStatus::name().to_string(),
                            ))
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Tabs::SettlementStatus)
                            .custom(Alias::new(
                                sea_orm_active_enums::SettlementStatus::name().to_string(),
                            ))
                            .not_null(),
                    )
                    .col(ColumnDef::new(Tabs::Ttl).big_integer().not_null())
                    .col(ColumnDef::new(Tabs::CreatedAt).timestamp().not_null())
                    .col(ColumnDef::new(Tabs::UpdatedAt).timestamp().not_null())
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_tabs_user_address")
                            .from(Tabs::Table, Tabs::UserAddress)
                            .to(User::Table, User::Address)
                            .on_delete(ForeignKeyAction::Restrict)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        // ----- Guarantee -----
        manager
            .create_table(
                Table::create()
                    .table(Guarantee::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(Guarantee::TabId).string().not_null())
                    .col(ColumnDef::new(Guarantee::ReqId).string().not_null())
                    .col(ColumnDef::new(Guarantee::FromAddress).string().not_null())
                    .col(ColumnDef::new(Guarantee::ToAddress).string().not_null())
                    .col(ColumnDef::new(Guarantee::Value).string().not_null())
                    .col(ColumnDef::new(Guarantee::StartTs).timestamp().not_null())
                    .col(ColumnDef::new(Guarantee::Cert).string().null())
                    .col(ColumnDef::new(Guarantee::CreatedAt).timestamp().not_null())
                    .col(ColumnDef::new(Guarantee::UpdatedAt).timestamp().not_null())
                    .primary_key(Index::create().col(Guarantee::TabId).col(Guarantee::ReqId))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_guarantee_tabs")
                            .from(Guarantee::Table, Guarantee::TabId)
                            .to(Tabs::Table, Tabs::Id),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_guarantee_user_from")
                            .from(Guarantee::Table, Guarantee::FromAddress)
                            .to(User::Table, User::Address),
                    )
                    .to_owned(),
            )
            .await?;

        // ----- UserTransaction -----
        manager
            .create_table(
                Table::create()
                    .table(UserTransaction::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(UserTransaction::TxId)
                            .string()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(UserTransaction::UserAddress)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(UserTransaction::RecipientAddress)
                            .string()
                            .not_null(),
                    )
                    .col(ColumnDef::new(UserTransaction::Amount).string().not_null())
                    .col(
                        ColumnDef::new(UserTransaction::Verified)
                            .boolean()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(UserTransaction::Finalized)
                            .boolean()
                            .not_null(),
                    )
                    .col(ColumnDef::new(UserTransaction::Failed).boolean().not_null())
                    .col(
                        ColumnDef::new(UserTransaction::CreatedAt)
                            .timestamp()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(UserTransaction::UpdatedAt)
                            .timestamp()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_user_tx_user")
                            .from(UserTransaction::Table, UserTransaction::UserAddress)
                            .to(User::Table, User::Address),
                    )
                    .to_owned(),
            )
            .await?;

        // ----- Withdrawal -----
        manager
            .create_table(
                Table::create()
                    .table(Withdrawal::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Withdrawal::Id)
                            .string()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(Withdrawal::UserAddress).string().not_null())
                    .col(
                        ColumnDef::new(Withdrawal::RequestedAmount)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Withdrawal::ExecutedAmount)
                            .string()
                            .not_null(),
                    )
                    .col(ColumnDef::new(Withdrawal::RequestTs).timestamp().not_null())
                    .col(
                        ColumnDef::new(Withdrawal::Status)
                            .custom(Alias::new(
                                sea_orm_active_enums::WithdrawalStatus::name().to_string(),
                            ))
                            .not_null(),
                    )
                    .col(ColumnDef::new(Withdrawal::CreatedAt).timestamp().not_null())
                    .col(ColumnDef::new(Withdrawal::UpdatedAt).timestamp().not_null())
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_withdrawal_user")
                            .from(Withdrawal::Table, Withdrawal::UserAddress)
                            .to(User::Table, User::Address),
                    )
                    .to_owned(),
            )
            .await?;

        // ----- Withdrawal Partial Constraints -----
        // enforce: at most one PENDING withdrawal per user
        manager
            .get_connection()
            .execute_unprepared(
                r#"
            CREATE UNIQUE INDEX uniq_user_pending_withdrawal
            ON "Withdrawal" (user_address)
            WHERE status = 'PENDING';
            "#,
            )
            .await?;

        // ----- CollateralEvent -----
        manager
            .create_table(
                Table::create()
                    .table(CollateralEvent::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(CollateralEvent::Id)
                            .string()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(CollateralEvent::UserAddress)
                            .string()
                            .not_null(),
                    )
                    .col(ColumnDef::new(CollateralEvent::Amount).string().not_null())
                    .col(
                        ColumnDef::new(CollateralEvent::EventType)
                            .custom(Alias::new(
                                sea_orm_active_enums::CollateralEventType::name().to_string(),
                            ))
                            .not_null(),
                    )
                    .col(ColumnDef::new(CollateralEvent::TabId).string().null())
                    .col(ColumnDef::new(CollateralEvent::ReqId).string().null())
                    .col(ColumnDef::new(CollateralEvent::TxId).string().null())
                    .col(
                        ColumnDef::new(CollateralEvent::CreatedAt)
                            .timestamp()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_collateral_user")
                            .from(CollateralEvent::Table, CollateralEvent::UserAddress)
                            .to(User::Table, User::Address),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .get_connection()
            .execute_unprepared(
                r#"
        CREATE UNIQUE INDEX uniq_tab_remunerate_event
        ON "CollateralEvent" (tab_id)
        WHERE event_type = 'REMUNERATE';
        "#,
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(CollateralEvent::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Withdrawal::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(UserTransaction::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Guarantee::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Tabs::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(User::Table).to_owned())
            .await?;
        manager
            .get_connection()
            .execute_unprepared(
                r#"
        ALTER TABLE "User"
        DROP CONSTRAINT IF EXISTS user_locked_not_greater_than_total;
        "#,
            )
            .await?;
        manager
            .drop_type(
                Type::drop()
                    .if_exists()
                    .name("withdrawal_status")
                    .to_owned(),
            )
            .await?;
        manager
            .get_connection()
            .execute_unprepared(
                r#"
                DROP INDEX IF EXISTS uniq_user_pending_withdrawal;
                "#,
            )
            .await?;
        manager
            .drop_type(Type::drop().if_exists().name("tab_status").to_owned())
            .await?;
        manager
            .drop_type(
                Type::drop()
                    .if_exists()
                    .name("settlement_status")
                    .to_owned(),
            )
            .await?;
        manager
            .drop_type(
                Type::drop()
                    .if_exists()
                    .name("collateral_event_type")
                    .to_owned(),
            )
            .await?;
        manager
            .get_connection()
            .execute_unprepared(
                r#"
                DROP INDEX IF EXISTS uniq_tab_remunerate_event;
                "#,
            )
            .await?;
        Ok(())
    }
}

#[derive(DeriveIden)]
pub enum User {
    #[sea_orm(iden = "User")]
    Table,
    Address,
    Version,
    CreatedAt,
    UpdatedAt,
    Collateral,
    LockedCollateral,
}

#[derive(DeriveIden)]
pub enum Tabs {
    #[sea_orm(iden = "Tabs")]
    Table,
    Id,
    UserAddress,
    ServerAddress,
    StartTs,
    Status,
    SettlementStatus,
    Ttl,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
pub enum Guarantee {
    #[sea_orm(iden = "Guarantee")]
    Table,
    TabId,
    ReqId,
    FromAddress,
    ToAddress,
    Value,
    StartTs,
    Cert,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
pub enum UserTransaction {
    #[sea_orm(iden = "UserTransaction")]
    Table,
    TxId,
    UserAddress,
    RecipientAddress,
    Amount,
    Verified,
    Finalized,
    Failed,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
pub enum Withdrawal {
    #[sea_orm(iden = "Withdrawal")]
    Table,
    Id,
    UserAddress,
    RequestedAmount,
    ExecutedAmount,
    RequestTs,
    Status,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
pub enum CollateralEvent {
    #[sea_orm(iden = "CollateralEvent")]
    Table,
    Id,
    UserAddress,
    Amount,
    EventType,
    TabId,
    ReqId,
    TxId,
    CreatedAt,
}
