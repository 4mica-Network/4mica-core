use entities::{
    collateral_event, guarantee, sea_orm_active_enums, tabs, user, user_transaction, withdrawal,
};
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
                    .table(user::Entity)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(user::Column::Address)
                            .string()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(user::Column::Version).integer().not_null())
                    .col(
                        ColumnDef::new(user::Column::CreatedAt)
                            .timestamp()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(user::Column::UpdatedAt)
                            .timestamp()
                            .not_null(),
                    )
                    .col(ColumnDef::new(user::Column::Collateral).string().not_null())
                    .col(
                        ColumnDef::new(user::Column::LockedCollateral)
                            .string()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        // ----- Tabs -----
        manager
            .create_table(
                Table::create()
                    .table(tabs::Entity)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(tabs::Column::Id)
                            .string()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(tabs::Column::UserAddress)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(tabs::Column::ServerAddress)
                            .string()
                            .not_null(),
                    )
                    .col(ColumnDef::new(tabs::Column::StartTs).timestamp().not_null())
                    .col(
                        ColumnDef::new(tabs::Column::Status)
                            .custom(Alias::new(
                                sea_orm_active_enums::TabStatus::name().to_string(),
                            ))
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(tabs::Column::SettlementStatus)
                            .custom(Alias::new(
                                sea_orm_active_enums::SettlementStatus::name().to_string(),
                            ))
                            .not_null(),
                    )
                    .col(ColumnDef::new(tabs::Column::Ttl).big_integer().not_null())
                    .col(
                        ColumnDef::new(tabs::Column::CreatedAt)
                            .timestamp()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(tabs::Column::UpdatedAt)
                            .timestamp()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_tabs_user_address")
                            .from(tabs::Entity, tabs::Column::UserAddress)
                            .to(user::Entity, user::Column::Address)
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
                    .table(guarantee::Entity)
                    .if_not_exists()
                    .col(ColumnDef::new(guarantee::Column::TabId).string().not_null())
                    .col(ColumnDef::new(guarantee::Column::ReqId).string().not_null())
                    .col(
                        ColumnDef::new(guarantee::Column::FromAddress)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(guarantee::Column::ToAddress)
                            .string()
                            .not_null(),
                    )
                    .col(ColumnDef::new(guarantee::Column::Value).string().not_null())
                    .col(
                        ColumnDef::new(guarantee::Column::StartTs)
                            .timestamp()
                            .not_null(),
                    )
                    .col(ColumnDef::new(guarantee::Column::Cert).string().null())
                    .col(
                        ColumnDef::new(guarantee::Column::CreatedAt)
                            .timestamp()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(guarantee::Column::UpdatedAt)
                            .timestamp()
                            .not_null(),
                    )
                    .primary_key(
                        Index::create()
                            .col(guarantee::Column::TabId)
                            .col(guarantee::Column::ReqId),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_guarantee_tabs")
                            .from(guarantee::Entity, guarantee::Column::TabId)
                            .to(tabs::Entity, tabs::Column::Id),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_guarantee_user_from")
                            .from(guarantee::Entity, guarantee::Column::FromAddress)
                            .to(user::Entity, user::Column::Address),
                    )
                    .to_owned(),
            )
            .await?;

        // ----- UserTransaction -----
        manager
            .create_table(
                Table::create()
                    .table(user_transaction::Entity)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(user_transaction::Column::TxId)
                            .string()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(user_transaction::Column::UserAddress)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(user_transaction::Column::RecipientAddress)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(user_transaction::Column::Amount)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(user_transaction::Column::Verified)
                            .boolean()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(user_transaction::Column::Finalized)
                            .boolean()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(user_transaction::Column::Failed)
                            .boolean()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(user_transaction::Column::CreatedAt)
                            .timestamp()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(user_transaction::Column::UpdatedAt)
                            .timestamp()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_user_tx_user")
                            .from(
                                user_transaction::Entity,
                                user_transaction::Column::UserAddress,
                            )
                            .to(user::Entity, user::Column::Address),
                    )
                    .to_owned(),
            )
            .await?;

        // ----- Withdrawal -----
        manager
            .create_table(
                Table::create()
                    .table(withdrawal::Entity)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(withdrawal::Column::Id)
                            .string()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(withdrawal::Column::UserAddress)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(withdrawal::Column::RequestedAmount)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(withdrawal::Column::ExecutedAmount)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(withdrawal::Column::RequestTs)
                            .timestamp()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(withdrawal::Column::Status)
                            .custom(Alias::new(
                                sea_orm_active_enums::WithdrawalStatus::name().to_string(),
                            ))
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(withdrawal::Column::CreatedAt)
                            .timestamp()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(withdrawal::Column::UpdatedAt)
                            .timestamp()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_withdrawal_user")
                            .from(withdrawal::Entity, withdrawal::Column::UserAddress)
                            .to(user::Entity, user::Column::Address),
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
                    .table(collateral_event::Entity)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(collateral_event::Column::Id)
                            .string()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(collateral_event::Column::UserAddress)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(collateral_event::Column::Amount)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(collateral_event::Column::EventType)
                            .custom(Alias::new(
                                sea_orm_active_enums::CollateralEventType::name().to_string(),
                            ))
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(collateral_event::Column::TabId)
                            .string()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(collateral_event::Column::ReqId)
                            .string()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(collateral_event::Column::TxId)
                            .string()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(collateral_event::Column::CreatedAt)
                            .timestamp()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_collateral_user")
                            .from(
                                collateral_event::Entity,
                                collateral_event::Column::UserAddress,
                            )
                            .to(user::Entity, user::Column::Address),
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
            .drop_table(Table::drop().table(collateral_event::Entity).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(withdrawal::Entity).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(user_transaction::Entity).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(guarantee::Entity).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(tabs::Entity).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(user::Entity).to_owned())
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
