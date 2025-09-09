use entities::{
    collateral_event, guarantee, sea_orm_active_enums, tabs, user, user_transaction, withdrawal,
};
use sea_orm_migration::prelude::extension::postgres::Type;
use sea_orm_migration::{prelude::*, sea_orm::Schema};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db_backend = manager.get_database_backend();
        let schema = Schema::new(db_backend);

        // ----- Enums (create first) -----
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

        // ----- Tables (via entities) -----
        manager
            .create_table(
                schema
                    .create_table_from_entity(user::Entity)
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;
        for mut idx in schema.create_index_from_entity(user::Entity) {
            manager.create_index(idx.if_not_exists().to_owned()).await?;
        }

        manager
            .create_table(
                schema
                    .create_table_from_entity(tabs::Entity)
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;
        for mut idx in schema.create_index_from_entity(tabs::Entity) {
            manager.create_index(idx.if_not_exists().to_owned()).await?;
        }

        manager
            .create_table(
                schema
                    .create_table_from_entity(guarantee::Entity)
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;
        for mut idx in schema.create_index_from_entity(guarantee::Entity) {
            manager.create_index(idx.if_not_exists().to_owned()).await?;
        }

        manager
            .create_table(
                schema
                    .create_table_from_entity(user_transaction::Entity)
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;
        for mut idx in schema.create_index_from_entity(user_transaction::Entity) {
            manager.create_index(idx.if_not_exists().to_owned()).await?;
        }

        manager
            .create_table(
                schema
                    .create_table_from_entity(withdrawal::Entity)
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;
        for mut idx in schema.create_index_from_entity(withdrawal::Entity) {
            manager.create_index(idx.if_not_exists().to_owned()).await?;
        }

        manager
            .create_table(
                schema
                    .create_table_from_entity(collateral_event::Entity)
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;
        for mut idx in schema.create_index_from_entity(collateral_event::Entity) {
            manager.create_index(idx.if_not_exists().to_owned()).await?;
        }

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // ----- Drop tables in reverse order -----
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

        // drop enum types (lowercase)
        manager
            .drop_type(
                Type::drop()
                    .if_exists()
                    .name("withdrawal_status")
                    .to_owned(),
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

        Ok(())
    }
}
