use sea_orm::entity::prelude::DeriveIden;
use sea_orm_migration::prelude::*;

const ZERO_ADDRESS: &str = "0x0000000000000000000000000000000000000000";

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Create UserAssetBalance table
        manager
            .create_table(
                Table::create()
                    .table(UserAssetBalance::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(UserAssetBalance::UserAddress)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(UserAssetBalance::AssetAddress)
                            .string()
                            .not_null(),
                    )
                    .col(ColumnDef::new(UserAssetBalance::Total).string().not_null())
                    .col(ColumnDef::new(UserAssetBalance::Locked).string().not_null())
                    .col(
                        ColumnDef::new(UserAssetBalance::Version)
                            .integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(UserAssetBalance::CreatedAt)
                            .date_time()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(UserAssetBalance::UpdatedAt)
                            .date_time()
                            .not_null(),
                    )
                    .primary_key(
                        Index::create()
                            .col(UserAssetBalance::UserAddress)
                            .col(UserAssetBalance::AssetAddress),
                    )
                    .to_owned(),
            )
            .await?;

        // Migrate User.collateral and User.locked_collateral to UserAssetBalance with ZERO_ADDRESS
        manager
            .get_connection()
            .execute_unprepared(&format!(
                r#"
                INSERT INTO "UserAssetBalance" (user_address, asset_address, total, locked, version, created_at, updated_at)
                SELECT address, '{}', collateral, locked_collateral, version, created_at, updated_at
                FROM "User";
                "#,
                ZERO_ADDRESS
            ))
            .await?;

        // Drop the constraint on User table
        manager
            .get_connection()
            .execute_unprepared(
                r#"
                ALTER TABLE "User"
                DROP CONSTRAINT IF EXISTS user_locked_not_greater_than_total;
                "#,
            )
            .await?;

        // Drop collateral and locked_collateral columns from User table
        manager
            .alter_table(
                Table::alter()
                    .table(User::Table)
                    .drop_column(User::Collateral)
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(User::Table)
                    .drop_column(User::LockedCollateral)
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(CollateralEvent::Table)
                    .add_column_if_not_exists(
                        ColumnDef::new(CollateralEvent::AssetAddress)
                            .string()
                            .not_null()
                            .default(ZERO_ADDRESS),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(UserTransaction::Table)
                    .add_column_if_not_exists(
                        ColumnDef::new(UserTransaction::AssetAddress)
                            .string()
                            .not_null()
                            .default(ZERO_ADDRESS),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Withdrawal::Table)
                    .add_column_if_not_exists(
                        ColumnDef::new(Withdrawal::AssetAddress)
                            .string()
                            .not_null()
                            .default(ZERO_ADDRESS),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Guarantee::Table)
                    .add_column_if_not_exists(
                        ColumnDef::new(Guarantee::AssetAddress)
                            .string()
                            .not_null()
                            .default(ZERO_ADDRESS),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Tabs::Table)
                    .add_column_if_not_exists(
                        ColumnDef::new(Tabs::AssetAddress)
                            .string()
                            .not_null()
                            .default(ZERO_ADDRESS),
                    )
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Re-add collateral and locked_collateral columns to User table
        manager
            .alter_table(
                Table::alter()
                    .table(User::Table)
                    .add_column(
                        ColumnDef::new(User::Collateral)
                            .string()
                            .not_null()
                            .default("0"),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(User::Table)
                    .add_column(
                        ColumnDef::new(User::LockedCollateral)
                            .string()
                            .not_null()
                            .default("0"),
                    )
                    .to_owned(),
            )
            .await?;

        // Migrate data back from UserAssetBalance to User
        manager
            .get_connection()
            .execute_unprepared(&format!(
                r#"
                UPDATE "User"
                SET collateral = uab.total,
                    locked_collateral = uab.locked
                FROM "UserAssetBalance" uab
                WHERE "User".address = uab.user_address
                  AND uab.asset_address = '{}';
                "#,
                ZERO_ADDRESS
            ))
            .await?;

        // Re-add the constraint on User table
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

        // Drop AssetAddress columns from other tables
        manager
            .alter_table(
                Table::alter()
                    .table(Withdrawal::Table)
                    .drop_column(Withdrawal::AssetAddress)
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(UserTransaction::Table)
                    .drop_column(UserTransaction::AssetAddress)
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(CollateralEvent::Table)
                    .drop_column(CollateralEvent::AssetAddress)
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Guarantee::Table)
                    .drop_column(Guarantee::AssetAddress)
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Tabs::Table)
                    .drop_column(Tabs::AssetAddress)
                    .to_owned(),
            )
            .await?;

        manager
            .drop_table(Table::drop().table(UserAssetBalance::Table).to_owned())
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
pub enum UserAssetBalance {
    #[sea_orm(iden = "UserAssetBalance")]
    Table,
    UserAddress,
    AssetAddress,
    Total,
    Locked,
    Version,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
pub enum CollateralEvent {
    #[sea_orm(iden = "CollateralEvent")]
    Table,
    AssetAddress,
}

#[derive(DeriveIden)]
pub enum UserTransaction {
    #[sea_orm(iden = "UserTransaction")]
    Table,
    AssetAddress,
}

#[derive(DeriveIden)]
pub enum Withdrawal {
    #[sea_orm(iden = "Withdrawal")]
    Table,
    AssetAddress,
}

#[derive(DeriveIden)]
pub enum Guarantee {
    #[sea_orm(iden = "Guarantee")]
    Table,
    AssetAddress,
}

#[derive(DeriveIden)]
pub enum User {
    #[sea_orm(iden = "User")]
    Table,
    Collateral,
    LockedCollateral,
}

#[derive(DeriveIden)]
pub enum Tabs {
    #[sea_orm(iden = "Tabs")]
    Table,
    AssetAddress,
}
