use sea_orm_migration::prelude::*;
use std::fmt;

#[derive(DeriveMigrationName)]
pub struct Migration;

pub enum UserAssetBalance {
    Table,
    UserAddress,
    AssetAddress,
    Total,
    Locked,
    Version,
    CreatedAt,
    UpdatedAt,
}

pub enum CollateralEvent {
    Table,
    AssetAddress,
}

pub enum UserTransaction {
    Table,
    AssetAddress,
}

pub enum Withdrawal {
    Table,
    AssetAddress,
}

pub enum Guarantee {
    Table,
    AssetAddress,
}

const ZERO_ADDRESS: &str = "0x0000000000000000000000000000000000000000";

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
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

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
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
            .drop_table(Table::drop().table(UserAssetBalance::Table).to_owned())
            .await?;

        Ok(())
    }
}

impl Iden for UserAssetBalance {
    fn unquoted(&self, s: &mut dyn fmt::Write) {
        use UserAssetBalance::*;
        let name = match self {
            Table => "UserAssetBalance",
            UserAddress => "user_address",
            AssetAddress => "asset_address",
            Total => "total",
            Locked => "locked",
            Version => "version",
            CreatedAt => "created_at",
            UpdatedAt => "updated_at",
        };
        write!(s, "{}", name).unwrap();
    }
}

impl Iden for CollateralEvent {
    fn unquoted(&self, s: &mut dyn fmt::Write) {
        use CollateralEvent::*;
        let name = match self {
            Table => "CollateralEvent",
            AssetAddress => "asset_address",
        };
        write!(s, "{}", name).unwrap();
    }
}

impl Iden for UserTransaction {
    fn unquoted(&self, s: &mut dyn fmt::Write) {
        use UserTransaction::*;
        let name = match self {
            Table => "UserTransaction",
            AssetAddress => "asset_address",
        };
        write!(s, "{}", name).unwrap();
    }
}

impl Iden for Withdrawal {
    fn unquoted(&self, s: &mut dyn fmt::Write) {
        use Withdrawal::*;
        let name = match self {
            Table => "Withdrawal",
            AssetAddress => "asset_address",
        };
        write!(s, "{}", name).unwrap();
    }
}

impl Iden for Guarantee {
    fn unquoted(&self, s: &mut dyn fmt::Write) {
        use Guarantee::*;
        let name = match self {
            Table => "Guarantee",
            AssetAddress => "asset_address",
        };
        write!(s, "{}", name).unwrap();
    }
}
