//! `SeaORM` Entity representing per-asset balances

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "UserAssetBalance")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false, column_type = "Text")]
    pub user_address: String,
    #[sea_orm(primary_key, auto_increment = false, column_type = "Text")]
    pub asset_address: String,
    #[sea_orm(column_type = "Text")]
    pub total: String,
    #[sea_orm(column_type = "Text")]
    pub locked: String,
    pub version: i32,
    pub created_at: DateTime,
    pub updated_at: DateTime,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::user::Entity",
        from = "Column::UserAddress",
        to = "super::user::Column::Address",
        on_update = "Cascade",
        on_delete = "Cascade"
    )]
    User,
}

impl Related<super::user::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::User.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
