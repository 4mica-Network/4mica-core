//! `SeaORM` Entity definition for auth nonces.

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "AuthNonce")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false, column_type = "Text")]
    pub address: String,
    #[sea_orm(primary_key, auto_increment = false, column_type = "Text")]
    pub nonce: String,
    pub expires_at: DateTime,
    pub used_at: Option<DateTime>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
