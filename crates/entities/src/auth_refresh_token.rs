//! `SeaORM` Entity definition for auth refresh tokens.

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "AuthRefreshToken")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false, column_type = "Text")]
    pub token_hash: String,
    #[sea_orm(column_type = "Text")]
    pub address: String,
    pub issued_at: DateTime,
    pub expires_at: DateTime,
    pub revoked_at: Option<DateTime>,
    #[sea_orm(column_type = "Text", nullable)]
    pub replaced_by: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
