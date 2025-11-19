//! `SeaORM` Entity definition for admin API keys.

use sea_orm::JsonValue;
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "AdminApiKey")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false, column_type = "Uuid")]
    pub id: Uuid,
    pub name: String,
    pub key_hash: String,
    #[sea_orm(column_type = "JsonBinary")]
    pub scopes: JsonValue,
    pub created_at: DateTime,
    pub revoked_at: Option<DateTime>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
