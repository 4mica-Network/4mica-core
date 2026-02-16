use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "BlockchainBlock")]
pub struct Model {
    #[sea_orm(primary_key, column_type = "BigInteger")]
    pub chain_id: i64,
    #[sea_orm(primary_key, column_type = "BigInteger")]
    pub block_number: i64,
    #[sea_orm(column_type = "Text")]
    pub block_hash: String,
    pub created_at: DateTime,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
