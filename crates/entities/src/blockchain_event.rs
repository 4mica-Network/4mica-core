use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "BlockchainEvent")]
pub struct Model {
    #[sea_orm(primary_key, column_type = "BigInteger")]
    pub chain_id: i64,
    #[sea_orm(column_type = "BigInteger")]
    pub block_number: i64,
    #[sea_orm(primary_key, column_type = "Text")]
    pub block_hash: String,
    #[sea_orm(column_type = "Text")]
    pub tx_hash: String,
    #[sea_orm(primary_key, column_type = "BigInteger")]
    pub log_index: i64,
    #[sea_orm(column_type = "Text")]
    pub signature: String,
    #[sea_orm(column_type = "Text")]
    pub address: String,
    #[sea_orm(column_type = "Text")]
    pub data: String,
    pub created_at: DateTime,
    /// deterministic handler failure has been recorded so the scanner can skip it instead of wedging.
    #[sea_orm(column_type = "Text", nullable)]
    pub status: Option<String>,
    /// Handler attempts made before the event was dead-lettered.
    pub attempts: Option<i32>,
    /// The deterministic error that caused the dead-letter, for operator diagnosis/replay.
    #[sea_orm(column_type = "Text", nullable)]
    pub last_error: Option<String>,
    /// When the event was dead-lettered.
    pub failed_at: Option<DateTime>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
