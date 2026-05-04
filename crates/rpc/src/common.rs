use alloy_primitives::U256;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserTransactionInfo {
    pub user_address: String,
    pub recipient_address: String,
    pub tx_hash: String,
    pub amount: U256,
    pub verified: bool,
    pub finalized: bool,
    pub failed: bool,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollateralEventInfo {
    pub id: String,
    pub user_address: String,
    pub asset_address: String,
    pub amount: U256,
    pub event_type: String,
    pub req_id: Option<U256>,
    pub tx_id: Option<String>,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetBalanceInfo {
    pub user_address: String,
    pub asset_address: String,
    pub total: U256,
    pub locked: U256,
    pub version: i32,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateUserSuspensionRequest {
    pub suspended: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserSuspensionStatus {
    pub user_address: String,
    pub suspended: bool,
    pub updated_at: i64,
}
