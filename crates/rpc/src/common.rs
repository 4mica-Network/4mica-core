use alloy_primitives::U256;
use serde::{Deserialize, Serialize};

use crate::guarantee::PaymentGuaranteeClaims;

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
pub struct CreatePaymentTabRequest {
    pub user_address: String,
    pub recipient_address: String,
    /// Address of ERC20-Token
    pub erc20_token: Option<String>,
    /// Tab TTL in seconds
    pub ttl: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreatePaymentTabResult {
    pub id: U256,
    pub user_address: String,
    pub recipient_address: String,
    pub erc20_token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfo {
    pub collateral: U256,
    pub available_collateral: U256,
    pub guarantees: Vec<PaymentGuaranteeClaims>,
    pub transactions: Vec<UserTransactionInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TabInfo {
    pub tab_id: U256,
    pub user_address: String,
    pub recipient_address: String,
    pub asset_address: String,
    pub start_timestamp: i64,
    pub ttl_seconds: i64,
    pub status: String,
    pub settlement_status: String,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuaranteeInfo {
    pub tab_id: U256,
    pub req_id: U256,
    pub from_address: String,
    pub to_address: String,
    pub asset_address: String,
    pub amount: U256,
    pub start_timestamp: i64,
    pub certificate: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingRemunerationInfo {
    pub tab: TabInfo,
    pub latest_guarantee: Option<GuaranteeInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollateralEventInfo {
    pub id: String,
    pub user_address: String,
    pub asset_address: String,
    pub amount: U256,
    pub event_type: String,
    pub tab_id: Option<U256>,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateAdminApiKeyRequest {
    pub name: String,
    pub scopes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminApiKeyInfo {
    pub id: String,
    pub name: String,
    pub scopes: Vec<String>,
    pub created_at: i64,
    pub revoked_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminApiKeySecret {
    pub id: String,
    pub name: String,
    pub scopes: Vec<String>,
    pub created_at: i64,
    pub api_key: String,
}
