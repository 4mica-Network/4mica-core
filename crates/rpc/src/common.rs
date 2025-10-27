use alloy_primitives::U256;
use serde::{Deserialize, Serialize};

fn default_asset_address() -> String {
    "0x0000000000000000000000000000000000000000".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentGuaranteeClaims {
    pub user_address: String,
    pub recipient_address: String,
    pub tab_id: U256,
    pub req_id: U256,
    pub amount: U256,
    pub timestamp: u64,
    #[serde(default = "default_asset_address")]
    pub asset_address: String,
}

impl PaymentGuaranteeClaims {
    pub fn new(
        user_address: String,
        recipient_address: String,
        tab_id: U256,
        req_id: U256,
        amount: U256,
        timestamp: u64,
        erc20_token: Option<String>,
    ) -> Self {
        let asset_address = erc20_token.unwrap_or(default_asset_address());
        Self {
            user_address,
            recipient_address,
            tab_id,
            req_id,
            amount,
            timestamp,
            asset_address,
        }
    }
}

impl TryInto<Vec<u8>> for PaymentGuaranteeClaims {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<Vec<u8>, Self::Error> {
        crypto::guarantee::encode_guarantee_bytes(
            self.tab_id,
            self.req_id,
            &self.user_address,
            &self.recipient_address,
            self.amount,
            &self.asset_address,
            self.timestamp,
        )
        .map_err(|e| anyhow::anyhow!("Failed to encode guarantee bytes: {}", e))
    }
}

impl TryFrom<&[u8]> for PaymentGuaranteeClaims {
    type Error = anyhow::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let (domain, tab_id, req_id, client, recipient, amount, asset, timestamp) =
            crypto::guarantee::decode_guarantee_bytes(value)?;
        let expected_domain = crypto::guarantee::guarantee_domain_separator()?;
        if domain != expected_domain {
            anyhow::bail!("guarantee domain separator mismatch");
        }
        Ok(PaymentGuaranteeClaims {
            user_address: client.to_string(),
            recipient_address: recipient.to_string(),
            tab_id,
            req_id,
            amount,
            asset_address: asset.to_string(),
            timestamp,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SigningScheme {
    Eip712,
    Eip191, // optional fallback (personal_sign)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentGuaranteeRequest {
    pub claims: PaymentGuaranteeClaims,
    /// 65-byte signature as 0x-prefixed hex
    pub signature: String,
    pub scheme: SigningScheme,
}

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
#[serde(tag = "result", content = "claims")]
pub enum PaymentVerificationResult {
    Verified(PaymentGuaranteeClaims),
    AlreadyVerified(PaymentGuaranteeClaims),
    InvalidCertificate,
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
