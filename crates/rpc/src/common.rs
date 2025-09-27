use alloy_primitives::U256;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentGuaranteeClaims {
    pub user_address: String,
    pub recipient_address: String,
    pub tab_id: U256,
    pub req_id: U256,
    pub amount: U256,
    pub timestamp: u64,
}

impl TryInto<Vec<u8>> for PaymentGuaranteeClaims {
    type Error = serde_json::Error;

    fn try_into(self) -> Result<Vec<u8>, Self::Error> {
        serde_json::to_vec(&self)
    }
}

impl TryFrom<Vec<u8>> for PaymentGuaranteeClaims {
    type Error = serde_json::Error;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        serde_json::from_slice(&value)
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
    // ttl in seconds
    pub ttl: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreatePaymentTabResult {
    pub id: U256,
    pub user_address: String,
    pub recipient_address: String,
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
