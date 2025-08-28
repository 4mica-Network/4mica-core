use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentGuaranteeClaims {
    pub user_addr: String,
    pub recipient_addr: String,
    pub tx_hash: String,
    pub amount: f64,
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
pub struct UserTransactionInfo {
    pub user_addr: String,
    pub recipient_addr: String,
    pub tx_hash: String,
    pub amount: f64,
    pub finalized: bool,
    pub failed: bool,
    pub cert: Option<String>,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfo {
    pub deposit: f64,
    pub available_deposit: f64,
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
pub enum TransactionVerificationResult {
    Verified,
    AlreadyVerified,
    NotFound,
}
