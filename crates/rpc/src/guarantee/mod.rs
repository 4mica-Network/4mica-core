use alloy_primitives::U256;
use serde::{Deserialize, Serialize};

pub mod codec;

const DEFAULT_ASSET_ADDRESS: &str = "0x0000000000000000000000000000000000000000";

pub const GUARANTEE_CLAIMS_VERSION: u64 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaymentGuaranteeClaims {
    pub domain: [u8; 32],
    pub user_address: String,
    pub recipient_address: String,
    pub tab_id: U256,
    pub req_id: U256,
    pub amount: U256,
    pub total_amount: U256,
    pub asset_address: String,
    pub timestamp: u64,
    pub version: u64,
}

impl PaymentGuaranteeClaims {
    pub fn from_request(
        request: &PaymentGuaranteeRequestClaims,
        domain: [u8; 32],
        total_amount: U256,
    ) -> Self {
        match request {
            PaymentGuaranteeRequestClaims::V1(claims) => Self {
                domain,
                user_address: claims.user_address.clone(),
                recipient_address: claims.recipient_address.clone(),
                tab_id: claims.tab_id,
                req_id: claims.req_id,
                amount: claims.amount,
                total_amount,
                asset_address: claims.asset_address.clone(),
                timestamp: claims.timestamp,
                version: GUARANTEE_CLAIMS_VERSION,
            },
        }
    }
}

impl TryInto<Vec<u8>> for PaymentGuaranteeClaims {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<Vec<u8>, Self::Error> {
        codec::encode_guarantee_claims(self)
            .map_err(|e| anyhow::anyhow!("Failed to encode guarantee bytes: {}", e))
    }
}

impl TryFrom<&[u8]> for PaymentGuaranteeClaims {
    type Error = anyhow::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let claims = codec::decode_guarantee_claims(value)?;
        Ok(claims)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentGuaranteeRequestClaimsV1 {
    pub user_address: String,
    pub recipient_address: String,
    pub tab_id: U256,
    pub req_id: U256,
    pub amount: U256,
    pub asset_address: String,
    pub timestamp: u64,
}

impl PaymentGuaranteeRequestClaimsV1 {
    pub fn new(
        user_address: String,
        recipient_address: String,
        tab_id: U256,
        req_id: U256,
        amount: U256,
        timestamp: u64,
        erc20_token: Option<String>,
    ) -> Self {
        let asset_address = erc20_token.unwrap_or(DEFAULT_ASSET_ADDRESS.to_string());
        Self {
            user_address,
            recipient_address,
            tab_id,
            req_id,
            amount,
            asset_address,
            timestamp,
        }
    }
}

pub trait PaymentGuaranteeRequestEssentials {
    fn user_address(&self) -> &str;

    fn recipient_address(&self) -> &str;

    fn tab_id(&self) -> U256;

    fn req_id(&self) -> U256;

    fn amount(&self) -> U256;
}

impl PaymentGuaranteeRequestEssentials for PaymentGuaranteeRequestClaims {
    fn user_address(&self) -> &str {
        match self {
            PaymentGuaranteeRequestClaims::V1(claims) => &claims.user_address,
        }
    }

    fn recipient_address(&self) -> &str {
        match self {
            PaymentGuaranteeRequestClaims::V1(claims) => &claims.recipient_address,
        }
    }

    fn tab_id(&self) -> U256 {
        match self {
            PaymentGuaranteeRequestClaims::V1(claims) => claims.tab_id,
        }
    }

    fn req_id(&self) -> U256 {
        match self {
            PaymentGuaranteeRequestClaims::V1(claims) => claims.req_id,
        }
    }

    fn amount(&self) -> U256 {
        match self {
            PaymentGuaranteeRequestClaims::V1(claims) => claims.amount,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "version")]
pub enum PaymentGuaranteeRequestClaims {
    V1(PaymentGuaranteeRequestClaimsV1),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SigningScheme {
    Eip712,
    Eip191, // optional fallback (personal_sign)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentGuaranteeRequest {
    pub claims: PaymentGuaranteeRequestClaims,
    /// 65-byte signature as 0x-prefixed hex
    pub signature: String,
    pub scheme: SigningScheme,
}

impl PaymentGuaranteeRequest {
    pub fn new(
        claims: PaymentGuaranteeRequestClaims,
        signature: String,
        scheme: SigningScheme,
    ) -> Self {
        Self {
            claims,
            signature,
            scheme,
        }
    }
}
