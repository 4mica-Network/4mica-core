use alloy_primitives::{B256, Bytes, U256};
use serde::{Deserialize, Serialize};

use super::codec;

const DEFAULT_ASSET_ADDRESS: &str = "0x0000000000000000000000000000000000000000";

/// Current guarantee claims version. Clients always issue at this version; core accepts every
/// version in [`super::SUPPORTED_GUARANTEE_VERSIONS`] so older clients keep working.
pub const GUARANTEE_CLAIMS_VERSION: u64 = 1;

/// An agreement, reached out of band between payer and recipient and signed by the payer, that a
/// guarantee only becomes payable once an external validator approves it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationRequirement {
    /// Validator identity, exact-matched against the operator's whitelist. By convention a URL
    /// or a CAIP-10 account id; its adapter decides how to interpret it.
    pub validator: String,
    /// What must be validated. Must be unique per guarantee: a reused subject would let one
    /// verdict satisfy another guarantee.
    pub subject: B256,
    /// Optional cap on how long validation may take, unix seconds. Core may tighten it to fit
    /// the settlement cycle, never extend it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deadline: Option<u64>,
    /// Validator-specific acceptance policy, parsed only by that validator's adapter.
    #[serde(default, skip_serializing_if = "params_is_empty")]
    pub params: Bytes,
}

fn params_is_empty(params: &Bytes) -> bool {
    params.is_empty()
}

/// Guarantee claims as signed by core's BLS key and decoded on-chain. Validation is enforced
/// off-chain and never enters this envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaymentGuaranteeClaims {
    pub domain: [u8; 32],
    pub user_address: String,
    pub recipient_address: String,
    pub cycle_id: U256,
    pub req_id: U256,
    pub amount: U256,
    pub asset_address: String,
    pub timestamp: u64,
    pub version: u64,
}

impl PaymentGuaranteeClaims {
    pub fn from_request(
        request: &PaymentGuaranteeRequestClaims,
        domain: [u8; 32],
        cycle_id: U256,
    ) -> Self {
        Self {
            domain,
            user_address: request.user_address().to_string(),
            recipient_address: request.recipient_address().to_string(),
            cycle_id,
            req_id: request.req_id(),
            amount: request.amount(),
            asset_address: request.asset_address().to_string(),
            timestamp: request.timestamp(),
            version: request.version(),
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
        codec::decode_guarantee_claims(value)
    }
}

/// V1 payment guarantee request claims, as signed by the payer's wallet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaymentGuaranteeRequestClaimsV1 {
    pub user_address: String,
    pub recipient_address: String,
    pub req_id: U256,
    pub amount: U256,
    pub asset_address: String,
    pub timestamp: u64,
    /// Present ⇒ the guarantee is validation-gated. Absent ⇒ payable at issuance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validation: Option<ValidationRequirement>,
}

/// A payment guarantee request, tagged by the claims version it was signed under.
///
/// To add VN: add a variant with its own claims struct, extend the accessors below and append N to
/// [`super::SUPPORTED_GUARANTEE_VERSIONS`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "version")]
pub enum PaymentGuaranteeRequestClaims {
    V1(PaymentGuaranteeRequestClaimsV1),
}

impl PaymentGuaranteeRequestClaims {
    /// Build claims at the current version.
    pub fn new(
        user_address: String,
        recipient_address: String,
        req_id: U256,
        amount: U256,
        timestamp: u64,
        erc20_token: Option<String>,
    ) -> Self {
        Self::V1(PaymentGuaranteeRequestClaimsV1 {
            user_address,
            recipient_address,
            req_id,
            amount,
            asset_address: erc20_token.unwrap_or_else(|| DEFAULT_ASSET_ADDRESS.to_string()),
            timestamp,
            validation: None,
        })
    }

    pub fn with_validation(self, validation: ValidationRequirement) -> Self {
        match self {
            Self::V1(claims) => Self::V1(PaymentGuaranteeRequestClaimsV1 {
                validation: Some(validation),
                ..claims
            }),
        }
    }

    pub fn version(&self) -> u64 {
        match self {
            Self::V1(_) => GUARANTEE_CLAIMS_VERSION,
        }
    }

    pub fn user_address(&self) -> &str {
        match self {
            Self::V1(claims) => &claims.user_address,
        }
    }

    pub fn recipient_address(&self) -> &str {
        match self {
            Self::V1(claims) => &claims.recipient_address,
        }
    }

    pub fn req_id(&self) -> U256 {
        match self {
            Self::V1(claims) => claims.req_id,
        }
    }

    pub fn amount(&self) -> U256 {
        match self {
            Self::V1(claims) => claims.amount,
        }
    }

    pub fn asset_address(&self) -> &str {
        match self {
            Self::V1(claims) => &claims.asset_address,
        }
    }

    pub fn timestamp(&self) -> u64 {
        match self {
            Self::V1(claims) => claims.timestamp,
        }
    }

    pub fn validation(&self) -> Option<&ValidationRequirement> {
        match self {
            Self::V1(claims) => claims.validation.as_ref(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SigningScheme {
    Eip712,
    Eip191,
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
