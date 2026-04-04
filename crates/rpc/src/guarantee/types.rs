use alloy_primitives::{Address, B256, U256};
use serde::{Deserialize, Serialize, de};
use std::str::FromStr;

use super::{codec, compute_validation_request_hash, compute_validation_subject_hash};

const DEFAULT_ASSET_ADDRESS: &str = "0x0000000000000000000000000000000000000000";

pub const GUARANTEE_CLAIMS_VERSION: u64 = 1;
pub const GUARANTEE_CLAIMS_VERSION_V2: u64 = 2;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaymentGuaranteeValidationPolicyV2 {
    pub validation_registry_address: Address,
    pub validation_request_hash: B256,
    pub validation_chain_id: u64,
    pub validator_address: Address,
    pub validator_agent_id: U256,
    pub min_validation_score: u8,
    pub validation_subject_hash: B256,
    #[serde(default)]
    pub job_hash: B256,
    #[serde(default)]
    pub required_validation_tag: String,
}

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validation_policy: Option<PaymentGuaranteeValidationPolicyV2>,
}

impl PaymentGuaranteeClaims {
    pub fn from_request(
        request: &PaymentGuaranteeRequestClaims,
        domain: [u8; 32],
        total_amount: U256,
    ) -> Self {
        let version = request.version();
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
                version,
                validation_policy: None,
            },
            PaymentGuaranteeRequestClaims::V2(claims) => Self {
                domain,
                user_address: claims.user_address.clone(),
                recipient_address: claims.recipient_address.clone(),
                tab_id: claims.tab_id,
                req_id: claims.req_id,
                amount: claims.amount,
                total_amount,
                asset_address: claims.asset_address.clone(),
                timestamp: claims.timestamp,
                version,
                validation_policy: Some(claims.validation_policy.clone()),
            },
        }
    }

    pub fn validate_v2_policy_binding(&self) -> anyhow::Result<()> {
        let Some(policy) = &self.validation_policy else {
            return Ok(());
        };

        validate_policy_binding(
            &self.user_address,
            &self.recipient_address,
            self.tab_id,
            self.req_id,
            self.amount,
            &self.asset_address,
            self.timestamp,
            policy,
        )
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PaymentGuaranteeRequestClaimsV2Unchecked {
    pub user_address: String,
    pub recipient_address: String,
    pub tab_id: U256,
    pub req_id: U256,
    pub amount: U256,
    pub asset_address: String,
    pub timestamp: u64,
    #[serde(flatten)]
    pub validation_policy: PaymentGuaranteeValidationPolicyV2,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PaymentGuaranteeRequestClaimsV2 {
    pub user_address: String,
    pub recipient_address: String,
    pub tab_id: U256,
    pub req_id: U256,
    pub amount: U256,
    pub asset_address: String,
    pub timestamp: u64,
    #[serde(flatten)]
    pub validation_policy: PaymentGuaranteeValidationPolicyV2,
}

#[derive(Debug, Clone)]
pub struct PaymentGuaranteeRequestClaimsV2Builder {
    user_address: String,
    recipient_address: String,
    tab_id: U256,
    req_id: U256,
    amount: U256,
    asset_address: String,
    timestamp: u64,
    validation_policy: Option<PaymentGuaranteeValidationPolicyV2>,
}

impl TryFrom<PaymentGuaranteeRequestClaimsV2Unchecked> for PaymentGuaranteeRequestClaimsV2 {
    type Error = anyhow::Error;

    fn try_from(value: PaymentGuaranteeRequestClaimsV2Unchecked) -> Result<Self, Self::Error> {
        let claims = Self {
            user_address: value.user_address,
            recipient_address: value.recipient_address,
            tab_id: value.tab_id,
            req_id: value.req_id,
            amount: value.amount,
            asset_address: value.asset_address,
            timestamp: value.timestamp,
            validation_policy: value.validation_policy,
        };
        claims.validate()?;
        Ok(claims)
    }
}

impl<'de> Deserialize<'de> for PaymentGuaranteeRequestClaimsV2 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let unchecked = PaymentGuaranteeRequestClaimsV2Unchecked::deserialize(deserializer)?;
        unchecked.try_into().map_err(de::Error::custom)
    }
}

impl PaymentGuaranteeRequestClaimsV2 {
    pub fn builder(
        user_address: String,
        recipient_address: String,
        tab_id: U256,
        req_id: U256,
        amount: U256,
        timestamp: u64,
    ) -> PaymentGuaranteeRequestClaimsV2Builder {
        PaymentGuaranteeRequestClaimsV2Builder {
            user_address,
            recipient_address,
            tab_id,
            req_id,
            amount,
            asset_address: DEFAULT_ASSET_ADDRESS.to_string(),
            timestamp,
            validation_policy: None,
        }
    }

    /// Prefer [`PaymentGuaranteeRequestClaimsV2::builder`] — it is composable and avoids
    /// the long parameter list. This constructor exists only for backward compatibility.
    #[deprecated(note = "use PaymentGuaranteeRequestClaimsV2::builder() instead")]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        user_address: String,
        recipient_address: String,
        tab_id: U256,
        req_id: U256,
        amount: U256,
        timestamp: u64,
        erc20_token: Option<String>,
        validation_registry_address: String,
        validation_request_hash: String,
        validation_chain_id: u64,
        validator_address: String,
        validator_agent_id: U256,
        min_validation_score: u8,
        validation_subject_hash: String,
        job_hash: String,
        required_validation_tag: Option<String>,
    ) -> anyhow::Result<Self> {
        let validation_policy = PaymentGuaranteeValidationPolicyV2 {
            validation_registry_address: parse_address(
                "validation_registry_address",
                &validation_registry_address,
            )?,
            validation_request_hash: parse_b256(
                "validation_request_hash",
                &validation_request_hash,
            )?,
            validation_chain_id,
            validator_address: parse_address("validator_address", &validator_address)?,
            validator_agent_id,
            min_validation_score,
            validation_subject_hash: parse_b256(
                "validation_subject_hash",
                &validation_subject_hash,
            )?,
            job_hash: parse_b256("job_hash", &job_hash)?,
            required_validation_tag: required_validation_tag.unwrap_or_default(),
        };
        let mut builder = Self::builder(
            user_address,
            recipient_address,
            tab_id,
            req_id,
            amount,
            timestamp,
        )
        .validation_policy(validation_policy);
        if let Some(token) = erc20_token {
            builder = builder.asset_address(token);
        }
        builder.build()
    }

    pub fn compute_validation_subject_hash(&self) -> anyhow::Result<[u8; 32]> {
        compute_validation_subject_hash(
            &self.user_address,
            &self.recipient_address,
            self.tab_id,
            self.req_id,
            self.amount,
            &self.asset_address,
            self.timestamp,
        )
    }

    pub fn compute_validation_request_hash(&self) -> anyhow::Result<[u8; 32]> {
        compute_validation_request_hash(&self.validation_policy)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        validate_policy_binding(
            &self.user_address,
            &self.recipient_address,
            self.tab_id,
            self.req_id,
            self.amount,
            &self.asset_address,
            self.timestamp,
            &self.validation_policy,
        )
    }
}

impl PaymentGuaranteeRequestClaimsV2Builder {
    pub fn asset_address(mut self, asset_address: String) -> Self {
        self.asset_address = asset_address;
        self
    }

    pub fn validation_policy(
        mut self,
        validation_policy: PaymentGuaranteeValidationPolicyV2,
    ) -> Self {
        self.validation_policy = Some(validation_policy);
        self
    }

    pub fn build(self) -> anyhow::Result<PaymentGuaranteeRequestClaimsV2> {
        let validation_policy = self
            .validation_policy
            .ok_or_else(|| anyhow::anyhow!("validation_policy is required for v2 claims"))?;
        let claims = PaymentGuaranteeRequestClaimsV2 {
            user_address: self.user_address,
            recipient_address: self.recipient_address,
            tab_id: self.tab_id,
            req_id: self.req_id,
            amount: self.amount,
            asset_address: self.asset_address,
            timestamp: self.timestamp,
            validation_policy,
        };
        claims.validate()?;
        Ok(claims)
    }
}

/// Validates that `validation_subject_hash` and `validation_request_hash` in the policy are
/// canonical for the given payment intent fields. Used by both `PaymentGuaranteeRequestClaimsV2`
/// and `PaymentGuaranteeClaims` to avoid duplicating this logic.
#[allow(clippy::too_many_arguments)]
fn validate_policy_binding(
    user_address: &str,
    recipient_address: &str,
    tab_id: U256,
    req_id: U256,
    amount: U256,
    asset_address: &str,
    timestamp: u64,
    policy: &PaymentGuaranteeValidationPolicyV2,
) -> anyhow::Result<()> {
    if policy.job_hash == B256::ZERO {
        anyhow::bail!("job_hash must be provided for V2 validation policy");
    }

    let expected_subject_hash = compute_validation_subject_hash(
        user_address,
        recipient_address,
        tab_id,
        req_id,
        amount,
        asset_address,
        timestamp,
    )?;
    if policy.validation_subject_hash != B256::from(expected_subject_hash) {
        anyhow::bail!("validation_subject_hash is not canonical for the payment intent fields");
    }

    let expected_request_hash = compute_validation_request_hash(policy)?;
    if policy.validation_request_hash != B256::from(expected_request_hash) {
        anyhow::bail!("validation_request_hash is not canonical for the validation policy fields");
    }

    Ok(())
}

fn parse_address(field: &str, value: &str) -> anyhow::Result<Address> {
    Address::from_str(value).map_err(|_| anyhow::anyhow!("{field} is not a valid address: {value}"))
}

fn parse_b256(field: &str, value: &str) -> anyhow::Result<B256> {
    B256::from_str(value)
        .map_err(|_| anyhow::anyhow!("{field} is not a valid bytes32 hex value: {value}"))
}

pub trait PaymentGuaranteeRequestEssentials {
    fn user_address(&self) -> &str;
    fn recipient_address(&self) -> &str;
    fn tab_id(&self) -> U256;
    fn amount(&self) -> U256;
}

impl PaymentGuaranteeRequestEssentials for PaymentGuaranteeRequestClaims {
    fn user_address(&self) -> &str {
        match self {
            PaymentGuaranteeRequestClaims::V1(claims) => &claims.user_address,
            PaymentGuaranteeRequestClaims::V2(claims) => &claims.user_address,
        }
    }

    fn recipient_address(&self) -> &str {
        match self {
            PaymentGuaranteeRequestClaims::V1(claims) => &claims.recipient_address,
            PaymentGuaranteeRequestClaims::V2(claims) => &claims.recipient_address,
        }
    }

    fn tab_id(&self) -> U256 {
        match self {
            PaymentGuaranteeRequestClaims::V1(claims) => claims.tab_id,
            PaymentGuaranteeRequestClaims::V2(claims) => claims.tab_id,
        }
    }

    fn amount(&self) -> U256 {
        match self {
            PaymentGuaranteeRequestClaims::V1(claims) => claims.amount,
            PaymentGuaranteeRequestClaims::V2(claims) => claims.amount,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "version")]
pub enum PaymentGuaranteeRequestClaims {
    V1(PaymentGuaranteeRequestClaimsV1),
    V2(Box<PaymentGuaranteeRequestClaimsV2>),
}

impl PaymentGuaranteeRequestClaims {
    /// Returns the numeric version identifier for this claims variant.
    pub fn version(&self) -> u64 {
        match self {
            Self::V1(_) => GUARANTEE_CLAIMS_VERSION,
            Self::V2(_) => GUARANTEE_CLAIMS_VERSION_V2,
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
