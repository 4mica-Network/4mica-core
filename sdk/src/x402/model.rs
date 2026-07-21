use rpc::PaymentGuaranteeRequest;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::PaymentSignature;

pub trait X402PaymentRequirements {
    fn amount(&self) -> &str;
    fn asset(&self) -> &str;
    fn pay_to(&self) -> &str;
    fn extra(&self) -> Option<&Value>;
}

pub const SCHEME_4MICA_CREDIT: &str = "4mica-credit";

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct PaymentRequirements {
    pub scheme: String,
    pub network: String,
    pub max_amount_required: String,
    #[serde(default)]
    pub resource: String,
    #[serde(default)]
    pub description: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_schema: Option<Value>,
    pub pay_to: String,
    #[serde(default)]
    pub max_timeout_seconds: u64,
    pub asset: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extra: Option<Value>,
}

impl X402PaymentRequirements for PaymentRequirements {
    fn amount(&self) -> &str {
        &self.max_amount_required
    }
    fn asset(&self) -> &str {
        &self.asset
    }
    fn pay_to(&self) -> &str {
        &self.pay_to
    }
    fn extra(&self) -> Option<&Value> {
        self.extra.as_ref()
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct PaymentRequirementsExtra {
    /// Present when the payment is validation-gated.
    #[serde(default)]
    pub validation: Option<ValidationExtra>,
}

/// The `extra.validation` object a resource server sends to gate a payment on a validator.
#[derive(Debug, Clone, Deserialize)]
pub struct ValidationExtra {
    /// Validator identity, as whitelisted by core.
    pub validator: String,
    /// 0x-prefixed bytes32 the validator must approve.
    pub subject: String,
    /// Unix seconds; core tightens this to the settlement cycle's resolution cutoff.
    #[serde(default)]
    pub deadline: Option<u64>,
    /// 0x-prefixed validator-specific policy bytes.
    #[serde(default)]
    pub params: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct X402PaymentEnvelope {
    pub x402_version: u8,
    pub scheme: String,
    pub network: String,
    pub payload: PaymentGuaranteeRequest,
}

/// Final signed payment envelope plus the resolved paymentRequirements and claims.
#[derive(Debug, Clone, Deserialize)]
pub struct X402SignedPayment {
    /// Base64 of `envelope`, for the `X-PAYMENT` (v1) / `PAYMENT-SIGNATURE` (v2) request header.
    pub header: String,
    /// The decoded envelope. Facilitators take this as `paymentPayload`, an object — the base64
    /// form is only ever an HTTP header value.
    pub envelope: Value,
    pub x402_version: u8,
    pub payload: PaymentGuaranteeRequest,
    pub signature: PaymentSignature,
}

/// End-to-end payment that has been prepared and settled via the X402 endpoints.
#[derive(Debug, Clone)]
pub struct X402SettledPayment {
    pub payment: X402SignedPayment,
    pub settlement: Value,
}
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum X402Requirements {
    V1(PaymentRequirements),
    V2(PaymentRequirementsV2),
}

impl X402Requirements {
    /// The x402 version whose shape this holds.
    pub fn x402_version(&self) -> u8 {
        match self {
            Self::V1(_) => 1,
            Self::V2(_) => 2,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct FacilitatorSettleParams {
    pub x402_version: u8,
    pub payment_payload: Value,
    pub payment_requirements: X402Requirements,
}

// X402 V2 Models

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct PaymentRequirementsV2 {
    pub scheme: String,
    pub network: String,
    pub asset: String,
    pub amount: String,
    pub pay_to: String,
    #[serde(default)]
    pub max_timeout_seconds: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extra: Option<Value>,
}

impl X402PaymentRequirements for PaymentRequirementsV2 {
    fn amount(&self) -> &str {
        &self.amount
    }
    fn asset(&self) -> &str {
        &self.asset
    }
    fn pay_to(&self) -> &str {
        &self.pay_to
    }
    fn extra(&self) -> Option<&Value> {
        self.extra.as_ref()
    }
}

impl From<PaymentRequirements> for PaymentRequirementsV2 {
    fn from(requirements: PaymentRequirements) -> Self {
        PaymentRequirementsV2 {
            scheme: requirements.scheme,
            network: requirements.network,
            asset: requirements.asset,
            amount: requirements.max_amount_required,
            pay_to: requirements.pay_to,
            max_timeout_seconds: requirements.max_timeout_seconds,
            extra: requirements.extra,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct X402ResourceInfo {
    pub url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct X402PaymentRequiredV2 {
    pub x402_version: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub resource: X402ResourceInfo,
    pub accepts: Vec<PaymentRequirementsV2>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extensions: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct X402PaymentEnvelopeV2 {
    pub x402_version: u8,
    pub accepted: PaymentRequirementsV2,
    pub payload: PaymentGuaranteeRequest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<X402ResourceInfo>,
    /// Echoed back from `PaymentRequired.extensions`. Spec v2 §5.1.2 requires the client to
    /// return at least the info the server advertised.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extensions: Option<Value>,
}
