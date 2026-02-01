use reqwest::Url;
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

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct PaymentRequirements {
    pub scheme: String,
    pub network: String,
    pub max_amount_required: String,
    pub resource: Option<String>,
    pub description: Option<String>,
    pub mime_type: Option<String>,
    pub output_schema: Option<Value>,
    pub pay_to: String,
    pub max_timeout_seconds: Option<u64>,
    pub asset: String,
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
    #[serde(alias = "tabEndpoint")]
    pub tab_endpoint: Option<Url>,
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
    pub header: String,
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
#[serde(rename_all = "camelCase")]
pub struct TabRequestParams<TRequirements> {
    pub x402_version: u8,
    pub user_address: String,
    pub payment_requirements: TRequirements,
    pub resource: Option<X402ResourceInfo>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct TabResponse {
    #[serde(alias = "tabId")]
    pub tab_id: String,
    #[serde(alias = "userAddress")]
    pub user_address: String,
    #[serde(alias = "nextReqId", alias = "reqId")]
    pub next_req_id: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct FacilitatorSettleParams {
    pub x402_version: u8,
    pub payment_header: String,
    pub payment_requirements: PaymentRequirements,
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
    pub max_timeout_seconds: Option<u64>,
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
    pub description: String,
    pub mime_type: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct X402PaymentRequiredV2 {
    pub x402_version: u8,
    pub error: Option<String>,
    pub resource: X402ResourceInfo,
    pub accepts: Vec<PaymentRequirementsV2>,
    pub extensions: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct X402PaymentEnvelopeV2 {
    pub x402_version: u8,
    pub accepted: PaymentRequirementsV2,
    pub payload: PaymentGuaranteeRequest,
    pub resource: X402ResourceInfo,
}
