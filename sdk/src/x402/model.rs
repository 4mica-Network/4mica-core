use reqwest::Url;
use rpc::{PaymentGuaranteeRequest, PaymentGuaranteeRequestClaimsV1};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::PaymentSignature;

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
    pub extra: Value,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PaymentRequirementsExtra {
    #[serde(alias = "tabEndpoint")]
    pub tab_endpoint: Option<Url>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct X402PaymentEnvelope {
    pub x402_version: u64,
    pub scheme: String,
    pub network: String,
    pub payload: PaymentGuaranteeRequest,
}

/// Final signed payment envelope plus the resolved paymentRequirements and claims.
#[derive(Debug, Clone, Deserialize)]
pub struct X402SignedPayment {
    pub header: String,
    pub claims: PaymentGuaranteeRequestClaimsV1,
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
pub struct TabRequestParams {
    pub user_address: String,
    pub payment_requirements: PaymentRequirements,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct TabResponse {
    #[serde(alias = "tabId")]
    pub tab_id: String,
    #[serde(alias = "userAddress")]
    pub user_address: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct FacilitatorSettleParams {
    pub x402_version: u64,
    pub payment_header: String,
    pub payment_requirements: PaymentRequirements,
}
