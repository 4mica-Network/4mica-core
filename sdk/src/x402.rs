use std::time::{SystemTime, UNIX_EPOCH};

use alloy::primitives::U256;
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use log::warn;
use reqwest::{Client as HttpClient, Method, StatusCode, Url};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
    Client, PaymentGuaranteeRequestClaims, PaymentSignature, SigningScheme, error::FacilitatorError,
};

#[async_trait]
pub trait FlowSigner: Send + Sync {
    async fn sign_payment(
        &self,
        claims: PaymentGuaranteeRequestClaims,
        scheme: SigningScheme,
    ) -> Result<PaymentSignature, FacilitatorError>;
}

#[async_trait]
impl FlowSigner for Client {
    async fn sign_payment(
        &self,
        claims: PaymentGuaranteeRequestClaims,
        scheme: SigningScheme,
    ) -> Result<PaymentSignature, FacilitatorError> {
        self.user
            .sign_payment(claims, scheme)
            .await
            .map_err(FacilitatorError::Signing)
    }
}

/// High-level helper that handles the 402 → tab → signed-claim flow for a paid resource.
#[derive(Clone)]
pub struct X402Flow<S = Client> {
    http: HttpClient,
    base_url: Url,
    signer: S,
}

/// Simple input describing the protected resource the user is trying to access.
#[derive(Debug, Clone)]
pub struct PaymentRequest {
    pub user_address: String,
    pub resource_url: String,
    pub method: Method,
}

/// Final signed payment envelope plus the resolved paymentRequirements and claims.
#[derive(Debug, Clone)]
pub struct PreparedPayment {
    header: String,
    verify_body: Value,
    pub requirements: PaymentRequirements,
    pub claims: PaymentGuaranteeRequestClaims,
    pub signature: PaymentSignature,
}

/// End-to-end payment that has been prepared and settled via the X402 endpoints.
#[derive(Debug, Clone)]
pub struct SettledPayment {
    pub prepared: PreparedPayment,
    settlement: Value,
}

#[derive(Debug, Clone)]
struct ResolvedRequirements {
    requirements: PaymentRequirements,
    accepted: Vec<PaymentRequirements>,
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
    pub extra: Value,
}

#[derive(Deserialize)]
struct SupportedKind {
    scheme: String,
    network: String,
}

impl X402Flow<Client> {
    /// Create a flow helper that will default to the local x402 URL.
    pub fn new(core: Client) -> Result<Self, FacilitatorError> {
        Self::with_base_url(core, "http://localhost:8080/")
    }

    /// Create a flow helper with an explicit base URL (used for /supported lookup).
    pub fn with_base_url(
        core: Client,
        base_url: impl AsRef<str>,
    ) -> Result<Self, FacilitatorError> {
        X402Flow::with_signer(core, base_url)
    }
}

impl<S> X402Flow<S>
where
    S: FlowSigner,
{
    /// Create a flow helper with a custom signer (useful for tests).
    pub fn with_signer(signer: S, base_url: impl AsRef<str>) -> Result<Self, FacilitatorError> {
        let base_url = Url::parse(base_url.as_ref())
            .map_err(|e| FacilitatorError::InvalidUrl(e.to_string()))?;
        Ok(Self {
            http: HttpClient::new(),
            base_url,
            signer,
        })
    }

    /// Build a signed payment envelope for the given paid resource.
    pub async fn prepare_payment(
        &self,
        request: PaymentRequest,
    ) -> Result<PreparedPayment, FacilitatorError> {
        let resolved = self.fetch_payment_requirements(&request).await?;
        let requirements = self
            .align_with_supported(resolved.requirements, &resolved.accepted)
            .await;
        let claims = claims_from_requirements(&requirements, &request.user_address)?;
        let signature = self
            .signer
            .sign_payment(claims.clone(), SigningScheme::Eip712)
            .await?;

        let envelope = json!({
            "x402Version": 1,
            "scheme": requirements.scheme,
            "network": requirements.network,
            "payload": {
                "claims": claims,
                "signature": signature.signature,
                "signingScheme": "eip712"
            }
        });
        let envelope_bytes = serde_json::to_vec(&envelope)
            .map_err(|e| FacilitatorError::EncodeEnvelope(e.to_string()))?;
        let header = BASE64_STANDARD.encode(envelope_bytes);
        let verify_body = json!({
            "x402Version": 1,
            "paymentHeader": header,
            "paymentRequirements": requirements,
        });

        Ok(PreparedPayment {
            header,
            verify_body,
            requirements,
            claims,
            signature,
        })
    }

    /// Prepare and immediately settle a payment through the X402 `/settle` endpoint.
    pub async fn complete_payment(
        &self,
        request: PaymentRequest,
    ) -> Result<SettledPayment, FacilitatorError> {
        let prepared = self.prepare_payment(request).await?;
        self.settle_prepared_payment(prepared).await
    }

    /// Settle a previously prepared payment through the X402 /settle endpoint.
    pub async fn settle_prepared_payment(
        &self,
        payment: PreparedPayment,
    ) -> Result<SettledPayment, FacilitatorError> {
        let url = self
            .base_url
            .join("settle")
            .map_err(|e| FacilitatorError::InvalidUrl(e.to_string()))?;

        let response = self
            .http
            .post(url)
            .json(payment.verify_body())
            .send()
            .await?;

        let status = response.status();
        let settlement: Value = response.json().await?;

        if !status.is_success() {
            return Err(FacilitatorError::SettlementFailed {
                status,
                body: settlement,
            });
        }

        Ok(SettledPayment {
            prepared: payment,
            settlement,
        })
    }

    async fn fetch_payment_requirements(
        &self,
        request: &PaymentRequest,
    ) -> Result<ResolvedRequirements, FacilitatorError> {
        let response = self
            .http
            .request(request.method.clone(), &request.resource_url)
            .send()
            .await?;

        if response.status() != StatusCode::PAYMENT_REQUIRED {
            return Err(FacilitatorError::UnexpectedStatus(response.status()));
        }

        let base_url = response.url().clone();
        let payload: Value = response.json().await?;

        let payment_requirements = payment_requirements_from_payload(&payload)
            .map(parse_payment_requirements_value)
            .transpose()?;
        let accepted = parse_accepted_requirements(&payload);
        let tab_endpoint = tab_endpoint_from_payload(&payload);

        if !accepted.is_empty() {
            if let Some(endpoint) = tab_endpoint {
                return self
                    .request_tab(
                        base_url,
                        endpoint,
                        &request.user_address,
                        payment_requirements,
                        accepted,
                    )
                    .await;
            }
            return Err(FacilitatorError::TabResolutionFailed(
                "accepted returned without tabEndpoint".into(),
            ));
        }

        if let Some(requirements) = payment_requirements {
            return Ok(ResolvedRequirements {
                requirements,
                accepted,
            });
        }

        if let Some(endpoint) = tab_endpoint {
            return self
                .request_tab(base_url, endpoint, &request.user_address, None, accepted)
                .await;
        }

        Err(FacilitatorError::MissingPaymentRequirements)
    }

    async fn request_tab(
        &self,
        base_url: Url,
        endpoint: &str,
        user_address: &str,
        fallback_requirements: Option<PaymentRequirements>,
        fallback_accepted: Vec<PaymentRequirements>,
    ) -> Result<ResolvedRequirements, FacilitatorError> {
        let tab_url = base_url
            .join(endpoint)
            .map_err(|e| FacilitatorError::InvalidUrl(e.to_string()))?;
        let response = self
            .http
            .post(tab_url)
            .json(&json!({ "userAddress": user_address }))
            .send()
            .await?
            .error_for_status()?;
        let payload: Value = response.json().await?;
        let requirements = if let Some(reqs) = payment_requirements_from_payload(&payload) {
            parse_payment_requirements_value(reqs)?
        } else if let Some(fallback) = fallback_requirements {
            fallback
        } else {
            return Err(FacilitatorError::TabResolutionFailed(
                "missing paymentRequirements".into(),
            ));
        };
        let mut accepted = parse_accepted_requirements(&payload);
        if accepted.is_empty() {
            accepted = fallback_accepted;
        }

        Ok(ResolvedRequirements {
            requirements,
            accepted,
        })
    }

    async fn align_with_supported(
        &self,
        mut requirements: PaymentRequirements,
        accepted: &[PaymentRequirements],
    ) -> PaymentRequirements {
        if let Some(chosen) = choose_from_accepted(requirements.clone(), accepted) {
            return chosen;
        }

        let url = match self.base_url.join("supported") {
            Ok(url) => url,
            Err(err) => {
                warn!("failed to build /supported URL from base: {err}");
                return requirements;
            }
        };

        let supported: Vec<SupportedKind> = match self.http.get(url).send().await {
            Ok(resp) if resp.status().is_success() => match resp.json().await {
                Ok(parsed) => parsed,
                Err(err) => {
                    warn!("failed to parse /supported response: {err}");
                    return requirements;
                }
            },
            Ok(resp) => {
                warn!("/supported returned status {}", resp.status());
                return requirements;
            }
            Err(err) => {
                warn!("failed to fetch /supported: {err}");
                return requirements;
            }
        };

        if supported.is_empty() {
            return requirements;
        }

        let scheme_lower = requirements.scheme.to_lowercase();
        if let Some(kind) = supported
            .iter()
            .find(|k| k.scheme.to_lowercase() == scheme_lower)
        {
            requirements.scheme = kind.scheme.clone();
            requirements.network = kind.network.clone();
            return requirements;
        }

        if let Some(kind) = supported
            .iter()
            .find(|k| k.scheme.to_lowercase().contains("4mica"))
        {
            requirements.scheme = kind.scheme.clone();
            requirements.network = kind.network.clone();
            return requirements;
        }

        if let Some(first) = supported.first() {
            requirements.scheme = first.scheme.clone();
            requirements.network = first.network.clone();
        }

        requirements
    }
}

impl PaymentRequest {
    pub fn new(resource_url: impl Into<String>, user_address: impl Into<String>) -> Self {
        Self {
            user_address: user_address.into(),
            resource_url: resource_url.into(),
            method: Method::GET,
        }
    }

    pub fn with_method_str(mut self, method: impl AsRef<str>) -> Result<Self, FacilitatorError> {
        self.method = parse_method(method.as_ref())?;
        Ok(self)
    }
}

impl PreparedPayment {
    /// Base64-encoded payment envelope suitable for the X-PAYMENT header.
    pub fn header(&self) -> &str {
        &self.header
    }

    /// Body expected by the X402 /verify endpoint.
    pub fn verify_body(&self) -> &Value {
        &self.verify_body
    }
}

impl SettledPayment {
    /// Base64-encoded payment envelope suitable for the X-PAYMENT header.
    pub fn header(&self) -> &str {
        self.prepared.header()
    }

    /// Body expected by the X402 /verify endpoint.
    pub fn verify_body(&self) -> &Value {
        self.prepared.verify_body()
    }

    /// Raw settlement response returned by the X402 /settle endpoint.
    pub fn settlement(&self) -> &Value {
        &self.settlement
    }
}

fn claims_from_requirements(
    requirements: &PaymentRequirements,
    user_address: &str,
) -> Result<PaymentGuaranteeRequestClaims, FacilitatorError> {
    let tab_id = extract_u256(&requirements.extra, &["tabId", "tab_id"], "tabId")?;
    let amount = parse_u256(&requirements.max_amount_required)?;
    validate_user_matches(requirements, user_address)?;

    Ok(PaymentGuaranteeRequestClaims::new(
        user_address.to_string(),
        requirements.pay_to.clone(),
        tab_id,
        amount,
        now_ts(),
        Some(requirements.asset.clone()),
    ))
}

fn parse_u256(raw: &str) -> Result<U256, FacilitatorError> {
    let trimmed = raw.trim();
    let value = if let Some(rest) = trimmed.strip_prefix("0x") {
        U256::from_str_radix(rest, 16)
    } else {
        U256::from_str_radix(trimmed, 10)
    };
    value.map_err(|e| FacilitatorError::InvalidNumber {
        field: raw.to_string(),
        source: e.into(),
    })
}

fn parse_method(method: &str) -> Result<Method, FacilitatorError> {
    method
        .parse::<Method>()
        .or_else(|_| method.to_uppercase().parse::<Method>())
        .map_err(|_| FacilitatorError::InvalidMethod(method.to_string()))
}

fn now_ts() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

fn payment_requirements_from_payload(payload: &Value) -> Option<Value> {
    payload.get("paymentRequirements").cloned()
}

fn tab_endpoint_from_payload(payload: &Value) -> Option<&str> {
    payload
        .get("tabEndpoint")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
}

fn parse_payment_requirements_value(value: Value) -> Result<PaymentRequirements, FacilitatorError> {
    serde_json::from_value(value)
        .map_err(|e| FacilitatorError::InvalidPaymentRequirements(e.to_string()))
}

fn parse_accepted_requirements(payload: &Value) -> Vec<PaymentRequirements> {
    payload
        .get("accepted")
        .and_then(|v| v.as_array())
        .map(|list| {
            list.iter()
                .filter_map(|item| serde_json::from_value(item.clone()).ok())
                .collect()
        })
        .unwrap_or_default()
}

fn choose_from_accepted(
    requirements: PaymentRequirements,
    accepted: &[PaymentRequirements],
) -> Option<PaymentRequirements> {
    if accepted.is_empty() {
        return None;
    }

    let target_scheme = requirements.scheme.to_lowercase();

    if let Some(exact_match) = accepted
        .iter()
        .find(|r| r.scheme.to_lowercase() == target_scheme)
    {
        return Some(exact_match.clone());
    }

    if let Some(four_mica) = accepted
        .iter()
        .find(|r| r.scheme.to_lowercase().contains("4mica"))
    {
        return Some(four_mica.clone());
    }

    accepted.first().cloned()
}

fn value_to_string(value: &Value, field: &str) -> Result<String, FacilitatorError> {
    match value {
        Value::String(s) => Ok(s.clone()),
        Value::Number(num) => num
            .as_u64()
            .map(|n| n.to_string())
            .ok_or_else(|| FacilitatorError::InvalidExtra(format!("{field} must be an integer"))),
        other => Err(FacilitatorError::InvalidExtra(format!(
            "{field} must be a string or integer, got {other:?}"
        ))),
    }
}

fn extract_u256(extra: &Value, keys: &[&str], field: &str) -> Result<U256, FacilitatorError> {
    let extra_obj = extra
        .as_object()
        .ok_or_else(|| FacilitatorError::InvalidExtra("extra must be an object".into()))?;
    for key in keys {
        if let Some(value) = extra_obj.get(*key) {
            let raw = value_to_string(value, field)?;
            return parse_u256(&raw);
        }
    }
    Err(FacilitatorError::MissingExtra(field.into()))
}

fn validate_user_matches(
    requirements: &PaymentRequirements,
    expected_user: &str,
) -> Result<(), FacilitatorError> {
    let extra_obj = requirements
        .extra
        .as_object()
        .ok_or_else(|| FacilitatorError::InvalidExtra("extra must be an object".into()))?;
    for key in ["userAddress", "user_address"] {
        if let Some(value) = extra_obj.get(key) {
            let raw = value_to_string(value, key)?;
            if raw.eq_ignore_ascii_case(expected_user) {
                return Ok(());
            }
            return Err(FacilitatorError::UserMismatch {
                found: raw,
                expected: expected_user.to_string(),
            });
        }
    }
    Err(FacilitatorError::MissingExtra("userAddress".into()))
}
