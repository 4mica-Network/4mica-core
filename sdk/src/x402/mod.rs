use std::time::{SystemTime, UNIX_EPOCH};

use alloy::primitives::U256;
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use reqwest::{Client as HttpClient, Url};
use rpc::{
    PaymentGuaranteeRequest, PaymentGuaranteeRequestClaims, PaymentGuaranteeRequestClaimsV1,
};
use serde_json::Value;

use crate::{Client, PaymentSignature, SigningScheme, error::X402Error};

pub mod model;

pub use model::*;

#[async_trait]
pub trait FlowSigner: Send + Sync {
    async fn sign_payment(
        &self,
        claims: PaymentGuaranteeRequestClaimsV1,
        scheme: SigningScheme,
    ) -> Result<PaymentSignature, X402Error>;
}

#[async_trait]
impl FlowSigner for Client {
    async fn sign_payment(
        &self,
        claims: PaymentGuaranteeRequestClaimsV1,
        scheme: SigningScheme,
    ) -> Result<PaymentSignature, X402Error> {
        self.user
            .sign_payment(claims, scheme)
            .await
            .map_err(X402Error::Signing)
    }
}

/// High-level helper that handles the 402 → tab → signed-claim flow for a paid resource.
#[derive(Clone)]
pub struct X402Flow<S = Client> {
    http: HttpClient,
    signer: S,
}

impl X402Flow<Client> {
    /// Create a flow helper that will default to the local x402 URL.
    pub fn new(core: Client) -> Result<Self, X402Error> {
        Self::with_signer(core)
    }
}

impl<S> X402Flow<S>
where
    S: FlowSigner,
{
    /// Create a flow helper with a custom signer.
    pub fn with_signer(signer: S) -> Result<Self, X402Error> {
        Ok(Self {
            http: HttpClient::new(),
            signer,
        })
    }

    /// Build a signed payment envelope for the given payment requirements.
    pub async fn sign_payment(
        &self,
        payment_requirements: PaymentRequirements,
        user_address: String,
    ) -> Result<X402SignedPayment, X402Error> {
        if !payment_requirements.scheme.to_lowercase().contains("4mica") {
            return Err(X402Error::InvalidScheme(payment_requirements.scheme));
        }

        let tab = self
            .request_tab(payment_requirements.clone(), user_address.clone())
            .await?;
        let claims = Self::build_claims_request(&payment_requirements, &tab, &user_address)?;
        let signature = self
            .signer
            .sign_payment(claims.clone(), SigningScheme::Eip712)
            .await?;

        let payload = PaymentGuaranteeRequest::new(
            PaymentGuaranteeRequestClaims::V1(claims.clone()),
            signature.signature.clone(),
            signature.scheme.clone(),
        );

        let envelope = X402PaymentEnvelope {
            x402_version: 1,
            scheme: payment_requirements.scheme,
            network: payment_requirements.network,
            payload,
        };

        let envelope =
            serde_json::to_vec(&envelope).map_err(|e| X402Error::EncodeEnvelope(e.to_string()))?;
        let header = BASE64_STANDARD.encode(envelope);

        Ok(X402SignedPayment {
            header,
            claims,
            signature,
        })
    }

    /// Settle a previously signed payment through the X402 /settle endpoint.
    pub async fn settle_payment(
        &self,
        payment: X402SignedPayment,
        payment_requirements: PaymentRequirements,
        facilitator_url: &str,
    ) -> Result<X402SettledPayment, X402Error> {
        let base_url = Url::parse(facilitator_url)
            .map_err(|e| X402Error::InvalidFacilitatorUrl(e.to_string()))?;
        let url = base_url
            .join("settle")
            .map_err(|e| X402Error::InvalidFacilitatorUrl(e.to_string()))?;

        let response = self
            .http
            .post(url)
            .json(&FacilitatorSettleParams {
                x402_version: 1,
                payment_header: payment.header.clone(),
                payment_requirements,
            })
            .send()
            .await?;

        let status = response.status();
        let settlement: Value = response.json().await?;

        if !status.is_success() {
            return Err(X402Error::SettlementFailed {
                status,
                body: settlement,
            });
        }

        Ok(X402SettledPayment {
            payment,
            settlement,
        })
    }

    async fn request_tab(
        &self,
        payment_requirements: PaymentRequirements,
        user_address: String,
    ) -> Result<TabResponse, X402Error> {
        let extra: PaymentRequirementsExtra =
            serde_json::from_value(payment_requirements.extra.clone())
                .map_err(|e| X402Error::InvalidExtra(e.to_string()))?;
        let Some(tab_url) = extra.tab_endpoint else {
            return Err(X402Error::TabResolutionFailed("missing tabEndpoint".into()));
        };

        let payload = TabRequestParams {
            user_address,
            payment_requirements,
        };
        let response = self
            .http
            .post(tab_url)
            .json(&payload)
            .send()
            .await?
            .error_for_status()?;

        Ok(response.json().await?)
    }

    fn build_claims_request(
        requirements: &PaymentRequirements,
        tab: &TabResponse,
        user_address: &str,
    ) -> Result<PaymentGuaranteeRequestClaimsV1, X402Error> {
        let tab_id = parse_u256(&tab.tab_id)?;
        let req_id = match tab.next_req_id.as_deref() {
            Some(raw) => parse_u256(raw)?,
            None => U256::ZERO,
        };
        let amount = parse_u256(&requirements.max_amount_required)?;

        if !tab.user_address.eq_ignore_ascii_case(user_address) {
            return Err(X402Error::UserMismatch {
                found: tab.user_address.clone(),
                expected: user_address.to_string(),
            });
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or_default();

        Ok(PaymentGuaranteeRequestClaimsV1::new(
            user_address.to_string(),
            requirements.pay_to.clone(),
            tab_id,
            req_id,
            amount,
            now,
            Some(requirements.asset.clone()),
        ))
    }
}

fn parse_u256(raw: &str) -> Result<U256, X402Error> {
    let trimmed = raw.trim();
    let value = if let Some(rest) = trimmed.strip_prefix("0x") {
        U256::from_str_radix(rest, 16)
    } else {
        U256::from_str_radix(trimmed, 10)
    };
    value.map_err(|e| X402Error::InvalidNumber {
        field: raw.to_string(),
        source: e.into(),
    })
}
