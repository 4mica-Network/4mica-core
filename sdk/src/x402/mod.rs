use std::time::{SystemTime, UNIX_EPOCH};

use crate::{Client, PaymentSignature, SigningScheme, error::X402Error};
use alloy::{
    primitives::{B256, Bytes, U256},
    signers::Signer,
};
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use reqwest::{Client as HttpClient, Url};
use rpc::{PaymentGuaranteeRequest, PaymentGuaranteeRequestClaims, ValidationRequirement};

pub mod model;

pub use model::*;

#[async_trait]
pub trait FlowSigner: Send + Sync {
    async fn sign_payment(
        &self,
        claims: PaymentGuaranteeRequestClaims,
        scheme: SigningScheme,
    ) -> Result<PaymentSignature, X402Error>;
}

#[async_trait]
impl<S> FlowSigner for Client<S>
where
    S: Signer + Send + Sync,
{
    async fn sign_payment(
        &self,
        claims: PaymentGuaranteeRequestClaims,
        scheme: SigningScheme,
    ) -> Result<PaymentSignature, X402Error> {
        self.payment
            .sign_request(claims, scheme)
            .await
            .map_err(X402Error::Signing)
    }
}

/// High-level helper that handles the 402 -> signed-claim flow for a paid resource.
#[derive(Clone)]
pub struct X402Flow<S> {
    http: HttpClient,
    signer: S,
}

impl<S> X402Flow<S> {
    /// Create a flow helper that will default to the local x402 URL.
    pub fn new(signer: S) -> Result<Self, X402Error> {
        Ok(Self {
            http: HttpClient::new(),
            signer,
        })
    }
}

impl<S> X402Flow<S>
where
    S: FlowSigner,
{
    /// Build a signed payment envelope for the given payment requirements, for x402 version 1.
    pub async fn sign_payment(
        &self,
        payment_requirements: PaymentRequirements,
        user_address: String,
    ) -> Result<X402SignedPayment, X402Error> {
        if payment_requirements.scheme != SCHEME_4MICA_CREDIT {
            return Err(X402Error::InvalidScheme(payment_requirements.scheme));
        }

        let claims = Self::build_claims_request(&payment_requirements, &user_address)?;
        let signature = self
            .signer
            .sign_payment(claims.clone(), SigningScheme::Eip712)
            .await?;

        let payload = PaymentGuaranteeRequest::new(
            claims,
            signature.signature.clone(),
            signature.scheme.clone(),
        );

        let envelope = X402PaymentEnvelope {
            x402_version: 1,
            scheme: payment_requirements.scheme,
            network: payment_requirements.network,
            payload: payload.clone(),
        };

        Self::finish(1, &envelope, payload, signature)
    }

    /// Build a signed payment envelope for the given payment requirements, for x402 version 2.
    pub async fn sign_payment_v2(
        &self,
        payment_required: X402PaymentRequiredV2,
        accepted: PaymentRequirementsV2,
        user_address: String,
    ) -> Result<X402SignedPayment, X402Error> {
        if accepted.scheme != SCHEME_4MICA_CREDIT {
            return Err(X402Error::InvalidScheme(accepted.scheme));
        }
        if payment_required.x402_version != 2 {
            return Err(X402Error::InvalidVersion("expected x402 version 2".into()));
        }

        let claims = Self::build_claims_request(&accepted, &user_address)?;
        let signature = self
            .signer
            .sign_payment(claims.clone(), SigningScheme::Eip712)
            .await?;

        let payload = PaymentGuaranteeRequest::new(
            claims,
            signature.signature.clone(),
            signature.scheme.clone(),
        );

        let envelope = X402PaymentEnvelopeV2 {
            x402_version: 2,
            accepted: accepted.clone(),
            payload: payload.clone(),
            resource: Some(payment_required.resource),
            extensions: payment_required.extensions,
        };

        Self::finish(2, &envelope, payload, signature)
    }

    /// Encode a signed envelope once, keeping both the object form (for a facilitator's
    /// `paymentPayload`) and the base64 form (for the payment request header).
    fn finish(
        x402_version: u8,
        envelope: &impl serde::Serialize,
        payload: PaymentGuaranteeRequest,
        signature: PaymentSignature,
    ) -> Result<X402SignedPayment, X402Error> {
        let envelope =
            serde_json::to_value(envelope).map_err(|e| X402Error::EncodeEnvelope(e.to_string()))?;
        let bytes =
            serde_json::to_vec(&envelope).map_err(|e| X402Error::EncodeEnvelope(e.to_string()))?;

        Ok(X402SignedPayment {
            header: BASE64_STANDARD.encode(bytes),
            envelope,
            x402_version,
            payload,
            signature,
        })
    }

    /// Settle a previously signed payment through the X402 /settle endpoint.
    pub async fn settle_payment(
        &self,
        payment: X402SignedPayment,
        payment_requirements: X402Requirements,
        facilitator_url: &str,
    ) -> Result<X402SettledPayment, X402Error> {
        if payment_requirements.x402_version() != payment.x402_version {
            return Err(X402Error::InvalidVersion(format!(
                "payment is x402 v{}, but requirements are x402 v{}",
                payment.x402_version,
                payment_requirements.x402_version(),
            )));
        }

        let base_url = Url::parse(facilitator_url)
            .map_err(|e| X402Error::InvalidFacilitatorUrl(e.to_string()))?;
        let url = base_url
            .join("settle")
            .map_err(|e| X402Error::InvalidFacilitatorUrl(e.to_string()))?;

        let response = self
            .http
            .post(url)
            .json(&FacilitatorSettleParams {
                x402_version: payment.x402_version,
                payment_payload: payment.envelope.clone(),
                payment_requirements,
            })
            .send()
            .await?;

        let status = response.status();
        let settlement: serde_json::Value = response.json().await?;

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

    /// Build the signed claims for a payment.
    fn build_claims_request(
        requirements: &impl X402PaymentRequirements,
        user_address: &str,
    ) -> Result<PaymentGuaranteeRequestClaims, X402Error> {
        let payment_context = Self::build_payment_context(requirements)?;

        let claims = PaymentGuaranteeRequestClaims::new(
            user_address.to_string(),
            requirements.pay_to().to_string(),
            payment_context.req_id,
            payment_context.amount,
            payment_context.timestamp,
            Some(requirements.asset().to_string()),
        );

        let Some(validation) = parse_validation_extra(requirements)? else {
            return Ok(claims);
        };

        let subject = parse_b256_field("subject", &validation.subject)?;
        let params = match validation.params.as_deref() {
            Some(raw) => parse_bytes_field("params", raw)?,
            None => Bytes::new(),
        };

        Ok(claims.with_validation(ValidationRequirement {
            validator: validation.validator,
            subject,
            deadline: validation.deadline,
            params,
        }))
    }

    fn build_payment_context(
        requirements: &impl X402PaymentRequirements,
    ) -> Result<PaymentContext, X402Error> {
        let req_id_bytes: [u8; 32] = rand::random();
        let req_id = U256::from_be_bytes(req_id_bytes);
        let amount = parse_u256_field("amount", requirements.amount())?;

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or_default();

        Ok(PaymentContext {
            req_id,
            amount,
            timestamp,
        })
    }
}

#[derive(Debug, Clone, Copy)]
struct PaymentContext {
    req_id: U256,
    amount: U256,
    timestamp: u64,
}

fn parse_validation_extra(
    requirements: &impl X402PaymentRequirements,
) -> Result<Option<ValidationExtra>, X402Error> {
    let Some(extra) = requirements.extra() else {
        return Ok(None);
    };
    let parsed: PaymentRequirementsExtra = serde_json::from_value(extra.clone())
        .map_err(|e| X402Error::InvalidExtra(e.to_string()))?;
    Ok(parsed.validation)
}

fn parse_u256_field(field: &str, raw: &str) -> Result<U256, X402Error> {
    let trimmed = raw.trim();
    let value = if let Some(rest) = trimmed.strip_prefix("0x") {
        U256::from_str_radix(rest, 16)
    } else {
        U256::from_str_radix(trimmed, 10)
    };
    value.map_err(|e| X402Error::InvalidNumber {
        field: field.to_string(),
        source: e.into(),
    })
}

fn parse_b256_field(field: &str, raw: &str) -> Result<B256, X402Error> {
    let trimmed = raw.trim();
    <B256 as std::str::FromStr>::from_str(trimmed).map_err(|e| X402Error::InvalidNumber {
        field: field.to_string(),
        source: e.into(),
    })
}

fn parse_bytes_field(field: &str, raw: &str) -> Result<Bytes, X402Error> {
    let trimmed = raw.trim();
    <Bytes as std::str::FromStr>::from_str(trimmed).map_err(|e| X402Error::InvalidNumber {
        field: field.to_string(),
        source: e.into(),
    })
}
