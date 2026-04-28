use std::time::{SystemTime, UNIX_EPOCH};

use alloy::{
    primitives::{B256, U256},
    signers::Signer,
};
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use reqwest::{Client as HttpClient, Url};
use rpc::{
    PaymentGuaranteeRequest, PaymentGuaranteeRequestClaims, PaymentGuaranteeRequestClaimsV1,
    PaymentGuaranteeRequestClaimsV2, PaymentGuaranteeValidationPolicyV2,
    compute_validation_request_hash, compute_validation_subject_hash,
};
use serde::Serialize;

use crate::{Client, PaymentSignature, SigningScheme, error::X402Error};

pub mod model;

pub use model::*;

#[async_trait]
pub trait FlowSigner: Send + Sync {
    /// Signs any version of guarantee request claims. The single method to implement for V3+.
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
        match claims {
            PaymentGuaranteeRequestClaims::V1(c) => self
                .user
                .sign_payment(c, scheme)
                .await
                .map_err(X402Error::Signing),
            PaymentGuaranteeRequestClaims::V2(c) => self
                .user
                .sign_payment_v2(*c, scheme)
                .await
                .map_err(X402Error::Signing),
        }
    }
}

/// High-level helper that handles the 402 -> tab -> signed-claim flow for a paid resource.
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
        if !payment_requirements.scheme.to_lowercase().contains("4mica") {
            return Err(X402Error::InvalidScheme(payment_requirements.scheme));
        }

        let tab = self
            .request_tab(1, payment_requirements.clone(), user_address.clone(), None)
            .await?;
        let claims = Self::build_claims_request_v1(&payment_requirements, &tab, &user_address)?;
        let signature = self
            .signer
            .sign_payment(
                PaymentGuaranteeRequestClaims::V1(claims.clone()),
                SigningScheme::Eip712,
            )
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
            payload: payload.clone(),
        };

        let envelope =
            serde_json::to_vec(&envelope).map_err(|e| X402Error::EncodeEnvelope(e.to_string()))?;
        let header = BASE64_STANDARD.encode(envelope);

        Ok(X402SignedPayment {
            header,
            payload,
            signature,
        })
    }

    /// Build a signed payment envelope for the given payment requirements, for x402 version 2.
    pub async fn sign_payment_v2(
        &self,
        payment_required: X402PaymentRequiredV2,
        accepted: PaymentRequirementsV2,
        user_address: String,
    ) -> Result<X402SignedPayment, X402Error> {
        if !accepted.scheme.to_lowercase().contains("4mica") {
            return Err(X402Error::InvalidScheme(accepted.scheme));
        }
        if payment_required.x402_version != 2 {
            return Err(X402Error::InvalidVersion("expected x402 version 2".into()));
        }

        let tab = self
            .request_tab(
                2,
                accepted.clone(),
                user_address.clone(),
                Some(payment_required.resource.clone()),
            )
            .await?;
        let claims = Self::build_claims_request_v2(&accepted, &tab, &user_address)?;
        let signature = self
            .signer
            .sign_payment(
                PaymentGuaranteeRequestClaims::V2(Box::new(claims.clone())),
                SigningScheme::Eip712,
            )
            .await?;

        let payload = PaymentGuaranteeRequest::new(
            PaymentGuaranteeRequestClaims::V2(Box::new(claims.clone())),
            signature.signature.clone(),
            signature.scheme.clone(),
        );

        let envelope = X402PaymentEnvelopeV2 {
            x402_version: 2,
            accepted: accepted.clone(),
            payload: payload.clone(),
            resource: payment_required.resource,
        };

        let envelope =
            serde_json::to_vec(&envelope).map_err(|e| X402Error::EncodeEnvelope(e.to_string()))?;
        let header = BASE64_STANDARD.encode(envelope);

        Ok(X402SignedPayment {
            header,
            payload,
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

    async fn request_tab<PR: X402PaymentRequirements + Serialize>(
        &self,
        x402_version: u8,
        payment_requirements: PR,
        user_address: String,
        resource: Option<X402ResourceInfo>,
    ) -> Result<TabResponse, X402Error> {
        let extra: PaymentRequirementsExtra = match payment_requirements.extra() {
            Some(extra) => serde_json::from_value(extra.clone())
                .map_err(|e| X402Error::InvalidExtra(e.to_string()))?,
            None => return Err(X402Error::InvalidExtra("extra is required".into())),
        };
        let Some(tab_url) = extra.tab_endpoint else {
            return Err(X402Error::TabResolutionFailed("missing tabEndpoint".into()));
        };

        let payload = TabRequestParams {
            x402_version,
            user_address,
            payment_requirements,
            resource,
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

    fn build_claims_request_v1(
        requirements: &impl X402PaymentRequirements,
        tab: &TabResponse,
        user_address: &str,
    ) -> Result<PaymentGuaranteeRequestClaimsV1, X402Error> {
        let payment_context = Self::build_payment_context(requirements, tab, user_address)?;

        Ok(PaymentGuaranteeRequestClaimsV1::new(
            user_address.to_string(),
            requirements.pay_to().to_string(),
            payment_context.tab_id,
            payment_context.req_id,
            payment_context.amount,
            payment_context.timestamp,
            Some(requirements.asset().to_string()),
        ))
    }

    fn build_claims_request_v2(
        requirements: &PaymentRequirementsV2,
        tab: &TabResponse,
        user_address: &str,
    ) -> Result<PaymentGuaranteeRequestClaimsV2, X402Error> {
        let payment_context = Self::build_payment_context(requirements, tab, user_address)?;
        let extra = parse_payment_requirements_extra(requirements)?;

        let validation_subject_hash = compute_validation_subject_hash(
            user_address,
            requirements.pay_to(),
            payment_context.req_id,
            payment_context.amount,
            requirements.asset(),
            payment_context.timestamp,
        )
        .map_err(|e| X402Error::InvalidExtra(e.to_string()))?;

        let mut validation_policy = PaymentGuaranteeValidationPolicyV2 {
            validation_registry_address: extra.validation_registry_address.ok_or_else(|| {
                X402Error::InvalidExtra("missing validationRegistryAddress".into())
            })?,
            validation_request_hash: B256::ZERO,
            validation_chain_id: extra
                .validation_chain_id
                .ok_or_else(|| X402Error::InvalidExtra("missing validationChainId".into()))?,
            validator_address: extra
                .validator_address
                .ok_or_else(|| X402Error::InvalidExtra("missing validatorAddress".into()))?,
            validator_agent_id: extra
                .validator_agent_id
                .as_deref()
                .ok_or_else(|| X402Error::InvalidExtra("missing validatorAgentId".into()))
                .and_then(|raw| parse_u256_field("validatorAgentId", raw))?,
            min_validation_score: extra
                .min_validation_score
                .ok_or_else(|| X402Error::InvalidExtra("missing minValidationScore".into()))?,
            validation_subject_hash: B256::from(validation_subject_hash),
            job_hash: extra
                .job_hash
                .as_deref()
                .ok_or_else(|| X402Error::InvalidExtra("missing jobHash".into()))
                .and_then(|raw| parse_b256_field("jobHash", raw))?,
            required_validation_tag: extra.required_validation_tag.unwrap_or_default(),
        };
        validation_policy.validation_request_hash = B256::from(
            compute_validation_request_hash(&validation_policy).map_err(|e| {
                X402Error::InvalidExtra(format!("invalid validation request policy: {e}"))
            })?,
        );

        PaymentGuaranteeRequestClaimsV2::builder(
            user_address.to_string(),
            requirements.pay_to.to_string(),
            payment_context.tab_id,
            payment_context.req_id,
            payment_context.amount,
            payment_context.timestamp,
        )
        .asset_address(requirements.asset.to_string())
        .validation_policy(validation_policy)
        .build()
        .map_err(|e| X402Error::InvalidExtra(e.to_string()))
    }

    fn build_payment_context(
        requirements: &impl X402PaymentRequirements,
        tab: &TabResponse,
        user_address: &str,
    ) -> Result<PaymentContext, X402Error> {
        let tab_id = parse_u256_field("tabId", &tab.tab_id)?;
        let req_id = match tab.next_req_id.as_deref() {
            Some(raw) => parse_u256_field("nextReqId", raw)?,
            None => U256::ZERO,
        };
        let amount = parse_u256_field("amount", requirements.amount())?;

        if !tab.user_address.eq_ignore_ascii_case(user_address) {
            return Err(X402Error::UserMismatch {
                found: tab.user_address.clone(),
                expected: user_address.to_string(),
            });
        }

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or_default();

        Ok(PaymentContext {
            tab_id,
            req_id,
            amount,
            timestamp,
        })
    }
}

#[derive(Debug, Clone, Copy)]
struct PaymentContext {
    tab_id: U256,
    req_id: U256,
    amount: U256,
    timestamp: u64,
}

fn parse_payment_requirements_extra(
    requirements: &impl X402PaymentRequirements,
) -> Result<PaymentRequirementsExtra, X402Error> {
    match requirements.extra() {
        Some(extra) => serde_json::from_value(extra.clone())
            .map_err(|e| X402Error::InvalidExtra(e.to_string())),
        None => Err(X402Error::InvalidExtra("extra is required".into())),
    }
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
