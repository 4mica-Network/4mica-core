use std::net::SocketAddr;

use alloy::primitives::U256;
use axum::{
    Json, Router,
    http::{HeaderMap, HeaderValue, StatusCode},
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use rpc::PaymentGuaranteeRequestClaims;

/// Whitelisted validator identity used by the v2 requirements fixture.
pub const VALIDATOR_URI: &str = "eip155:84532:0x2222222222222222222222222222222222222222";
use sdk_4mica::{
    PaymentSignature, SigningScheme,
    x402::{
        FlowSigner, PaymentRequirements, PaymentRequirementsV2, X402PaymentEnvelope,
        X402PaymentRequiredV2, X402ResourceInfo,
    },
};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;

#[derive(Clone)]
pub struct MockSigner;

#[async_trait::async_trait]
impl FlowSigner for MockSigner {
    async fn sign_payment(
        &self,
        _claims: PaymentGuaranteeRequestClaims,
        _scheme: SigningScheme,
    ) -> Result<PaymentSignature, sdk_4mica::error::X402Error> {
        Ok(PaymentSignature {
            signature: "0xsig".into(),
            scheme: SigningScheme::Eip712,
        })
    }
}

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ResourceResponse {
    pub x402_version: u64,
    pub accepts: Vec<PaymentRequirements>,
    pub error: String,
}

/// V1 requirements carry no `extra`: the field only ever existed to advertise a
/// tab endpoint, and v1 claims have no validation policy.
pub fn sample_requirements() -> PaymentRequirements {
    PaymentRequirements {
        scheme: "4mica-credit".into(),
        network: "polygon-amoy".into(),
        max_amount_required: "0xde0b6b3a7640000".into(),
        resource: "http://example.com/resource".into(),
        description: "Protected resource".into(),
        mime_type: None,
        output_schema: None,
        pay_to: "0x000000000000000000000000000000000000dead".into(),
        max_timeout_seconds: 300,
        asset: "0x000000000000000000000000000000000000c0de".into(),
        extra: None,
    }
}

pub fn sample_requirements_v2() -> PaymentRequirementsV2 {
    PaymentRequirementsV2 {
        scheme: "4mica-credit".into(),
        network: "polygon-amoy".into(),
        asset: "0x000000000000000000000000000000000000c0de".into(),
        amount: "0xde0b6b3a7640000".into(),
        pay_to: "0x000000000000000000000000000000000000dead".into(),
        max_timeout_seconds: 300,
        extra: Some(serde_json::json!({
            "validator": VALIDATOR_URI,
            "subject": "0x1111111111111111111111111111111111111111111111111111111111111111",
            "deadline": 1_800_003_600u64,
            "params": "0x0a0b",
        })),
    }
}

pub fn build_router(requirements: PaymentRequirements) -> Router {
    Router::new()
        .route(
            "/resource",
            get({
                let requirements = requirements.clone();
                move || {
                    let requirements = requirements.clone();
                    async move {
                        (
                            StatusCode::PAYMENT_REQUIRED,
                            Json(ResourceResponse {
                                x402_version: 1,
                                accepts: vec![requirements],
                                error: "Payment is required to access this resource".into(),
                            }),
                        )
                    }
                }
            }),
        )
        .route(
            "/resource/v2",
            get({
                move || async move {
                    let payment_required = X402PaymentRequiredV2 {
                        x402_version: 2,
                        error: Some("Payment is required to access this resource".into()),
                        resource: X402ResourceInfo {
                            url: "http://example.com/resource".into(),
                            description: Some("Protected resource".into()),
                            mime_type: Some("application/json".into()),
                        },
                        accepts: vec![sample_requirements_v2()],
                        extensions: None,
                    };

                    let payment_header =
                        serde_json::to_vec(&payment_required).expect("serialize payment required");
                    let payment_header = BASE64_STANDARD.encode(payment_header);

                    let mut headers = HeaderMap::new();
                    headers.insert(
                        "PAYMENT-REQUIRED",
                        HeaderValue::from_str(&payment_header).expect("valid header value"),
                    );

                    (StatusCode::PAYMENT_REQUIRED, headers)
                }
            }),
        )
        .route(
            "/settle",
            post({
                let requirements = requirements.clone();
                move |Json(body): Json<serde_json::Value>| {
                    let requirements = requirements.clone();
                    async move {
                        let payload = body
                            .get("paymentPayload")
                            .expect("body must carry paymentPayload");
                        assert!(
                            payload.is_object(),
                            "paymentPayload must be a decoded object, got {payload}"
                        );
                        assert!(
                            body.get("paymentHeader").is_none(),
                            "paymentHeader is not an x402 facilitator field"
                        );
                        assert!(body.get("paymentRequirements").is_some());
                        assert_eq!(
                            body.get("x402Version").and_then(|v| v.as_u64()),
                            payload.get("x402Version").and_then(|v| v.as_u64()),
                            "x402Version must track the payload, not a hardcoded 1"
                        );

                        let envelope: X402PaymentEnvelope =
                            serde_json::from_value(payload.clone()).expect("parse envelope");

                        let claims = envelope.payload.claims;
                        assert_eq!(claims.recipient_address(), requirements.pay_to);
                        assert_ne!(
                            claims.req_id(),
                            U256::ZERO,
                            "req_id must be a generated nonce, not the zero default"
                        );

                        (
                            StatusCode::OK,
                            Json(serde_json::json!({
                                "settled": true,
                                "networkId": requirements.network
                            })),
                        )
                    }
                }
            }),
        )
}

pub async fn spawn_mock_server() -> (String, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");

    let router = build_router(sample_requirements());

    let handle = tokio::spawn(async move {
        if let Err(err) = axum::serve(listener, router.into_make_service()).await {
            eprintln!("test server stopped: {err}");
        }
    });
    (format!("http://{}", addr), handle)
}

pub async fn request_server_and_fetch_payment_requirements(
    server_url: &str,
) -> anyhow::Result<PaymentRequirements> {
    let resource_url = format!("{}/resource", server_url);
    let response = reqwest::get(resource_url).await?;

    if response.status() == StatusCode::PAYMENT_REQUIRED {
        let body: ResourceResponse = response.json().await?;
        body.accepts
            .into_iter()
            .next()
            .ok_or_else(|| anyhow::anyhow!("No payment requirements found"))
    } else {
        Err(anyhow::anyhow!(
            "Expected 402 status, got {}",
            response.status()
        ))
    }
}

pub async fn request_server_and_fetch_payment_requirements_v2(
    server_url: &str,
) -> anyhow::Result<X402PaymentRequiredV2> {
    let resource_url = format!("{}/resource/v2", server_url);
    let response = reqwest::get(resource_url).await?;

    if response.status() != StatusCode::PAYMENT_REQUIRED {
        return Err(anyhow::anyhow!(
            "Expected 402 status, got {}",
            response.status()
        ));
    }

    let payment_header = response
        .headers()
        .get("payment-required")
        .ok_or_else(|| anyhow::anyhow!("Missing payment-required header"))?
        .to_str()
        .map_err(|e| anyhow::anyhow!("Invalid header value: {}", e))?;

    let decoded = BASE64_STANDARD
        .decode(payment_header)
        .map_err(|e| anyhow::anyhow!("Failed to decode payment header: {}", e))?;
    let payment_required: X402PaymentRequiredV2 = serde_json::from_slice(&decoded)
        .map_err(|e| anyhow::anyhow!("Failed to parse payment-required: {}", e))?;

    Ok(payment_required)
}
