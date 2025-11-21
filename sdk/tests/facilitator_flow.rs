use std::net::SocketAddr;

use axum::{
    Json, Router,
    http::StatusCode,
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use rust_sdk_4mica::{
    PaymentSignature, SigningScheme,
    facilitator::{FacilitatorFlow, FlowSigner, PaymentRequest, PaymentRequirements},
};
use serde_json::{Value, json};
use tokio::net::TcpListener;

#[derive(Clone)]
struct MockSigner;

#[async_trait::async_trait]
impl FlowSigner for MockSigner {
    async fn sign_payment(
        &self,
        _claims: rust_sdk_4mica::PaymentGuaranteeRequestClaims,
        _scheme: SigningScheme,
    ) -> Result<PaymentSignature, rust_sdk_4mica::error::FacilitatorError> {
        Ok(PaymentSignature {
            signature: "0xsig".into(),
            scheme: SigningScheme::Eip712,
        })
    }
}

async fn spawn_router(router: Router) -> (String, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let handle = tokio::spawn(async move {
        if let Err(err) = axum::serve(listener, router.into_make_service()).await {
            eprintln!("test server stopped: {err}");
        }
    });
    (format!("http://{}", addr), handle)
}

fn sample_requirements(user: &str) -> PaymentRequirements {
    PaymentRequirements {
        scheme: "4mica-credit".into(),
        network: "polygon-amoy".into(),
        max_amount_required: "0xde0b6b3a7640000".into(),
        resource: None,
        description: None,
        mime_type: None,
        output_schema: None,
        pay_to: "0x000000000000000000000000000000000000dead".into(),
        max_timeout_seconds: Some(300),
        asset: "0x000000000000000000000000000000000000c0de".into(),
        extra: json!({
            "tabId": "0x1",
            "userAddress": user,
        }),
    }
}

#[tokio::test]
async fn prepare_payment_uses_inline_payment_requirements() {
    let user_address = "0x0000000000000000000000000000000000000001";
    let requirements = sample_requirements(user_address);

    let router = Router::new().route(
        "/resource",
        get({
            let requirements = requirements.clone();
            move || {
                let requirements = requirements.clone();
                async move {
                    (
                        StatusCode::PAYMENT_REQUIRED,
                        Json(json!({ "paymentRequirements": requirements })),
                    )
                }
            }
        }),
    );
    let (base, handle) = spawn_router(router).await;

    let flow: FacilitatorFlow<MockSigner> =
        FacilitatorFlow::with_signer(MockSigner, &base).expect("flow");
    let payment = flow
        .prepare_payment(PaymentRequest::new(
            format!("{base}/resource"),
            user_address,
        ))
        .await
        .expect("prepare payment");

    let envelope_bytes = BASE64_STANDARD
        .decode(payment.header())
        .expect("decode header");
    let envelope: Value = serde_json::from_slice(&envelope_bytes).expect("parse envelope");
    assert_eq!(envelope["scheme"], "4mica-credit");
    assert_eq!(envelope["payload"]["signature"], "0xsig");
    assert_eq!(
        envelope["payload"]["claims"]["recipient_address"],
        requirements.pay_to
    );

    assert_eq!(
        payment.verify_body()["paymentRequirements"]["asset"],
        requirements.asset
    );
    assert_eq!(
        payment.verify_body()["paymentHeader"]
            .as_str()
            .expect("header in body"),
        payment.header()
    );

    handle.abort();
}

#[tokio::test]
async fn prepare_payment_resolves_tab_endpoint() {
    let user_address = "0x0000000000000000000000000000000000000002";
    let requirements = sample_requirements(user_address);

    let router = Router::new()
        .route(
            "/resource",
            get(|| async {
                (
                    StatusCode::PAYMENT_REQUIRED,
                    Json(json!({ "tabEndpoint": "/tab" })),
                )
            }),
        )
        .route(
            "/tab",
            post({
                let requirements = requirements.clone();
                move || {
                    let requirements = requirements.clone();
                    async move { Json(json!({ "paymentRequirements": requirements })) }
                }
            }),
        );
    let (base, handle) = spawn_router(router).await;

    let flow: FacilitatorFlow<MockSigner> =
        FacilitatorFlow::with_signer(MockSigner, &base).expect("flow");
    let payment = flow
        .prepare_payment(PaymentRequest::new(
            format!("{base}/resource"),
            user_address,
        ))
        .await
        .expect("prepare payment");

    assert_eq!(payment.requirements.pay_to, requirements.pay_to);

    handle.abort();
}
