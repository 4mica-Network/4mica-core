use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use axum::{
    Json, Router,
    http::StatusCode,
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use rust_sdk_4mica::{
    PaymentSignature, SigningScheme,
    x402::{FlowSigner, PaymentRequest, PaymentRequirements, X402Flow},
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

    let flow: X402Flow<MockSigner> = X402Flow::with_signer(MockSigner, &base).expect("flow");
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

    let flow: X402Flow<MockSigner> = X402Flow::with_signer(MockSigner, &base).expect("flow");
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

#[tokio::test]
async fn prepare_payment_fetches_tab_when_accepts_present() {
    let user_address = "0x0000000000000000000000000000000000000004";
    let mut inline_requirements = sample_requirements(user_address);
    inline_requirements.extra["tabId"] = json!("0x1");

    let mut tab_requirements = sample_requirements(user_address);
    tab_requirements.extra["tabId"] = json!("0x2");

    let tab_calls = Arc::new(AtomicUsize::new(0));

    let router = Router::new()
        .route(
            "/resource",
            get({
                let inline_requirements = inline_requirements.clone();
                move || {
                    let inline_requirements = inline_requirements.clone();
                    async move {
                        (
                            StatusCode::PAYMENT_REQUIRED,
                            Json(json!({
                                "paymentRequirements": inline_requirements,
                                "accepted": [inline_requirements],
                                "tabEndpoint": "/tab"
                            })),
                        )
                    }
                }
            }),
        )
        .route(
            "/tab",
            post({
                let tab_calls = tab_calls.clone();
                let tab_requirements = tab_requirements.clone();
                move || {
                    let tab_calls = tab_calls.clone();
                    let tab_requirements = tab_requirements.clone();
                    async move {
                        tab_calls.fetch_add(1, Ordering::SeqCst);
                        Json(json!({
                            "paymentRequirements": tab_requirements,
                            "accepted": [tab_requirements],
                        }))
                    }
                }
            }),
        );

    let (base, handle) = spawn_router(router).await;

    let flow: X402Flow<MockSigner> = X402Flow::with_signer(MockSigner, &base).expect("flow");
    let payment = flow
        .prepare_payment(PaymentRequest::new(
            format!("{base}/resource"),
            user_address,
        ))
        .await
        .expect("prepare payment");

    assert_eq!(payment.requirements.extra["tabId"], json!("0x2"));
    assert_eq!(tab_calls.load(Ordering::SeqCst), 1);

    handle.abort();
}

#[tokio::test]
async fn complete_payment_prepares_and_settles() {
    let user_address = "0x0000000000000000000000000000000000000003";
    let requirements = sample_requirements(user_address);

    let router = Router::new()
        .route(
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
        )
        .route(
            "/settle",
            post({
                let requirements = requirements.clone();
                move |Json(body): Json<Value>| {
                    let requirements = requirements.clone();
                    async move {
                        let header = body["paymentHeader"].as_str().expect("paymentHeader");
                        let decoded = BASE64_STANDARD
                            .decode(header)
                            .expect("decode payment header");
                        let envelope: Value =
                            serde_json::from_slice(&decoded).expect("parse envelope");

                        assert_eq!(
                            envelope["payload"]["claims"]["recipient_address"],
                            requirements.pay_to
                        );
                        assert_eq!(body["paymentRequirements"]["extra"]["tabId"], json!("0x1"));

                        (
                            StatusCode::OK,
                            Json(json!({
                                "settled": true,
                                "networkId": requirements.network
                            })),
                        )
                    }
                }
            }),
        );

    let (base, handle) = spawn_router(router).await;
    let flow: X402Flow<MockSigner> = X402Flow::with_signer(MockSigner, &base).expect("flow");
    let prepared = flow
        .prepare_payment(PaymentRequest::new(
            format!("{base}/resource"),
            user_address,
        ))
        .await
        .expect("prepare payment");
    let settled = flow
        .settle_prepared_payment(prepared)
        .await
        .expect("settle payment");

    assert_eq!(settled.prepared.requirements.pay_to, requirements.pay_to);
    assert_eq!(settled.settlement()["settled"], true);
    assert_eq!(settled.settlement()["networkId"], requirements.network);

    handle.abort();
}

#[tokio::test]
async fn prepare_payment_merges_tab_metadata_into_template() {
    let user_address = "0x0000000000000000000000000000000000000005";
    let mut template = sample_requirements(user_address);
    template.pay_to = "0x0000000000000000000000000000000000000bad".into();
    template.asset = "0x0000000000000000000000000000000000000bad".into();
    template.max_timeout_seconds = None;
    {
        let extra = template
            .extra
            .as_object_mut()
            .expect("template extra object");
        extra.insert("tabId".into(), json!("0x0"));
        extra.insert(
            "userAddress".into(),
            json!("0x0000000000000000000000000000000000000bad"),
        );
    }

    let tab_recipient = "0x000000000000000000000000000000000000beef";
    let tab_asset = "0x000000000000000000000000000000000000cafe";

    let router = Router::new()
        .route(
            "/resource",
            get({
                let template = template.clone();
                move || {
                    let template = template.clone();
                    async move {
                        (
                            StatusCode::PAYMENT_REQUIRED,
                            Json(json!({
                                "paymentRequirements": template,
                                "tabEndpoint": "/tab"
                            })),
                        )
                    }
                }
            }),
        )
        .route(
            "/tab",
            post({
                let tab_recipient = tab_recipient.to_string();
                let tab_asset = tab_asset.to_string();
                let user_address = user_address.to_string();
                move || {
                    let tab_recipient = tab_recipient.clone();
                    let tab_asset = tab_asset.clone();
                    let user_address = user_address.clone();
                    async move {
                        Json(json!({
                            "tabId": "0xbeef",
                            "userAddress": user_address,
                            "recipientAddress": tab_recipient,
                            "assetAddress": tab_asset,
                            "ttlSeconds": 600,
                            "startTimestamp": 123456,
                        }))
                    }
                }
            }),
        );

    let (base, handle) = spawn_router(router).await;
    let flow: X402Flow<MockSigner> = X402Flow::with_signer(MockSigner, &base).expect("flow");
    let payment = flow
        .prepare_payment(PaymentRequest::new(
            format!("{base}/resource"),
            user_address,
        ))
        .await
        .expect("prepare payment");

    assert_eq!(payment.requirements.pay_to, tab_recipient);
    assert_eq!(payment.requirements.asset, tab_asset);
    assert_eq!(payment.requirements.max_timeout_seconds, Some(600));
    assert_eq!(payment.requirements.extra["tabId"], json!("0xbeef"));
    assert_eq!(
        payment.requirements.extra["userAddress"],
        json!(user_address)
    );
    assert_eq!(payment.requirements.extra["startTimestamp"], json!(123456));

    handle.abort();
}
