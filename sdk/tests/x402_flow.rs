use alloy::primitives::U256;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use rpc::PaymentGuaranteeRequestClaims;
use rust_sdk_4mica::x402::{X402Flow, X402PaymentEnvelope};

mod common;

use common::x402::MockSigner;

#[tokio::test]
#[serial_test::serial]
async fn sign_payment_respects_payment_requirements() {
    let user_address = "0x0000000000000000000000000000000000000001";
    let (server_url, handle) = common::x402::spawn_mock_server().await;

    let payment_requirements =
        common::x402::request_server_and_fetch_payment_requirements(&server_url)
            .await
            .expect("fetch requirements");

    let flow: X402Flow<MockSigner> = X402Flow::with_signer(MockSigner).expect("flow");
    let payment = flow
        .sign_payment(payment_requirements.clone(), user_address.to_string())
        .await
        .expect("sign payment");

    let envelope_bytes = BASE64_STANDARD
        .decode(payment.header)
        .expect("decode header");
    let envelope: X402PaymentEnvelope =
        serde_json::from_slice(&envelope_bytes).expect("parse envelope");
    assert_eq!(envelope.scheme, "4mica-credit");
    assert_eq!(envelope.payload.signature, "0xsig");

    let claims = match envelope.payload.claims {
        PaymentGuaranteeRequestClaims::V1(claims) => claims,
        #[allow(unused)]
        _ => panic!("legacy claims version found!"),
    };
    assert_eq!(claims.recipient_address, payment_requirements.pay_to);

    handle.abort();
}

#[tokio::test]
#[serial_test::serial]
async fn sign_payment_requests_tab_correctly() {
    let user_address = "0x0000000000000000000000000000000000000002";
    let (server_url, handle) = common::x402::spawn_mock_server().await;

    let payment_requirements =
        common::x402::request_server_and_fetch_payment_requirements(&server_url)
            .await
            .expect("fetch requirements");

    let flow: X402Flow<MockSigner> = X402Flow::with_signer(MockSigner).expect("flow");
    let payment = flow
        .sign_payment(payment_requirements.clone(), user_address.to_string())
        .await
        .expect("sign payment");

    assert_eq!(payment.claims.tab_id, U256::from(0x1234));

    handle.abort();
}

#[tokio::test]
#[serial_test::serial]
async fn complete_payment_flow_through_facilitator() {
    let user_address = "0x0000000000000000000000000000000000000003";
    let (server_url, handle) = common::x402::spawn_mock_server().await;

    let payment_requirements =
        common::x402::request_server_and_fetch_payment_requirements(&server_url)
            .await
            .expect("fetch requirements");

    let flow: X402Flow<MockSigner> = X402Flow::with_signer(MockSigner).expect("flow");
    let payment = flow
        .sign_payment(payment_requirements.clone(), user_address.to_string())
        .await
        .expect("sign payment");

    let settled = flow
        .settle_payment(payment, payment_requirements.clone(), &server_url)
        .await
        .expect("settle payment");

    assert_eq!(
        settled.payment.claims.recipient_address,
        payment_requirements.pay_to
    );
    assert_eq!(settled.settlement["settled"], true);
    assert_eq!(
        settled.settlement["networkId"],
        payment_requirements.network
    );

    handle.abort();
}
