use alloy::primitives::B256;
use alloy::primitives::U256;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use sdk_4mica::x402::{X402Flow, X402PaymentEnvelope, X402PaymentEnvelopeV2};

mod common;

use common::x402::MockSigner;

#[tokio::test]
#[serial_test::file_serial]
async fn sign_payment_respects_payment_requirements() {
    let user_address = "0x0000000000000000000000000000000000000001";
    let (server_url, handle) = common::x402::spawn_mock_server().await;

    let payment_requirements =
        common::x402::request_server_and_fetch_payment_requirements(&server_url)
            .await
            .expect("fetch resource");

    let flow: X402Flow<MockSigner> = X402Flow::new(MockSigner).expect("flow");
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

    let claims = envelope.payload.claims;
    assert_eq!(claims.recipient_address(), payment_requirements.pay_to);
    assert!(claims.validation().is_none());

    handle.abort();
}

#[tokio::test]
#[serial_test::file_serial]
async fn sign_payment_v2_respects_payment_requirements() {
    let user_address = "0x0000000000000000000000000000000000000001";
    let (server_url, handle) = common::x402::spawn_mock_server().await;

    let payment_required =
        common::x402::request_server_and_fetch_payment_requirements_v2(&server_url)
            .await
            .expect("fetch resource");

    let accepted = payment_required.accepts.first().expect("accepted");

    let flow: X402Flow<MockSigner> = X402Flow::new(MockSigner).expect("flow");
    let payment = flow
        .sign_payment_v2(
            payment_required.clone(),
            accepted.clone(),
            user_address.to_string(),
        )
        .await
        .expect("sign payment");

    let envelope_bytes = BASE64_STANDARD
        .decode(payment.header)
        .expect("decode header");
    let envelope: X402PaymentEnvelopeV2 =
        serde_json::from_slice(&envelope_bytes).expect("parse envelope v2");
    assert_eq!(envelope.accepted.scheme, "4mica-credit");
    assert_eq!(envelope.payload.signature, "0xsig");

    let claims = envelope.payload.claims;
    assert_eq!(claims.recipient_address(), accepted.pay_to);

    // The validation requirement travels verbatim from `accepted.extra`: the flow never
    // interprets a validator's policy.
    let validation = claims
        .validation()
        .expect("validation requirement from extra");
    assert_eq!(validation.validator, common::x402::VALIDATOR_URI);
    assert_eq!(validation.subject, B256::repeat_byte(0x11));
    assert_eq!(validation.deadline, Some(1_800_003_600));
    assert_eq!(validation.params.to_vec(), vec![0x0a, 0x0b]);

    handle.abort();
}

#[tokio::test]
#[serial_test::file_serial]
async fn sign_payment_requests_tab_correctly() {
    let user_address = "0x0000000000000000000000000000000000000002";
    let (server_url, handle) = common::x402::spawn_mock_server().await;

    let payment_requirements =
        common::x402::request_server_and_fetch_payment_requirements(&server_url)
            .await
            .expect("fetch resource");

    let flow: X402Flow<MockSigner> = X402Flow::new(MockSigner).expect("flow");
    let payment = flow
        .sign_payment(payment_requirements.clone(), user_address.to_string())
        .await
        .expect("sign payment v2");

    assert_eq!(payment.payload.claims.req_id(), U256::ZERO);

    handle.abort();
}

#[tokio::test]
#[serial_test::file_serial]
async fn sign_payment_v2_requests_tab_correctly() {
    let user_address = "0x0000000000000000000000000000000000000002";
    let (server_url, handle) = common::x402::spawn_mock_server().await;

    let payment_required =
        common::x402::request_server_and_fetch_payment_requirements_v2(&server_url)
            .await
            .expect("fetch resource");

    let accepted = payment_required.accepts.first().expect("accepted");

    let flow: X402Flow<MockSigner> = X402Flow::new(MockSigner).expect("flow");
    let payment = flow
        .sign_payment_v2(
            payment_required.clone(),
            accepted.clone(),
            user_address.to_string(),
        )
        .await
        .expect("sign payment v2");

    assert_eq!(payment.payload.claims.req_id(), U256::ZERO);
    assert!(payment.payload.claims.validation().is_some());

    handle.abort();
}

#[tokio::test]
#[serial_test::file_serial]
async fn complete_payment_flow_through_facilitator() {
    let user_address = "0x0000000000000000000000000000000000000003";
    let (server_url, handle) = common::x402::spawn_mock_server().await;

    let payment_requirements =
        common::x402::request_server_and_fetch_payment_requirements(&server_url)
            .await
            .expect("fetch requirements");

    let flow: X402Flow<MockSigner> = X402Flow::new(MockSigner).expect("flow");
    let payment = flow
        .sign_payment(payment_requirements.clone(), user_address.to_string())
        .await
        .expect("sign payment");

    let settled = flow
        .settle_payment(payment, payment_requirements.clone(), &server_url)
        .await
        .expect("settle payment");

    assert_eq!(
        settled.payment.payload.claims.recipient_address(),
        payment_requirements.pay_to
    );
    assert_eq!(settled.settlement["settled"], true);
    assert_eq!(
        settled.settlement["networkId"],
        payment_requirements.network
    );

    handle.abort();
}
