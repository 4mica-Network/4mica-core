use alloy::primitives::U256;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use rpc::{
    PaymentGuaranteeRequestClaims, PaymentGuaranteeRequestEssentials,
    compute_validation_request_hash, compute_validation_subject_hash,
};
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

    let claims = match envelope.payload.claims {
        PaymentGuaranteeRequestClaims::V1(claims) => claims,
        #[allow(unused)]
        _ => panic!("legacy claims version found!"),
    };
    assert_eq!(claims.recipient_address, payment_requirements.pay_to);

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

    let claims = match envelope.payload.claims {
        PaymentGuaranteeRequestClaims::V2(claims) => claims,
        _ => panic!("expected v2 claims"),
    };
    assert_eq!(claims.recipient_address, accepted.pay_to);
    assert_eq!(
        claims.validation_policy.validation_chain_id, 84532,
        "expected validation chain id from accepted.extra"
    );
    let expected_subject_hash = compute_validation_subject_hash(
        &claims.user_address,
        &claims.recipient_address,
        claims.req_id,
        claims.amount,
        &claims.asset_address,
        claims.timestamp,
    )
    .expect("subject hash");
    assert_eq!(
        claims.validation_policy.validation_subject_hash.to_string(),
        alloy::primitives::B256::from(expected_subject_hash).to_string()
    );
    let expected_request_hash =
        compute_validation_request_hash(&claims.validation_policy).expect("request hash");
    assert_eq!(
        claims.validation_policy.validation_request_hash.to_string(),
        alloy::primitives::B256::from(expected_request_hash).to_string()
    );

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

    assert_eq!(payment.payload.claims.tab_id(), U256::from(0x1234));

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

    assert_eq!(payment.payload.claims.tab_id(), U256::from(0x1234));
    assert!(matches!(
        payment.payload.claims,
        PaymentGuaranteeRequestClaims::V2(_)
    ));

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
