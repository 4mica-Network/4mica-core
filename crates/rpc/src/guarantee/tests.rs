use alloy_primitives::{B256, U256};
use serde_json::json;

use super::{GUARANTEE_CLAIMS_VERSION, PaymentGuaranteeRequestClaims, ValidationRequirement};

fn sample_claims() -> PaymentGuaranteeRequestClaims {
    PaymentGuaranteeRequestClaims::new(
        "0x1234567890123456789012345678901234567890".to_string(),
        "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd".to_string(),
        U256::from(7u64),
        U256::from(1_000u64),
        1_736_000_000,
        None,
    )
}

fn sample_validation() -> ValidationRequirement {
    ValidationRequirement {
        validator: "eip155:84532:0x1111111111111111111111111111111111111111".to_string(),
        subject: B256::repeat_byte(0x11),
        deadline: Some(1_736_003_600),
        params: vec![1, 2, 3].into(),
    }
}

#[test]
fn plain_payload_deserializes_without_validation() {
    let payload = json!({
        "version": "v1",
        "user_address": "0x1234567890123456789012345678901234567890",
        "recipient_address": "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd",
        "req_id": "2",
        "amount": "3",
        "asset_address": "0x0000000000000000000000000000000000000000",
        "timestamp": 100
    });

    let decoded: PaymentGuaranteeRequestClaims =
        serde_json::from_value(payload).expect("payload must deserialize");
    assert_eq!(decoded.version(), GUARANTEE_CLAIMS_VERSION);
    assert!(decoded.validation().is_none());
}

/// The version tag is what lets core pick a layout, so a request without one is not merely
/// defaulted — it is unroutable and must be rejected.
#[test]
fn missing_version_tag_is_rejected() {
    let payload = json!({
        "user_address": "0x1234567890123456789012345678901234567890",
        "recipient_address": "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd",
        "req_id": "2",
        "amount": "3",
        "asset_address": "0x0000000000000000000000000000000000000000",
        "timestamp": 100
    });

    let err = serde_json::from_value::<PaymentGuaranteeRequestClaims>(payload)
        .expect_err("a request without a version tag must fail");
    assert!(err.to_string().contains("version"));
}

/// An unsupported version is refused at the wire boundary, before any service logic runs.
#[test]
fn unknown_version_is_rejected() {
    let payload = json!({
        "version": "v9",
        "user_address": "0x1234567890123456789012345678901234567890",
        "recipient_address": "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd",
        "req_id": "2",
        "amount": "3",
        "asset_address": "0x0000000000000000000000000000000000000000",
        "timestamp": 100
    });

    let err = serde_json::from_value::<PaymentGuaranteeRequestClaims>(payload)
        .expect_err("an unknown version must fail");
    assert!(err.to_string().contains("unknown variant"));
}

/// Pins the v1 wire tag: changing it would invalidate every already-signed v1 request.
#[test]
fn v1_serializes_with_its_version_tag() {
    let payload = serde_json::to_value(sample_claims()).expect("serialize");
    assert_eq!(payload["version"], "v1");
}

#[test]
fn validation_roundtrips() {
    let claims = sample_claims().with_validation(sample_validation());
    let encoded = serde_json::to_string(&claims).expect("serialize");
    let decoded: PaymentGuaranteeRequestClaims =
        serde_json::from_str(&encoded).expect("deserialize");

    assert_eq!(decoded, claims);
    assert_eq!(
        decoded.validation().expect("validation").subject,
        B256::repeat_byte(0x11)
    );
}

#[test]
fn validation_is_omitted_from_the_wire_when_absent() {
    let payload = serde_json::to_value(sample_claims()).expect("serialize");
    let object = payload.as_object().expect("payload should be object");
    assert!(!object.contains_key("validation"));
}

#[test]
fn validation_is_nested_not_flattened() {
    let claims = sample_claims().with_validation(sample_validation());
    let payload = serde_json::to_value(claims).expect("serialize");
    let object = payload.as_object().expect("payload should be object");
    assert!(object.contains_key("validation"));
    assert!(!object.contains_key("validator"));
}

#[test]
fn deadline_is_optional() {
    let mut validation = sample_validation();
    validation.deadline = None;
    let claims = sample_claims().with_validation(validation);

    let encoded = serde_json::to_value(&claims).expect("serialize");
    let validation_object = encoded
        .get("validation")
        .and_then(|v| v.as_object())
        .expect("validation object");
    assert!(!validation_object.contains_key("deadline"));

    let decoded: PaymentGuaranteeRequestClaims =
        serde_json::from_value(encoded).expect("deserialize");
    assert!(decoded.validation().expect("validation").deadline.is_none());
}
