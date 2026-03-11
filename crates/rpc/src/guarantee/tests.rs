use alloy_primitives::{Address, B256, U256};
use serde_json::{Value, json};

use super::{
    PaymentGuaranteeRequestClaims, PaymentGuaranteeRequestClaimsV2,
    PaymentGuaranteeValidationPolicyV2, compute_validation_request_hash,
    compute_validation_subject_hash,
};

fn sample_v2_claims() -> PaymentGuaranteeRequestClaimsV2 {
    let user = "0x1234567890123456789012345678901234567890";
    let recipient = "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd";
    let asset = "0x0000000000000000000000000000000000000000";
    let validation_registry = "0x1111111111111111111111111111111111111111";
    let validator = "0x2222222222222222222222222222222222222222";
    let tab_id = U256::from(42u64);
    let req_id = U256::from(7u64);
    let amount = U256::from(1_000u64);
    let timestamp = 1_736_000_000u64;
    let validation_subject_hash =
        compute_validation_subject_hash(user, recipient, tab_id, req_id, amount, asset, timestamp)
            .expect("build subject hash");

    let policy_without_hash = PaymentGuaranteeValidationPolicyV2 {
        validation_registry_address: validation_registry
            .parse::<Address>()
            .expect("valid address"),
        validation_request_hash: B256::ZERO,
        validation_chain_id: 84532,
        validator_address: validator.parse::<Address>().expect("valid address"),
        validator_agent_id: U256::from(99u64),
        min_validation_score: 80,
        validation_subject_hash: B256::from(validation_subject_hash),
        required_validation_tag: "hard-finality".to_string(),
    };
    let validation_request_hash =
        compute_validation_request_hash(&policy_without_hash).expect("build request hash");

    PaymentGuaranteeRequestClaimsV2::new(
        user.to_string(),
        recipient.to_string(),
        tab_id,
        req_id,
        amount,
        timestamp,
        Some(asset.to_string()),
        validation_registry.to_string(),
        B256::from(validation_request_hash).to_string(),
        84532,
        validator.to_string(),
        U256::from(99u64),
        80,
        B256::from(validation_subject_hash).to_string(),
        Some("hard-finality".to_string()),
    )
    .expect("valid v2 claims")
}

#[test]
fn v1_payload_deserializes_for_compatibility() {
    let payload = json!({
        "version": "v1",
        "user_address": "0x1234567890123456789012345678901234567890",
        "recipient_address": "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd",
        "tab_id": "1",
        "req_id": "2",
        "amount": "3",
        "asset_address": "0x0000000000000000000000000000000000000000",
        "timestamp": 100
    });

    let decoded: PaymentGuaranteeRequestClaims =
        serde_json::from_value(payload).expect("v1 payload must deserialize");
    match decoded {
        PaymentGuaranteeRequestClaims::V1(_) => {}
        PaymentGuaranteeRequestClaims::V2(_) => panic!("must decode to v1"),
    }
}

#[test]
fn v2_payload_roundtrip_succeeds() {
    let claims = sample_v2_claims();
    let wrapped = PaymentGuaranteeRequestClaims::V2(claims);
    let encoded = serde_json::to_string(&wrapped).expect("serialize v2");
    let decoded: PaymentGuaranteeRequestClaims =
        serde_json::from_str(&encoded).expect("deserialize v2");

    match decoded {
        PaymentGuaranteeRequestClaims::V2(v2) => {
            assert_eq!(v2.validation_policy.min_validation_score, 80);
        }
        PaymentGuaranteeRequestClaims::V1(_) => panic!("must decode to v2"),
    }
}

#[test]
fn v2_serialization_flattens_validation_fields() {
    let claims = sample_v2_claims();
    let payload =
        serde_json::to_value(PaymentGuaranteeRequestClaims::V2(claims)).expect("serialize payload");
    let object = payload.as_object().expect("payload should be object");
    assert!(object.contains_key("validator_address"));
    assert!(!object.contains_key("validation_policy"));
}

#[test]
fn unknown_version_fails() {
    let payload = json!({
        "version": "v9",
        "user_address": "0x1234567890123456789012345678901234567890"
    });
    let err = serde_json::from_value::<PaymentGuaranteeRequestClaims>(payload)
        .expect_err("unknown version must fail");
    assert!(err.to_string().contains("unknown variant"));
}

#[test]
fn missing_required_v2_field_fails() {
    let claims = sample_v2_claims();
    let mut payload =
        serde_json::to_value(PaymentGuaranteeRequestClaims::V2(claims)).expect("serialize");
    let object = payload
        .as_object_mut()
        .expect("payload must be a json object");
    object.remove("validator_address");

    let err = serde_json::from_value::<PaymentGuaranteeRequestClaims>(payload)
        .expect_err("missing field must fail");
    assert!(err.to_string().contains("missing field"));
    assert!(err.to_string().contains("validator_address"));
}

#[test]
fn min_validation_score_out_of_range_fails() {
    let claims = sample_v2_claims();
    let mut payload =
        serde_json::to_value(PaymentGuaranteeRequestClaims::V2(claims)).expect("serialize");
    let object = payload
        .as_object_mut()
        .expect("payload must be a json object");
    object.insert("min_validation_score".to_string(), Value::from(0u64));
    let err_zero = serde_json::from_value::<PaymentGuaranteeRequestClaims>(payload.clone())
        .expect_err("score 0 must fail");
    assert!(err_zero.to_string().contains("min_validation_score"));

    let object = payload
        .as_object_mut()
        .expect("payload must be a json object");
    object.insert("min_validation_score".to_string(), Value::from(101u64));
    let err_high = serde_json::from_value::<PaymentGuaranteeRequestClaims>(payload)
        .expect_err("score 101 must fail");
    assert!(err_high.to_string().contains("min_validation_score"));
}

#[test]
fn non_canonical_validation_request_hash_fails() {
    let claims = sample_v2_claims();
    let mut payload =
        serde_json::to_value(PaymentGuaranteeRequestClaims::V2(claims)).expect("serialize");
    let object = payload
        .as_object_mut()
        .expect("payload must be a json object");
    object.insert(
        "validation_request_hash".to_string(),
        Value::from("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
    );

    let err = serde_json::from_value::<PaymentGuaranteeRequestClaims>(payload)
        .expect_err("non-canonical hash must fail");
    assert!(err.to_string().contains("validation_request_hash"));
    assert!(err.to_string().contains("canonical"));
}
