use alloy::primitives::{Address, B256, U256};
use rpc::{CorePublicParameters, PaymentGuaranteeRequestClaims, PaymentGuaranteeRequestEssentials};
use sdk_4mica::{
    PaymentGuaranteeIntent, PaymentGuaranteeValidationInput, PreparedPaymentGuaranteeClaims,
    guarantee::prepare_payment_guarantee_claims,
};

fn public_params() -> CorePublicParameters {
    CorePublicParameters {
        public_key: vec![],
        contract_address: Address::ZERO.to_string(),
        ethereum_http_rpc_url: "http://localhost:8545".to_string(),
        eip712_name: "4mica".to_string(),
        eip712_version: "1".to_string(),
        chain_id: 84532,
        max_accepted_guarantee_version: 2,
        accepted_guarantee_versions: vec![1, 2],
        active_guarantee_domain_separator:
            "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        trusted_validation_registries: vec![Address::repeat_byte(0x44).to_string()],
        validation_hash_canonicalization_version: "4MICA_VALIDATION_REQUEST_V2".to_string(),
    }
}

fn intent(version: u64) -> PaymentGuaranteeIntent {
    PaymentGuaranteeIntent {
        guarantee_version: version,
        user_address: Address::repeat_byte(0x11).to_string(),
        recipient_address: Address::repeat_byte(0x22).to_string(),
        req_id: U256::from(7u64),
        amount: U256::from(13u64),
        asset_address: Address::ZERO.to_string(),
        timestamp: 1_800_000_000,
    }
}

#[test]
fn sdk_prepares_cycle_native_v1_claims_without_tab_fields() {
    let claims =
        prepare_payment_guarantee_claims(&public_params(), intent(1), None).expect("claims");
    let PreparedPaymentGuaranteeClaims::V1(claims) = claims else {
        panic!("expected v1 claims");
    };

    assert_eq!(claims.req_id, U256::from(7u64));
    assert_eq!(claims.amount, U256::from(13u64));
    let envelope = PaymentGuaranteeRequestClaims::V1(claims);
    assert_eq!(envelope.req_id(), U256::from(7u64));
    assert_eq!(envelope.amount(), U256::from(13u64));
}

#[test]
fn sdk_prepares_validation_gated_cycle_native_v2_claims() {
    let validation = PaymentGuaranteeValidationInput {
        validation_registry_address: None,
        validator_address: Address::repeat_byte(0x55),
        validator_agent_id: U256::from(99u64),
        min_validation_score: 80,
        required_validation_tag: "risk:approved".to_string(),
        job_hash: B256::repeat_byte(0x66),
    };

    let claims = prepare_payment_guarantee_claims(&public_params(), intent(2), Some(validation))
        .expect("claims");
    let PreparedPaymentGuaranteeClaims::V2(claims) = claims else {
        panic!("expected v2 claims");
    };

    assert_eq!(claims.req_id, U256::from(7u64));
    assert_eq!(claims.amount, U256::from(13u64));
    assert_eq!(claims.validation_policy.validation_chain_id, 84532);
    assert_eq!(
        claims.validation_policy.validation_registry_address,
        Address::repeat_byte(0x44)
    );
}
