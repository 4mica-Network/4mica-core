//! Cross-boundary golden vectors for the guarantee wire format.
//!
//! This test pins the EXACT bytes that the Rust core ABI-encodes and BLS-signs for a
//! guarantee, using the real [`encode_guarantee_claims`] codec and the real BLS signing
//! path. The committed fixture (`contracts/test/fixtures/guarantee_vectors.json`) is then
//! consumed by `contracts/test/GuaranteeCrossBoundary.t.sol`, which feeds these bytes into a
//! real `Core4Mica.verifyAndDecodeGuarantee` on the Solidity side.
//!
//! Together they close the Rust<->Solidity boundary that previously went untested: each side
//! used to exercise only its own half, so layout drift between the two could go unnoticed.
//!
//! By default this test REGENERATES the vectors in-memory and asserts they match the committed
//! fixture, so a codec/layout change that drifts from the fixture fails CI automatically. BLS
//! signatures over BLS12-381 are deterministic, so regeneration is byte-stable. To update the
//! fixture after an intentional change, run:
//!
//! ```text
//! REGEN_GUARANTEE_VECTORS=1 cargo test -p rpc-4mica --test guarantee_golden_vectors
//! ```

use alloy_primitives::{Address, B256, U256, hex};
use crypto::bls::{KeyMaterial, Zeroizing};
use rpc::codec::encode_guarantee_claims;
use rpc::{
    GUARANTEE_CLAIMS_VERSION, GUARANTEE_CLAIMS_VERSION_V2, PaymentGuaranteeClaims,
    PaymentGuaranteeValidationPolicyV2, compute_validation_request_hash,
    compute_validation_subject_hash,
};
use serde_json::{Value, json};

/// Deterministic BLS secret key for the vectors (scalar < group order). The Solidity side
/// does NOT re-derive this key — it reads the public key emitted below — so the only
/// requirement is that it is a valid, fixed scalar.
const TEST_SK: [u8; 32] = [0x24; 32];

/// Chain id the V2 validation binding is computed against. Must match the chain id the
/// Foundry test runs under (forge's default is 31337) because it is bound into
/// `validation_request_hash` and re-checked on-chain against `block.chainid`.
const VECTOR_CHAIN_ID: u64 = 31337;

const CLIENT: &str = "0x1234567890123456789012345678901234567890";
const RECIPIENT: &str = "0x00000000000000000000000000000000000000Be";
const ASSET: &str = "0x0000000000000000000000000000000000000000";
/// Mock validation registry address the V2 vector is bound to. The Foundry test places the
/// mock registry's code at this exact address via `vm.etch`, so the signed
/// `validation_registry_address` matches a real, trusted, code-bearing contract on-chain.
const V2_REGISTRY: &str = "0x000000000000000000000000000000000000CAfe";
const V2_VALIDATOR: &str = "0x2222222222222222222222222222222222222222";

fn words_to_json(words: &[[u8; 32]]) -> Value {
    Value::Array(
        words
            .iter()
            .map(|w| Value::String(hex::encode_prefixed(w)))
            .collect(),
    )
}

fn build_v1_vector() -> Value {
    let key = KeyMaterial::from_bytes(Zeroizing::new(TEST_SK.to_vec())).expect("valid secret key");
    let verification_key = key.public_key().to_solidity_words().expect("g1 words");

    let domain = [0x11u8; 32];
    let amount = U256::from(1_000u64);
    let claims = PaymentGuaranteeClaims {
        domain,
        user_address: CLIENT.to_string(),
        recipient_address: RECIPIENT.to_string(),
        cycle_id: U256::from(100u64),
        req_id: U256::from(7u64),
        amount,
        asset_address: ASSET.to_string(),
        timestamp: 1_700_000_000,
        version: GUARANTEE_CLAIMS_VERSION,
        validation_policy: None,
    };

    let guarantee = encode_guarantee_claims(claims.clone()).expect("encode v1 claims");
    let signature = key.sign(&guarantee).to_solidity_words().expect("g2 words");

    json!({
        "domain": hex::encode_prefixed(domain),
        "verificationKey": words_to_json(&verification_key),
        "signature": words_to_json(&signature),
        "guarantee": hex::encode_prefixed(&guarantee),
        "expected": {
            "tabId": claims.cycle_id.to_string(),
            "reqId": claims.req_id.to_string(),
            "client": CLIENT,
            "recipient": RECIPIENT,
            "amount": amount.to_string(),
            "asset": ASSET,
            "timestamp": claims.timestamp,
            "version": claims.version,
        }
    })
}

fn build_v2_vector() -> Value {
    let key = KeyMaterial::from_bytes(Zeroizing::new(TEST_SK.to_vec())).expect("valid secret key");
    let verification_key = key.public_key().to_solidity_words().expect("g1 words");

    let domain = [0x22u8; 32];
    let amount = U256::from(2_000u64);
    let req_id = U256::from(11u64);
    let timestamp = 1_700_000_500u64;

    let subject_hash =
        compute_validation_subject_hash(CLIENT, RECIPIENT, req_id, amount, ASSET, timestamp)
            .expect("subject hash");

    let mut policy = PaymentGuaranteeValidationPolicyV2 {
        validation_registry_address: V2_REGISTRY.parse::<Address>().unwrap(),
        validation_request_hash: B256::ZERO,
        validation_chain_id: VECTOR_CHAIN_ID,
        validator_address: V2_VALIDATOR.parse::<Address>().unwrap(),
        validator_agent_id: U256::from(42u64),
        min_validation_score: 80,
        validation_subject_hash: B256::from(subject_hash),
        job_hash: B256::repeat_byte(0x11),
        required_validation_tag: "hard-finality".to_string(),
    };
    policy.validation_request_hash =
        B256::from(compute_validation_request_hash(&policy).expect("request hash"));

    let claims = PaymentGuaranteeClaims {
        domain,
        user_address: CLIENT.to_string(),
        recipient_address: RECIPIENT.to_string(),
        cycle_id: U256::from(101u64),
        req_id,
        amount,
        asset_address: ASSET.to_string(),
        timestamp,
        version: GUARANTEE_CLAIMS_VERSION_V2,
        validation_policy: Some(policy.clone()),
    };

    let guarantee = encode_guarantee_claims(claims.clone()).expect("encode v2 claims");
    let signature = key.sign(&guarantee).to_solidity_words().expect("g2 words");

    json!({
        "domain": hex::encode_prefixed(domain),
        "verificationKey": words_to_json(&verification_key),
        "signature": words_to_json(&signature),
        "guarantee": hex::encode_prefixed(&guarantee),
        // Values the Foundry test must reproduce in its mock validation registry so the
        // V2 decoder's post-decode validation passes.
        "policy": {
            "validationRegistryAddress": V2_REGISTRY,
            "validationRequestHash": policy.validation_request_hash.to_string(),
            "validationChainId": policy.validation_chain_id,
            "validatorAddress": V2_VALIDATOR,
            "validatorAgentId": policy.validator_agent_id.to_string(),
            "minValidationScore": policy.min_validation_score,
            "validationSubjectHash": policy.validation_subject_hash.to_string(),
            "jobHash": policy.job_hash.to_string(),
            "requiredValidationTag": policy.required_validation_tag,
        },
        "expected": {
            "tabId": claims.cycle_id.to_string(),
            "reqId": claims.req_id.to_string(),
            "client": CLIENT,
            "recipient": RECIPIENT,
            "amount": amount.to_string(),
            "asset": ASSET,
            "timestamp": claims.timestamp,
            "version": claims.version,
        }
    })
}

fn fixture_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../contracts/test/fixtures/guarantee_vectors.json")
}

#[test]
fn guarantee_golden_vectors_match_fixture() {
    let key = KeyMaterial::from_bytes(Zeroizing::new(TEST_SK.to_vec())).expect("valid secret key");

    // Sanity: the Rust side must accept its own signatures before we ever ask Solidity to.
    let v1 = build_v1_vector();
    let v2 = build_v2_vector();
    for vec in [&v1, &v2] {
        let guarantee = hex::decode(vec["guarantee"].as_str().unwrap()).unwrap();
        let cert = crypto::bls::BLSCert::sign(&key, crypto::bls::BlsClaims::from_bytes(guarantee))
            .expect("sign");
        cert.verify(&key.public_key()).expect("self-verify");
    }

    let generated = serde_json::to_string_pretty(&json!({
        "_comment": "Generated by crates/rpc/tests/guarantee_golden_vectors.rs. \
                     Do not edit by hand; rerun with REGEN_GUARANTEE_VECTORS=1.",
        "v1": v1,
        "v2": v2,
    }))
    .expect("serialize vectors");

    let path = fixture_path();
    if std::env::var("REGEN_GUARANTEE_VECTORS").is_ok() {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("create fixtures dir");
        }
        std::fs::write(&path, format!("{generated}\n")).expect("write fixture");
        eprintln!("regenerated {}", path.display());
        return;
    }

    let committed = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "missing fixture {} ({e}); run REGEN_GUARANTEE_VECTORS=1 cargo test -p rpc-4mica \
             --test guarantee_golden_vectors",
            path.display()
        )
    });

    // Compare structurally so trailing-newline / formatting differences don't cause flakes.
    let committed_json: Value = serde_json::from_str(&committed).expect("parse committed fixture");
    let generated_json: Value = serde_json::from_str(&generated).expect("parse generated fixture");
    assert_eq!(
        committed_json, generated_json,
        "guarantee golden vectors are stale; rerun with REGEN_GUARANTEE_VECTORS=1 to update \
         contracts/test/fixtures/guarantee_vectors.json"
    );
}
