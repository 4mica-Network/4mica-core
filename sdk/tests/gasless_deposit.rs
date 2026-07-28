//! Tests for the gasless deposit signing paths — `sign_deposit_authorization` (EIP-3009) and
//! `sign_deposit_permit2` (Permit2 `PermitTransferFrom`).
//!
//! These run fully offline against a mock JSON-RPC node, so they cover what the Foundry suites in
//! `contracts/test/Core4MicaDeposit{Authorization,Permit2}.t.sol` cannot: whether the *SDK* builds
//! the digest the verifier will actually check. Every expected digest here is recomputed from raw
//! keccak/ABI words with the type strings spelled out literally — never via `sdk_4mica::digest` —
//! so a swapped argument (`from`/`to`, `validAfter`/`validBefore`) or a wrong domain separator
//! fails the recovery assertion instead of cancelling out on both sides.

use alloy::primitives::{Address, B256, Signature, U256, address, b256, keccak256};
use alloy::signers::local::PrivateKeySigner;
use axum::{Json, Router, routing::get, routing::post};
use crypto::bls::KeyMaterial;
use rpc::{CorePublicParameters, GUARANTEE_CLAIMS_VERSION};
use sdk_4mica::{Client, ConfigBuilder};
use serde_json::{Value, json};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::net::TcpListener;

const CHAIN_ID: u64 = 1337;
const CONTRACT: Address = address!("00000000000000000000000000000000c04e4a1c");
const TOKEN: Address = address!("000000000000000000000000000000000000d0c5");
const OTHER_ADDRESS: Address = address!("000000000000000000000000000000000000bad0");

/// Canonical Permit2 singleton. Hardcoded rather than imported from the SDK's private `contract`
/// module, so the test independently pins the address the SDK must query.
const PERMIT2: Address = address!("000000000022D473030F116dDEE9F6B43aC78BA3");

/// Distinct domain separators per verifier, so a test fails loudly if the SDK reads the wrong one.
const TOKEN_DOMAIN: B256 =
    b256!("1111111111111111111111111111111111111111111111111111111111111111");
/// Permit2's real domain separator for `CHAIN_ID`, computed independently with `cast`:
/// keccak(abi.encode(keccak("EIP712Domain(string name,uint256 chainId,address verifyingContract)"),
///                   keccak("Permit2"), 1337, PERMIT2)).
/// Hardcoded rather than derived in-test so a bug in the SDK's derivation cannot cancel out.
const PERMIT2_DOMAIN: B256 =
    b256!("1f520b5ee38ad937955892c3dfc7055e8eeb515d905781b6951e4c687917c530");
const GUARANTEE_DOMAIN: B256 =
    b256!("3333333333333333333333333333333333333333333333333333333333333333");

/// Matches `DEPOSIT_AUTHORIZATION_TTL_SECS` in `sdk/src/client/user.rs`.
const EXPECTED_TTL_SECS: u64 = 3600;

const BLS_SECRET: &str = "0x4573DBD225C8E065FC30FF774C9EF81BD29D34E559D80E2276EE7824812399D3";

fn word_address(value: Address) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[12..].copy_from_slice(value.as_slice());
    word
}

fn word_u256(value: U256) -> [u8; 32] {
    value.to_be_bytes::<32>()
}

/// `keccak256(0x19 ‖ 0x01 ‖ domainSeparator ‖ structHash)`.
fn eip712_digest(domain_separator: B256, struct_hash: B256) -> B256 {
    let mut buf = Vec::with_capacity(66);
    buf.push(0x19);
    buf.push(0x01);
    buf.extend_from_slice(domain_separator.as_slice());
    buf.extend_from_slice(struct_hash.as_slice());
    keccak256(buf)
}

/// EIP-3009 `ReceiveWithAuthorization` digest, as USDC's FiatToken computes it.
#[allow(clippy::too_many_arguments)]
fn expected_erc3009_digest(
    domain_separator: B256,
    from: Address,
    to: Address,
    value: U256,
    valid_after: U256,
    valid_before: U256,
    nonce: B256,
) -> B256 {
    let type_hash = keccak256(
        b"ReceiveWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"
            .as_slice(),
    );
    let mut encoded = Vec::with_capacity(32 * 7);
    encoded.extend_from_slice(type_hash.as_slice());
    encoded.extend_from_slice(&word_address(from));
    encoded.extend_from_slice(&word_address(to));
    encoded.extend_from_slice(&word_u256(value));
    encoded.extend_from_slice(&word_u256(valid_after));
    encoded.extend_from_slice(&word_u256(valid_before));
    encoded.extend_from_slice(nonce.as_slice());
    eip712_digest(domain_separator, keccak256(encoded))
}

/// Permit2 `PermitTransferFrom` digest, with the nested `TokenPermissions` struct hashed first.
fn expected_permit2_digest(
    domain_separator: B256,
    token: Address,
    amount: U256,
    spender: Address,
    nonce: U256,
    deadline: U256,
) -> B256 {
    let token_permissions_type_hash =
        keccak256(b"TokenPermissions(address token,uint256 amount)".as_slice());
    let mut permitted = Vec::with_capacity(32 * 3);
    permitted.extend_from_slice(token_permissions_type_hash.as_slice());
    permitted.extend_from_slice(&word_address(token));
    permitted.extend_from_slice(&word_u256(amount));
    let permitted_hash = keccak256(permitted);

    let type_hash = keccak256(
        b"PermitTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline)TokenPermissions(address token,uint256 amount)"
            .as_slice(),
    );
    let mut encoded = Vec::with_capacity(32 * 5);
    encoded.extend_from_slice(type_hash.as_slice());
    encoded.extend_from_slice(permitted_hash.as_slice());
    encoded.extend_from_slice(&word_address(spender));
    encoded.extend_from_slice(&word_u256(nonce));
    encoded.extend_from_slice(&word_u256(deadline));
    eip712_digest(domain_separator, keccak256(encoded))
}

fn selector(signature: &str) -> [u8; 4] {
    let hash = keccak256(signature.as_bytes());
    [hash[0], hash[1], hash[2], hash[3]]
}

/// Every JSON-RPC call the SDK made, so tests can assert *which* contract was asked for a domain
/// separator and that no transaction was ever broadcast.
#[derive(Default)]
struct CallLog {
    methods: Vec<String>,
    eth_calls: Vec<(Address, [u8; 4])>,
}

impl CallLog {
    fn domain_separator_targets(&self) -> Vec<Address> {
        let want = selector("DOMAIN_SEPARATOR()");
        self.eth_calls
            .iter()
            .filter(|(_, sel)| *sel == want)
            .map(|(to, _)| *to)
            .collect()
    }
}

fn json_rpc_result(id: &Value, result: Value) -> Json<Value> {
    Json(json!({"jsonrpc": "2.0", "id": id, "result": result}))
}

fn encode_guarantee_version_config() -> String {
    // (G1Point verificationKey, bytes32 domainSeparator, address decoder, bool enabled).
    // G1Point is a static 4-word struct, so the whole return is head-only: 7 words.
    let mut out = Vec::with_capacity(32 * 7);
    out.extend_from_slice(&[0u8; 32 * 4]);
    out.extend_from_slice(GUARANTEE_DOMAIN.as_slice());
    out.extend_from_slice(&word_address(Address::ZERO));
    let mut enabled = [0u8; 32];
    enabled[31] = 1;
    out.extend_from_slice(&enabled);
    format!("0x{}", alloy::hex::encode(out))
}

async fn handle_rpc(
    axum::extract::State(log): axum::extract::State<Arc<Mutex<CallLog>>>,
    Json(body): Json<Value>,
) -> Json<Value> {
    let id = body.get("id").cloned().unwrap_or(json!(1));
    let method = body
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    log.lock().unwrap().methods.push(method.clone());

    match method.as_str() {
        "eth_chainId" => json_rpc_result(&id, json!(format!("0x{CHAIN_ID:x}"))),
        "eth_call" => {
            let tx = body
                .get("params")
                .and_then(|p| p.get(0))
                .cloned()
                .unwrap_or_default();
            let to = tx
                .get("to")
                .and_then(Value::as_str)
                .and_then(|s| Address::from_str(s).ok())
                .unwrap_or(Address::ZERO);
            let data = tx
                .get("input")
                .or_else(|| tx.get("data"))
                .and_then(Value::as_str)
                .unwrap_or("0x");
            let bytes = alloy::hex::decode(data.trim_start_matches("0x")).unwrap_or_default();
            let sel: [u8; 4] = bytes
                .get(..4)
                .and_then(|s| s.try_into().ok())
                .unwrap_or([0; 4]);
            log.lock().unwrap().eth_calls.push((to, sel));

            // Intentionally unhandled: the SDK must not ask the chain for a domain separator.
            // If it regresses to an eth_call, this returns a JSON-RPC error and the test fails.
            if sel == selector("getGuaranteeVersionConfig(uint64)") {
                return json_rpc_result(&id, json!(encode_guarantee_version_config()));
            }
            Json(json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {"code": -32601, "message": format!("mock: unhandled eth_call selector 0x{}", alloy::hex::encode(sel))}
            }))
        }
        other => Json(json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {"code": -32601, "message": format!("mock: unhandled method {other}")}
        })),
    }
}

async fn spawn(router: Router) -> anyhow::Result<String> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        if let Err(err) = axum::serve(listener, router.into_make_service()).await {
            eprintln!("mock server stopped: {err}");
        }
    });
    Ok(format!("http://{addr}"))
}

fn public_params(eth_rpc_url: &str) -> CorePublicParameters {
    let operator_key = KeyMaterial::from_str(BLS_SECRET).expect("valid test BLS key");
    CorePublicParameters {
        public_key: operator_key.public_key().to_vec(),
        contract_address: CONTRACT.to_string(),
        ethereum_http_rpc_url: eth_rpc_url.to_string(),
        eip712_name: "4mica".into(),
        eip712_version: "1".into(),
        chain_id: CHAIN_ID,
        supported_guarantee_versions: vec![GUARANTEE_CLAIMS_VERSION],
        guarantee_domain_separator: format!("0x{}", alloy::hex::encode(GUARANTEE_DOMAIN)),
        validators: vec![],
    }
}

/// Boots a mock chain + core and returns a `Client` wired to them, plus the signer and call log.
async fn test_client() -> anyhow::Result<(Client<PrivateKeySigner>, Address, Arc<Mutex<CallLog>>)> {
    let log = Arc::new(Mutex::new(CallLog::default()));
    let eth_url = spawn(
        Router::new()
            .route("/", post(handle_rpc))
            .with_state(log.clone()),
    )
    .await?;

    let params = public_params(&eth_url);
    let core_url = spawn(
        Router::new()
            .route(
                "/core/public-params",
                get(move || {
                    let params = params.clone();
                    async move { Json(params) }
                }),
            )
            .route(
                "/core/tokens",
                get(|| async {
                    Json(json!({
                        "chain_id": CHAIN_ID,
                        "tokens": [{
                            "symbol": "USDC",
                            "address": TOKEN.to_string(),
                            "decimals": 6,
                            "domain_separator": format!("0x{}", alloy::hex::encode(TOKEN_DOMAIN)),
                        }],
                    }))
                }),
            ),
    )
    .await?;

    let signer = PrivateKeySigner::random();
    let signer_address = signer.address();
    let cfg = ConfigBuilder::default()
        .rpc_url(core_url)
        .signer(signer)
        .ethereum_http_rpc_url(eth_url)
        .contract_address(CONTRACT.to_string())
        .build()?;

    let client = Client::new(cfg).await?;
    // Drop setup traffic so per-test assertions only see the signing calls.
    log.lock().unwrap().eth_calls.clear();
    Ok((client, signer_address, log))
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after epoch")
        .as_secs()
}

#[tokio::test]
async fn sign_deposit_authorization_recovers_to_signer_over_erc3009_digest() -> anyhow::Result<()> {
    let (client, signer_address, _log) = test_client().await?;
    let amount = U256::from(1_000_000u64);

    let auth = client
        .user
        .sign_deposit_authorization(TOKEN.to_string(), amount)
        .await?;

    assert_eq!(
        auth.from, signer_address,
        "authorization must bind the signer"
    );
    assert_eq!(auth.validAfter, U256::ZERO, "validAfter must be 0");

    let digest = expected_erc3009_digest(
        TOKEN_DOMAIN,
        signer_address,
        CONTRACT,
        amount,
        U256::ZERO,
        auth.validBefore,
        auth.nonce,
    );
    let recovered = Signature::from_scalars_and_parity(auth.r, auth.s, auth.v == 28)
        .recover_address_from_prehash(&digest)?;
    assert_eq!(
        recovered, signer_address,
        "signature must recover to the signer over the token's ReceiveWithAuthorization digest"
    );
    Ok(())
}

#[tokio::test]
async fn sign_deposit_authorization_binds_core4mica_as_recipient() -> anyhow::Result<()> {
    let (client, signer_address, _log) = test_client().await?;
    let amount = U256::from(1_000_000u64);

    let auth = client
        .user
        .sign_deposit_authorization(TOKEN.to_string(), amount)
        .await?;
    let signature = Signature::from_scalars_and_parity(auth.r, auth.s, auth.v == 28);

    // A facilitator cannot redirect the funds: only `to == Core4Mica` recovers to the signer.
    for wrong_to in [OTHER_ADDRESS, signer_address, Address::ZERO] {
        let digest = expected_erc3009_digest(
            TOKEN_DOMAIN,
            signer_address,
            wrong_to,
            amount,
            U256::ZERO,
            auth.validBefore,
            auth.nonce,
        );
        assert_ne!(
            signature.recover_address_from_prehash(&digest).ok(),
            Some(signer_address),
            "authorization must not be valid for recipient {wrong_to}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn sign_deposit_authorization_binds_amount() -> anyhow::Result<()> {
    let (client, signer_address, _log) = test_client().await?;
    let amount = U256::from(1_000_000u64);

    let auth = client
        .user
        .sign_deposit_authorization(TOKEN.to_string(), amount)
        .await?;
    let signature = Signature::from_scalars_and_parity(auth.r, auth.s, auth.v == 28);

    let inflated = expected_erc3009_digest(
        TOKEN_DOMAIN,
        signer_address,
        CONTRACT,
        amount + U256::from(1u64),
        U256::ZERO,
        auth.validBefore,
        auth.nonce,
    );
    assert_ne!(
        signature.recover_address_from_prehash(&inflated).ok(),
        Some(signer_address),
        "a submitter must not be able to inflate the signed amount"
    );
    Ok(())
}

#[tokio::test]
async fn sign_deposit_authorization_takes_the_token_domain_from_core_not_the_chain()
-> anyhow::Result<()> {
    let (client, signer_address, log) = test_client().await?;
    let amount = U256::from(1_000_000u64);

    let auth = client
        .user
        .sign_deposit_authorization(TOKEN.to_string(), amount)
        .await?;

    assert!(
        log.lock().unwrap().domain_separator_targets().is_empty(),
        "signing must not eth_call DOMAIN_SEPARATOR() — the separator comes from core over HTTP, \
         so a client needs no Ethereum RPC to deposit gaslessly"
    );

    // Signing against any other domain (e.g. Permit2's) would not verify inside the token.
    let signature = Signature::from_scalars_and_parity(auth.r, auth.s, auth.v == 28);
    let wrong_domain = expected_erc3009_digest(
        PERMIT2_DOMAIN,
        signer_address,
        CONTRACT,
        amount,
        U256::ZERO,
        auth.validBefore,
        auth.nonce,
    );
    assert_ne!(
        signature.recover_address_from_prehash(&wrong_domain).ok(),
        Some(signer_address),
        "authorization must be bound to the token's own EIP-712 domain"
    );
    Ok(())
}

#[tokio::test]
async fn sign_deposit_authorization_expires_one_hour_out() -> anyhow::Result<()> {
    let (client, _signer_address, _log) = test_client().await?;
    let before = now_secs();

    let auth = client
        .user
        .sign_deposit_authorization(TOKEN.to_string(), U256::from(1u64))
        .await?;

    let after = now_secs();
    let valid_before: u64 = auth.validBefore.to::<u64>();
    assert!(
        valid_before >= before + EXPECTED_TTL_SECS && valid_before <= after + EXPECTED_TTL_SECS,
        "validBefore {valid_before} must be ~{EXPECTED_TTL_SECS}s after signing time"
    );
    assert_eq!(
        auth.validAfter,
        U256::ZERO,
        "validAfter must stay 0 — a non-zero value would delay redemption"
    );
    Ok(())
}

#[tokio::test]
async fn sign_deposit_authorization_v_is_ecrecover_compatible() -> anyhow::Result<()> {
    let (client, _signer_address, _log) = test_client().await?;

    // The token calls `ecrecover(digest, v, r, s)`, which rejects a raw 0/1 y-parity.
    for _ in 0..8 {
        let auth = client
            .user
            .sign_deposit_authorization(TOKEN.to_string(), U256::from(1u64))
            .await?;
        assert!(
            auth.v == 27 || auth.v == 28,
            "v must be 27 or 28 for ecrecover, got {}",
            auth.v
        );
    }
    Ok(())
}

#[tokio::test]
async fn sign_deposit_authorization_uses_a_fresh_nonce_per_call() -> anyhow::Result<()> {
    let (client, _signer_address, _log) = test_client().await?;

    let first = client
        .user
        .sign_deposit_authorization(TOKEN.to_string(), U256::from(1u64))
        .await?;
    let second = client
        .user
        .sign_deposit_authorization(TOKEN.to_string(), U256::from(1u64))
        .await?;

    assert_ne!(
        first.nonce, second.nonce,
        "reusing a nonce would make the second authorization unredeemable (EIP-3009 replay guard)"
    );
    assert_ne!(first.nonce, B256::ZERO, "nonce must not be zero");
    Ok(())
}

#[tokio::test]
async fn sign_deposit_authorization_rejects_an_invalid_token_address() -> anyhow::Result<()> {
    let (client, _signer_address, log) = test_client().await?;

    // The authorization type does not implement Debug, so match rather than `expect_err`.
    let err = match client
        .user
        .sign_deposit_authorization("not-an-address".to_string(), U256::from(1u64))
        .await
    {
        Ok(_) => panic!("invalid token address must be rejected"),
        Err(err) => err,
    };

    assert!(
        matches!(err, sdk_4mica::error::DepositError::InvalidParams(_)),
        "expected InvalidParams, got {err:?}"
    );
    assert!(
        log.lock().unwrap().eth_calls.is_empty(),
        "validation must fail before touching the chain"
    );
    Ok(())
}

#[tokio::test]
async fn sign_deposit_permit2_recovers_to_signer_over_permit2_digest() -> anyhow::Result<()> {
    let (client, signer_address, _log) = test_client().await?;
    let amount = U256::from(2_500_000u64);

    let auth = client
        .user
        .sign_deposit_permit2(TOKEN.to_string(), amount)
        .await?;

    assert_eq!(auth.from, signer_address, "permit must bind the signer");
    assert_eq!(
        auth.signature.len(),
        65,
        "Permit2 expects a 65-byte ECDSA signature"
    );

    let digest = expected_permit2_digest(
        PERMIT2_DOMAIN,
        TOKEN,
        amount,
        CONTRACT,
        auth.nonce,
        auth.deadline,
    );
    let recovered = Signature::from_raw(&auth.signature)?.recover_address_from_prehash(&digest)?;
    assert_eq!(
        recovered, signer_address,
        "signature must recover to the signer over Permit2's PermitTransferFrom digest"
    );
    Ok(())
}

#[tokio::test]
async fn sign_deposit_permit2_binds_core4mica_as_spender() -> anyhow::Result<()> {
    let (client, signer_address, _log) = test_client().await?;
    let amount = U256::from(2_500_000u64);

    let auth = client
        .user
        .sign_deposit_permit2(TOKEN.to_string(), amount)
        .await?;
    let signature = Signature::from_raw(&auth.signature)?;

    // Only Core4Mica may consume the permit — no other contract can call permitTransferFrom with it.
    for wrong_spender in [OTHER_ADDRESS, signer_address, PERMIT2] {
        let digest = expected_permit2_digest(
            PERMIT2_DOMAIN,
            TOKEN,
            amount,
            wrong_spender,
            auth.nonce,
            auth.deadline,
        );
        assert_ne!(
            signature.recover_address_from_prehash(&digest).ok(),
            Some(signer_address),
            "permit must not be consumable by spender {wrong_spender}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn sign_deposit_permit2_binds_token_and_amount() -> anyhow::Result<()> {
    let (client, signer_address, _log) = test_client().await?;
    let amount = U256::from(2_500_000u64);

    let auth = client
        .user
        .sign_deposit_permit2(TOKEN.to_string(), amount)
        .await?;
    let signature = Signature::from_raw(&auth.signature)?;

    let wrong_token = expected_permit2_digest(
        PERMIT2_DOMAIN,
        OTHER_ADDRESS,
        amount,
        CONTRACT,
        auth.nonce,
        auth.deadline,
    );
    assert_ne!(
        signature.recover_address_from_prehash(&wrong_token).ok(),
        Some(signer_address),
        "permit must be bound to the requested token"
    );

    let wrong_amount = expected_permit2_digest(
        PERMIT2_DOMAIN,
        TOKEN,
        amount + U256::from(1u64),
        CONTRACT,
        auth.nonce,
        auth.deadline,
    );
    assert_ne!(
        signature.recover_address_from_prehash(&wrong_amount).ok(),
        Some(signer_address),
        "permit must be bound to the requested amount"
    );
    Ok(())
}

#[tokio::test]
async fn sign_deposit_permit2_derives_the_canonical_permit2_domain_offline() -> anyhow::Result<()> {
    let (client, signer_address, log) = test_client().await?;
    let amount = U256::from(2_500_000u64);

    let auth = client
        .user
        .sign_deposit_permit2(TOKEN.to_string(), amount)
        .await?;

    assert!(
        log.lock().unwrap().domain_separator_targets().is_empty(),
        "Permit2's domain has a fixed name, no version, and a canonical address, so it must be \
         derived from the chain id rather than read on-chain"
    );

    let signature = Signature::from_raw(&auth.signature)?;
    let wrong_domain = expected_permit2_digest(
        TOKEN_DOMAIN,
        TOKEN,
        amount,
        CONTRACT,
        auth.nonce,
        auth.deadline,
    );
    assert_ne!(
        signature.recover_address_from_prehash(&wrong_domain).ok(),
        Some(signer_address),
        "permit must be bound to Permit2's own EIP-712 domain"
    );
    Ok(())
}

#[tokio::test]
async fn sign_deposit_permit2_expires_one_hour_out() -> anyhow::Result<()> {
    let (client, _signer_address, _log) = test_client().await?;
    let before = now_secs();

    let auth = client
        .user
        .sign_deposit_permit2(TOKEN.to_string(), U256::from(1u64))
        .await?;

    let after = now_secs();
    let deadline: u64 = auth.deadline.to::<u64>();
    assert!(
        deadline >= before + EXPECTED_TTL_SECS && deadline <= after + EXPECTED_TTL_SECS,
        "deadline {deadline} must be ~{EXPECTED_TTL_SECS}s after signing time"
    );
    Ok(())
}

#[tokio::test]
async fn sign_deposit_permit2_uses_a_fresh_nonce_per_call() -> anyhow::Result<()> {
    let (client, _signer_address, _log) = test_client().await?;

    let first = client
        .user
        .sign_deposit_permit2(TOKEN.to_string(), U256::from(1u64))
        .await?;
    let second = client
        .user
        .sign_deposit_permit2(TOKEN.to_string(), U256::from(1u64))
        .await?;

    assert_ne!(
        first.nonce, second.nonce,
        "Permit2 nonces are single-use; a repeat would revert as InvalidNonce"
    );
    Ok(())
}

#[tokio::test]
async fn sign_deposit_permit2_rejects_an_invalid_token_address() -> anyhow::Result<()> {
    let (client, _signer_address, log) = test_client().await?;

    let err = match client
        .user
        .sign_deposit_permit2("0xnope".to_string(), U256::from(1u64))
        .await
    {
        Ok(_) => panic!("invalid token address must be rejected"),
        Err(err) => err,
    };

    assert!(
        matches!(err, sdk_4mica::error::DepositError::InvalidParams(_)),
        "expected InvalidParams, got {err:?}"
    );
    assert!(
        log.lock().unwrap().eth_calls.is_empty(),
        "validation must fail before touching the chain"
    );
    Ok(())
}

#[tokio::test]
async fn gasless_signing_never_broadcasts_a_transaction() -> anyhow::Result<()> {
    let (client, _signer_address, log) = test_client().await?;

    client
        .user
        .sign_deposit_authorization(TOKEN.to_string(), U256::from(1u64))
        .await?;
    client
        .user
        .sign_deposit_permit2(TOKEN.to_string(), U256::from(1u64))
        .await?;

    let methods = log.lock().unwrap().methods.clone();
    for method in &methods {
        assert!(
            !method.starts_with("eth_send") && method != "eth_estimateGas",
            "gasless signing must not broadcast or price a transaction, but called {method}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn authorizations_survive_a_json_round_trip() -> anyhow::Result<()> {
    let (client, signer_address, _log) = test_client().await?;
    let amount = U256::from(1_000_000u64);

    // Signing and submission happen in different processes: a gas-sponsoring submitter receives
    // these as an HTTP request body, so the serde derives on both types are load-bearing.
    let auth = client
        .user
        .sign_deposit_authorization(TOKEN.to_string(), amount)
        .await?;
    let decoded: sdk_4mica::ReceiveAuthorization =
        serde_json::from_str(&serde_json::to_string(&auth)?)?;
    assert_eq!(decoded.from, signer_address);
    assert_eq!(decoded.validAfter, auth.validAfter);
    assert_eq!(decoded.validBefore, auth.validBefore);
    assert_eq!(decoded.nonce, auth.nonce);
    assert_eq!(decoded.v, auth.v);
    assert_eq!(decoded.r, auth.r);
    assert_eq!(decoded.s, auth.s);

    let permit = client
        .user
        .sign_deposit_permit2(TOKEN.to_string(), amount)
        .await?;
    let decoded: sdk_4mica::Permit2Authorization =
        serde_json::from_str(&serde_json::to_string(&permit)?)?;
    assert_eq!(decoded.from, signer_address);
    assert_eq!(decoded.nonce, permit.nonce);
    assert_eq!(decoded.deadline, permit.deadline);
    assert_eq!(decoded.signature, permit.signature);
    Ok(())
}
