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
use rpc::{CorePublicParameters, GUARANTEE_CLAIMS_VERSION, GuaranteeVersionDomain};
use sdk_4mica::client::model::{Asset, DepositPath};
use sdk_4mica::error::DepositError;
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
/// Core4Mica's own domain. No deposit signs under it, so any appearance here is a bug.
const CORE_DOMAIN: B256 = b256!("4444444444444444444444444444444444444444444444444444444444444444");

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

/// EIP-2612 `Permit` digest, as the token computes it before `ecrecover`.
fn expected_permit_digest(
    domain_separator: B256,
    owner: Address,
    spender: Address,
    value: U256,
    nonce: U256,
    deadline: U256,
) -> B256 {
    let type_hash = keccak256(
        b"Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"
            .as_slice(),
    );
    let mut encoded = Vec::with_capacity(32 * 6);
    encoded.extend_from_slice(type_hash.as_slice());
    encoded.extend_from_slice(&word_address(owner));
    encoded.extend_from_slice(&word_address(spender));
    encoded.extend_from_slice(&word_u256(value));
    encoded.extend_from_slice(&word_u256(nonce));
    encoded.extend_from_slice(&word_u256(deadline));
    eip712_digest(domain_separator, keccak256(encoded))
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
            // Zero: these tests never grant the self-funded allowance, so a fallback that
            // pre-checks it must refuse rather than broadcast.
            if sel == selector("allowance(address,address)") {
                return json_rpc_result(&id, json!(format!("0x{}", "00".repeat(32))));
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
        guarantee_domains: vec![GuaranteeVersionDomain {
            version: GUARANTEE_CLAIMS_VERSION,
            domain_separator: format!("0x{}", alloy::hex::encode(GUARANTEE_DOMAIN)),
        }],
        core_domain_separator: format!("0x{}", alloy::hex::encode(CORE_DOMAIN)),
        validators: vec![],
    }
}

/// Every request a mock facilitator received, so tests can assert on what the SDK actually sent
/// rather than only on what it returned.
#[derive(Default)]
struct FacilitatorLog {
    deposits: Vec<Value>,
    verifies: Vec<Value>,
}

/// A stand-in facilitator that records requests and replies with `response`.
///
/// Deliberately dumb: the point is not to re-implement the facilitator, it is to observe what the
/// SDK puts on the wire and how it maps the reply back.
async fn spawn_facilitator(
    response: Value,
    log: Arc<Mutex<FacilitatorLog>>,
) -> anyhow::Result<String> {
    let deposit_log = log.clone();
    let deposit_response = response.clone();
    let verify_log = log.clone();

    spawn(
        Router::new()
            .route(
                "/deposit",
                post(move |Json(body): Json<Value>| {
                    let log = deposit_log.clone();
                    let response = deposit_response.clone();
                    async move {
                        let response = echoing_payer(response, &body);
                        log.lock().unwrap().deposits.push(body);
                        Json(response)
                    }
                }),
            )
            .route(
                "/deposit/verify",
                post(move |Json(body): Json<Value>| {
                    let log = verify_log.clone();
                    async move {
                        log.lock().unwrap().verifies.push(body);
                        Json(json!({ "isValid": true }))
                    }
                }),
            ),
    )
    .await
}

/// Rejects the first `/deposit` with `PERMIT2_ALLOWANCE_REQUIRED`, then accepts the retry. Mirrors
/// a real facilitator seeing the allowance appear once the sponsored permit lands.
async fn spawn_allowance_then_success_facilitator(
    eip2612_nonce: Option<&str>,
    log: Arc<Mutex<FacilitatorLog>>,
) -> anyhow::Result<String> {
    let nonce = eip2612_nonce.map(str::to_string);
    spawn(Router::new().route(
        "/deposit",
        post(move |Json(body): Json<Value>| {
            let log = log.clone();
            let nonce = nonce.clone();
            async move {
                let first = log.lock().unwrap().deposits.is_empty();

                let response = if first {
                    let mut allowance = json!({
                        "spender": "0x000000000022d473030f116ddee9f6b43ac78ba3",
                        "allowance": "0",
                        "required": "1000000",
                    });
                    if let Some(nonce) = nonce {
                        allowance["eip2612Nonce"] = json!(nonce);
                    }
                    json!({
                        "success": false,
                        "error": "approve permit2 first",
                        "errorCode": "PERMIT2_ALLOWANCE_REQUIRED",
                        "retryable": false,
                        "permit2Allowance": allowance,
                    })
                } else {
                    echoing_payer(success_response(), &body)
                };

                log.lock().unwrap().deposits.push(body);
                Json(response)
            }
        }),
    ))
    .await
}

fn success_response() -> Value {
    json!({
        "success": true,
        "txHash": "0x1111111111111111111111111111111111111111111111111111111111111111",
        "network": "eip155:1337",
        "asset": TOKEN.to_string(),
        "amount": "1000000",
    })
}

/// Stamps `response` with the payer the request carried, as a real facilitator echoes the account
/// it credited. The SDK refuses a receipt naming anyone else, and a canned address could never match
/// the signer, which is random per test.
fn echoing_payer(mut response: Value, request: &Value) -> Value {
    let payer = request
        .get("authorization")
        .or_else(|| request.get("permit2Authorization"))
        .and_then(|auth| auth.get("from"));
    if let (Some(payer), Some(response)) = (payer, response.as_object_mut()) {
        response.insert("from".into(), payer.clone());
    }
    response
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

/// As [`test_client`], but with a facilitator configured and its request log returned too.
async fn test_client_with_facilitator(
    response: Value,
) -> anyhow::Result<(
    Client<PrivateKeySigner>,
    Address,
    Arc<Mutex<CallLog>>,
    Arc<Mutex<FacilitatorLog>>,
)> {
    let facilitator_log = Arc::new(Mutex::new(FacilitatorLog::default()));
    let (client, signer, chain_log) =
        client_against(spawn_facilitator(response, facilitator_log.clone())).await?;
    Ok((client, signer, chain_log, facilitator_log))
}

/// Builds a `Client` pointed at a mock chain, a mock core, and whatever facilitator `facilitator`
/// resolves to. Taking the facilitator as a future lets each test supply its own behaviour without
/// duplicating the surrounding setup.
async fn client_against(
    facilitator: impl std::future::Future<Output = anyhow::Result<String>>,
) -> anyhow::Result<(Client<PrivateKeySigner>, Address, Arc<Mutex<CallLog>>)> {
    let chain_log = Arc::new(Mutex::new(CallLog::default()));
    let eth_url = spawn(
        Router::new()
            .route("/", post(handle_rpc))
            .with_state(chain_log.clone()),
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

    let facilitator_url = facilitator.await?;

    let signer = PrivateKeySigner::random();
    let signer_address = signer.address();
    let cfg = ConfigBuilder::default()
        .rpc_url(core_url)
        .signer(signer)
        .ethereum_http_rpc_url(eth_url)
        .contract_address(CONTRACT.to_string())
        .facilitator_url(facilitator_url)
        .build()?;

    let client = Client::new(cfg).await?;
    // Drop setup traffic so per-test assertions only see what the deposit did.
    chain_log.lock().unwrap().eth_calls.clear();
    chain_log.lock().unwrap().methods.clear();
    Ok((client, signer_address, chain_log))
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

    let auth = client.deposit.sign_eip3009(TOKEN, amount).await?;

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

    let auth = client.deposit.sign_eip3009(TOKEN, amount).await?;
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

    let auth = client.deposit.sign_eip3009(TOKEN, amount).await?;
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

    let auth = client.deposit.sign_eip3009(TOKEN, amount).await?;

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

    let auth = client.deposit.sign_eip3009(TOKEN, U256::from(1u64)).await?;

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
        let auth = client.deposit.sign_eip3009(TOKEN, U256::from(1u64)).await?;
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

    let first = client.deposit.sign_eip3009(TOKEN, U256::from(1u64)).await?;
    let second = client.deposit.sign_eip3009(TOKEN, U256::from(1u64)).await?;

    assert_ne!(
        first.nonce, second.nonce,
        "reusing a nonce would make the second authorization unredeemable (EIP-3009 replay guard)"
    );
    assert_ne!(first.nonce, B256::ZERO, "nonce must not be zero");
    Ok(())
}

#[tokio::test]
async fn sign_deposit_permit2_recovers_to_signer_over_permit2_digest() -> anyhow::Result<()> {
    let (client, signer_address, _log) = test_client().await?;
    let amount = U256::from(2_500_000u64);

    let auth = client.deposit.sign_permit2(TOKEN, amount).await?;

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

    let auth = client.deposit.sign_permit2(TOKEN, amount).await?;
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

    let auth = client.deposit.sign_permit2(TOKEN, amount).await?;
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

    let auth = client.deposit.sign_permit2(TOKEN, amount).await?;

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

    let auth = client.deposit.sign_permit2(TOKEN, U256::from(1u64)).await?;

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

    let first = client.deposit.sign_permit2(TOKEN, U256::from(1u64)).await?;
    let second = client.deposit.sign_permit2(TOKEN, U256::from(1u64)).await?;

    assert_ne!(
        first.nonce, second.nonce,
        "Permit2 nonces are single-use; a repeat would revert as InvalidNonce"
    );
    Ok(())
}

#[tokio::test]
async fn gasless_signing_never_broadcasts_a_transaction() -> anyhow::Result<()> {
    let (client, _signer_address, log) = test_client().await?;

    client.deposit.sign_eip3009(TOKEN, U256::from(1u64)).await?;
    client.deposit.sign_permit2(TOKEN, U256::from(1u64)).await?;

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
    let auth = client.deposit.sign_eip3009(TOKEN, amount).await?;
    let decoded: sdk_4mica::ReceiveAuthorization =
        serde_json::from_str(&serde_json::to_string(&auth)?)?;
    assert_eq!(decoded.from, signer_address);
    assert_eq!(decoded.validAfter, auth.validAfter);
    assert_eq!(decoded.validBefore, auth.validBefore);
    assert_eq!(decoded.nonce, auth.nonce);
    assert_eq!(decoded.v, auth.v);
    assert_eq!(decoded.r, auth.r);
    assert_eq!(decoded.s, auth.s);

    let permit = client.deposit.sign_permit2(TOKEN, amount).await?;
    let decoded: sdk_4mica::Permit2Authorization =
        serde_json::from_str(&serde_json::to_string(&permit)?)?;
    assert_eq!(decoded.from, signer_address);
    assert_eq!(decoded.nonce, permit.nonce);
    assert_eq!(decoded.deadline, permit.deadline);
    assert_eq!(decoded.signature, permit.signature);
    Ok(())
}

// ── facilitator client ──────────────────────────────────────────────────────
//
// The facilitator path is the reason the signing above is chain-free: a payer with tokens but no
// native gas signs here and something else submits. These tests pin the two properties that make
// that worth having — the SDK never touches an Ethereum RPC, and what it puts on the wire is what
// the facilitator expects to read.

#[tokio::test]
async fn facilitator_deposit_never_touches_an_ethereum_rpc() -> anyhow::Result<()> {
    let (client, signer_address, chain_log, facilitator_log) =
        test_client_with_facilitator(success_response()).await?;

    let receipt = client
        .deposit
        .send_eip3009(TOKEN, U256::from(1_000_000u64))
        .await?;

    assert_eq!(receipt.tx_hash, B256::repeat_byte(0x11));

    // The whole point of routing through a facilitator: signing and submitting cost the payer no
    // chain access at all. A regression here would silently reintroduce the RPC dependency this
    // path exists to remove.
    let chain = chain_log.lock().unwrap();
    assert!(
        chain.eth_calls.is_empty(),
        "a facilitator deposit must make no eth_call, saw {:?}",
        chain.eth_calls
    );
    assert!(
        !chain.methods.iter().any(|m| m.contains("send")),
        "a facilitator deposit must never broadcast, saw {:?}",
        chain.methods
    );

    // …and the request must name the signer, never anyone else.
    let facilitator = facilitator_log.lock().unwrap();
    assert_eq!(facilitator.deposits.len(), 1);
    let body = &facilitator.deposits[0];
    assert_eq!(
        body["authorization"]["from"]
            .as_str()
            .map(str::to_lowercase),
        Some(format!("{signer_address:#x}").to_lowercase())
    );
    Ok(())
}

/// The facilitator deserialises these fields directly, so their names and shapes are a contract
/// between the two crates. Catches drift that would otherwise only surface at runtime.
#[tokio::test]
async fn facilitator_deposit_sends_the_expected_wire_shape() -> anyhow::Result<()> {
    let (client, _signer, _chain, facilitator_log) =
        test_client_with_facilitator(success_response()).await?;

    client
        .deposit
        .send_eip3009(TOKEN, U256::from(1_000_000u64))
        .await?;

    let facilitator = facilitator_log.lock().unwrap();
    let body = &facilitator.deposits[0];

    assert_eq!(body["assetTransferMethod"], "eip3009");
    assert_eq!(body["amount"], "1000000");
    assert_eq!(
        body["asset"].as_str().map(str::to_lowercase),
        Some(TOKEN.to_string().to_lowercase())
    );
    for field in ["from", "validAfter", "validBefore", "nonce", "v", "r", "s"] {
        assert!(
            body["authorization"].get(field).is_some(),
            "authorization is missing {field}: {body}"
        );
    }
    // Sending the unused shape as null would trip the facilitator's exactly-one check.
    assert!(
        body.get("permit2Authorization").is_none(),
        "the unused authorization must be omitted entirely: {body}"
    );
    // Omitted rather than null, so the facilitator falls back to its default network.
    assert!(
        body.get("network").is_none(),
        "network must be omitted: {body}"
    );
    Ok(())
}

#[tokio::test]
async fn facilitator_permit2_deposit_sends_the_permit2_shape() -> anyhow::Result<()> {
    let (client, _signer, _chain, facilitator_log) =
        test_client_with_facilitator(success_response()).await?;

    client
        .deposit
        .send_permit2(TOKEN, U256::from(1_000_000u64))
        .await?;

    let facilitator = facilitator_log.lock().unwrap();
    let body = &facilitator.deposits[0];
    assert_eq!(body["assetTransferMethod"], "permit2");
    for field in ["from", "nonce", "deadline", "signature"] {
        assert!(
            body["permit2Authorization"].get(field).is_some(),
            "permit2Authorization is missing {field}: {body}"
        );
    }
    assert!(body.get("authorization").is_none());
    Ok(())
}

/// A known code becomes a typed variant so callers can branch without matching on prose.
#[tokio::test]
async fn facilitator_maps_a_known_error_code_to_a_typed_variant() -> anyhow::Result<()> {
    let (client, _signer, _chain, _log) = test_client_with_facilitator(json!({
        "success": false,
        "error": "0xabc has approved 0 but 1000 is required",
        "errorCode": "PERMIT2_ALLOWANCE_REQUIRED",
        "retryable": false,
    }))
    .await?;

    let err = client
        .deposit
        .send_permit2(TOKEN, U256::from(1_000_000u64))
        .await
        .expect_err("expected the facilitator's rejection to surface");

    assert!(
        matches!(err, DepositError::Permit2AllowanceRequired { .. }),
        "expected a typed allowance error, got {err:?}"
    );
    Ok(())
}

/// An unrecognised code must survive intact rather than being flattened, so an SDK built today
/// still lets callers branch on a code the facilitator adds tomorrow.
#[tokio::test]
async fn facilitator_passes_through_an_unknown_error_code() -> anyhow::Result<()> {
    let (client, _signer, _chain, _log) = test_client_with_facilitator(json!({
        "success": false,
        "error": "the relayer is on fire",
        "errorCode": "SOMETHING_ADDED_LATER",
        "retryable": true,
    }))
    .await?;

    let err = client
        .deposit
        .send_eip3009(TOKEN, U256::from(1_000_000u64))
        .await
        .expect_err("expected the facilitator's rejection to surface");

    match err {
        DepositError::Facilitator {
            code,
            message,
            retryable,
        } => {
            assert_eq!(code, "SOMETHING_ADDED_LATER");
            assert!(message.contains("on fire"));
            assert!(retryable, "retryability must survive an unrecognised code");
        }
        other => panic!("expected a passthrough Facilitator error, got {other:?}"),
    }
    Ok(())
}

/// Reporting success without a transaction hash is a broken facilitator, not a successful deposit.
#[tokio::test]
async fn facilitator_success_without_a_tx_hash_is_an_error() -> anyhow::Result<()> {
    let (client, _signer, _chain, _log) =
        test_client_with_facilitator(json!({ "success": true })).await?;

    let err = client
        .deposit
        .send_eip3009(TOKEN, U256::from(1_000_000u64))
        .await
        .expect_err("expected a missing txHash to be rejected");
    assert!(
        matches!(err, DepositError::OutcomeUnknown(_)),
        "got {err:?}"
    );
    Ok(())
}

/// Everything construction needs comes from core, so a client that only ever takes sponsored paths
/// never has to reach an Ethereum node — not even to be built.
#[tokio::test]
async fn building_a_client_touches_no_ethereum_rpc() -> anyhow::Result<()> {
    let (_client, _signer, log) = test_client().await?;

    let methods = log.lock().unwrap().methods.clone();
    assert!(
        methods.is_empty(),
        "construction reached the chain: {methods:?}"
    );
    Ok(())
}

#[tokio::test]
async fn facilitator_verify_posts_to_the_preflight_endpoint() -> anyhow::Result<()> {
    let (client, _signer, _chain, facilitator_log) =
        test_client_with_facilitator(success_response()).await?;

    let authorization = client
        .deposit
        .sign_eip3009(TOKEN, U256::from(1_000_000u64))
        .await?;
    client
        .deposit
        .verify_eip3009(TOKEN, U256::from(1_000_000u64), authorization)
        .await?;

    let facilitator = facilitator_log.lock().unwrap();
    assert_eq!(facilitator.verifies.len(), 1);
    assert!(
        facilitator.deposits.is_empty(),
        "verifying must not submit anything"
    );
    Ok(())
}

/// Without a facilitator the call must say so plainly, so a caller can fall back to a self-funded
/// deposit rather than discovering it through a transport error.
#[tokio::test]
async fn facilitator_calls_fail_clearly_when_none_is_configured() -> anyhow::Result<()> {
    let (client, _signer, _log) = test_client().await?;

    assert!(!client.deposit.is_gasless_available());
    let err = client
        .deposit
        .send_eip3009(TOKEN, U256::from(1_000_000u64))
        .await
        .expect_err("expected an unconfigured facilitator to be reported");
    assert!(
        matches!(err, DepositError::FacilitatorNotConfigured),
        "got {err:?}"
    );
    Ok(())
}

/// The sponsored path's whole purpose: recover from a missing allowance by *signing* it, without
/// ever reading the chain for the nonce.
#[tokio::test]
async fn sponsored_permit2_signs_the_approval_and_retries() -> anyhow::Result<()> {
    let facilitator_log = Arc::new(Mutex::new(FacilitatorLog::default()));
    let (client, signer_address, chain_log) = client_against(
        spawn_allowance_then_success_facilitator(Some("7"), facilitator_log.clone()),
    )
    .await?;

    let receipt = client
        .deposit
        .send_sponsored_permit2(TOKEN, U256::from(1_000_000u64))
        .await?;
    assert_eq!(receipt.tx_hash, B256::repeat_byte(0x11));

    let facilitator = facilitator_log.lock().unwrap();
    assert_eq!(facilitator.deposits.len(), 2, "expected one retry");

    // The first attempt carries no permit — sponsoring an approval the payer may already have made
    // would waste the facilitator's gas.
    assert!(facilitator.deposits[0].get("eip2612Permit").is_none());

    // The retry carries one, signed from the nonce the rejection supplied.
    let permit = &facilitator.deposits[1]["eip2612Permit"];
    assert!(permit.is_object(), "retry must carry a permit: {permit}");
    for field in ["value", "deadline", "v", "r", "s"] {
        assert!(
            permit.get(field).is_some(),
            "permit missing {field}: {permit}"
        );
    }
    assert_eq!(
        facilitator.deposits[1]["permit2Authorization"]["from"]
            .as_str()
            .map(str::to_lowercase),
        Some(format!("{signer_address:#x}").to_lowercase())
    );

    // Still chain-free: the nonce came over HTTP, not from an eth_call.
    let chain = chain_log.lock().unwrap();
    assert!(
        chain.eth_calls.is_empty(),
        "the sponsored path must read no chain state, saw {:?}",
        chain.eth_calls
    );
    Ok(())
}

/// The permit must recover to the signer over the token's `Permit` digest.
///
/// Field presence is not enough: a permit with a valid-looking `v` that inverts the parity
/// serialises identically and is rejected only by the token's `ecrecover`, on-chain.
#[tokio::test]
async fn sponsored_permit2_permit_recovers_to_the_signer() -> anyhow::Result<()> {
    let facilitator_log = Arc::new(Mutex::new(FacilitatorLog::default()));
    let (client, signer_address, _chain_log) = client_against(
        spawn_allowance_then_success_facilitator(Some("7"), facilitator_log.clone()),
    )
    .await?;

    client
        .deposit
        .send_sponsored_permit2(TOKEN, U256::from(1_000_000u64))
        .await?;

    let facilitator = facilitator_log.lock().unwrap();
    let permit = &facilitator.deposits[1]["eip2612Permit"];
    let value = U256::from_str(permit["value"].as_str().expect("value is a string"))?;
    let deadline = U256::from_str(permit["deadline"].as_str().expect("deadline is a string"))?;
    let v = permit["v"].as_u64().expect("v is a number") as u8;
    let r = B256::from_str(permit["r"].as_str().expect("r is a string"))?;
    let s = B256::from_str(permit["s"].as_str().expect("s is a string"))?;

    assert!(
        v == 27 || v == 28,
        "v must be Electrum notation for the token's ecrecover, got {v}"
    );

    // Nonce 7 is what the facilitator's rejection advertised; signing any other nonce would
    // produce a permit the token rejects as replayed.
    let digest = expected_permit_digest(
        TOKEN_DOMAIN,
        signer_address,
        PERMIT2,
        value,
        U256::from(7u64),
        deadline,
    );
    let recovered =
        Signature::from_scalars_and_parity(r, s, v == 28).recover_address_from_prehash(&digest)?;
    assert_eq!(
        recovered, signer_address,
        "permit must recover to the signer over the token's Permit digest"
    );
    Ok(())
}

/// Without an `eip2612Nonce` the token has no EIP-2612 surface, so the approval cannot be signed.
/// Retrying anyway would burn the facilitator's gas on a permit the token would reject.
#[tokio::test]
async fn sponsored_permit2_gives_up_when_the_token_has_no_permit() -> anyhow::Result<()> {
    let facilitator_log = Arc::new(Mutex::new(FacilitatorLog::default()));
    let (client, _signer, _chain) = client_against(spawn_allowance_then_success_facilitator(
        None,
        facilitator_log.clone(),
    ))
    .await?;

    let err = client
        .deposit
        .send_sponsored_permit2(TOKEN, U256::from(1_000_000u64))
        .await
        .expect_err("expected the allowance error to surface");

    assert!(
        matches!(
            err,
            DepositError::Permit2AllowanceRequired {
                eip2612_nonce: None,
                ..
            }
        ),
        "got {err:?}"
    );
    assert_eq!(
        facilitator_log.lock().unwrap().deposits.len(),
        1,
        "must not retry when the approval cannot be sponsored"
    );
    Ok(())
}

/// Refuses EIP-3009 as a simulation revert and Permit2 as a missing, unsponsorable allowance —
/// a token no gasless route can serve.
async fn spawn_no_gasless_route_facilitator(
    log: Arc<Mutex<FacilitatorLog>>,
) -> anyhow::Result<String> {
    spawn(Router::new().route(
        "/deposit",
        post(move |Json(body): Json<Value>| {
            let log = log.clone();
            async move {
                let response = if body["assetTransferMethod"] == "eip3009" {
                    json!({
                        "success": false,
                        "error": "deposit would revert",
                        "errorCode": "SIMULATION_REVERTED",
                        "retryable": false,
                    })
                } else {
                    json!({
                        "success": false,
                        "error": "approve permit2 first",
                        "errorCode": "PERMIT2_ALLOWANCE_REQUIRED",
                        "retryable": false,
                        "permit2Allowance": {
                            "spender": "0x000000000022d473030f116ddee9f6b43ac78ba3",
                            "allowance": "0",
                            "required": "1000000",
                        },
                    })
                };
                log.lock().unwrap().deposits.push(body);
                Json(response)
            }
        }),
    ))
    .await
}

/// With no gasless route left, the self-funded fallback needs an ERC-20 allowance the gasless
/// caller was never asked for. Without one it is refused with the fix named, rather than
/// broadcast to revert opaquely inside the token.
#[tokio::test]
async fn a_fallback_without_an_erc20_allowance_is_refused_not_broadcast() -> anyhow::Result<()> {
    let facilitator_log = Arc::new(Mutex::new(FacilitatorLog::default()));
    let (client, _signer, _chain) =
        client_against(spawn_no_gasless_route_facilitator(facilitator_log.clone())).await?;

    let err = client
        .deposit
        .send(Asset::Erc20(TOKEN), U256::from(1_000_000u64))
        .await
        .expect_err("a fallback without an allowance must be refused");

    assert!(
        matches!(
            err,
            DepositError::Erc20AllowanceRequired { needed, .. }
                if needed == U256::from(1_000_000u64)
        ),
        "got {err:?}"
    );
    assert_eq!(
        facilitator_log.lock().unwrap().deposits.len(),
        2,
        "eip3009 and then plain permit2 must both have been offered"
    );
    Ok(())
}

/// A token core publishes no EIP-712 domain separator for. EIP-3009 and EIP-2612 digests cannot
/// be built for it, but that closes those schemes, not the route.
const UNLISTED_TOKEN: Address = address!("000000000000000000000000000000000000ee75");

/// With no published domain separator the EIP-3009 digest cannot be built — but Permit2's domain
/// derives from the chain id, so the deposit still goes out gaslessly, without a wasted EIP-3009
/// request.
#[tokio::test]
async fn a_token_with_no_published_domain_deposits_over_permit2() -> anyhow::Result<()> {
    let facilitator_log = Arc::new(Mutex::new(FacilitatorLog::default()));
    let mut response = success_response();
    response["asset"] = json!(UNLISTED_TOKEN.to_string());
    let (client, _signer, chain_log) =
        client_against(spawn_facilitator(response, facilitator_log.clone())).await?;

    let receipt = client
        .deposit
        .send(Asset::Erc20(UNLISTED_TOKEN), U256::from(1_000_000u64))
        .await?;

    assert_eq!(receipt.path, DepositPath::Permit2);

    let facilitator = facilitator_log.lock().unwrap();
    assert_eq!(
        facilitator.deposits.len(),
        1,
        "an unsignable EIP-3009 authorization must not reach the facilitator"
    );
    assert_eq!(facilitator.deposits[0]["assetTransferMethod"], "permit2");

    // Still chain-free: the missing domain was learned from core, not an eth_call.
    let chain = chain_log.lock().unwrap();
    assert!(
        chain.eth_calls.is_empty(),
        "routing around the missing domain must read no chain state, saw {:?}",
        chain.eth_calls
    );
    Ok(())
}

/// With no domain separator the EIP-2612 permit cannot be signed either, so a missing allowance
/// is a dead end even when the facilitator advertises a nonce — reported as unsponsorable
/// (`eip2612_nonce: None`), which is exactly what routes `send` to self-funded.
#[tokio::test]
async fn a_missing_allowance_without_a_token_domain_cannot_be_sponsored() -> anyhow::Result<()> {
    let facilitator_log = Arc::new(Mutex::new(FacilitatorLog::default()));
    let (client, _signer, _chain) = client_against(spawn_allowance_then_success_facilitator(
        Some("7"),
        facilitator_log.clone(),
    ))
    .await?;

    let err = client
        .deposit
        .send_sponsored_permit2(UNLISTED_TOKEN, U256::from(1_000_000u64))
        .await
        .expect_err("expected the allowance error to surface");

    assert!(
        matches!(
            err,
            DepositError::Permit2AllowanceRequired {
                eip2612_nonce: None,
                ..
            }
        ),
        "got {err:?}"
    );
    assert_eq!(
        facilitator_log.lock().unwrap().deposits.len(),
        1,
        "must not retry a permit that cannot be signed"
    );
    Ok(())
}
