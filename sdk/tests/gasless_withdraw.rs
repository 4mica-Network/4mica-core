//! Tests for the gasless withdrawal routes — the `gasless()` pins' `sign()`/`send()` terminals,
//! and the fallback the unpinned `request`/`cancel`/`finalize` builders take.
//!
//! These run fully offline against a mock JSON-RPC node, a mock core and a mock facilitator, so
//! they cover what `contracts/test/Core4MicaGaslessWithdrawal.t.sol` cannot: whether the *SDK*
//! builds the digest the contract will actually check, and what it puts on the wire. Every expected
//! digest is recomputed from raw keccak/ABI words with the type strings spelled out literally —
//! never via `sdk_4mica::digest` — so a swapped argument or a wrong domain separator fails the
//! recovery assertion instead of cancelling out on both sides.

use alloy::primitives::{Address, B256, Signature, U256, address, b256, keccak256};
use alloy::signers::local::PrivateKeySigner;
use axum::{Json, Router, routing::get, routing::post};
use crypto::bls::KeyMaterial;
use rpc::{CorePublicParameters, GUARANTEE_CLAIMS_VERSION, GuaranteeVersionDomain};
use sdk_4mica::error::{SponsorshipError, WithdrawError};
use sdk_4mica::{Asset, Client, ClientBuilder, Route};
use serde_json::{Value, json};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::net::TcpListener;

const CHAIN_ID: u64 = 1337;
const CONTRACT: Address = address!("00000000000000000000000000000000c04e4a1c");
const TOKEN: Address = address!("000000000000000000000000000000000000d0c5");

/// Core4Mica's own domain separator, distinct from the token's so a test fails loudly if the SDK
/// signs a withdrawal under the wrong one.
const CORE_DOMAIN: B256 = b256!("4444444444444444444444444444444444444444444444444444444444444444");
const TOKEN_DOMAIN: B256 =
    b256!("1111111111111111111111111111111111111111111111111111111111111111");
const GUARANTEE_DOMAIN: B256 =
    b256!("3333333333333333333333333333333333333333333333333333333333333333");

/// Matches `AUTHORIZATION_TTL_SECS` in `sdk/src/client/sig.rs`.
const EXPECTED_TTL_SECS: u64 = 3600;

const AMOUNT: u64 = 1_000_000;
const BLS_SECRET: &str = "0x4573DBD225C8E065FC30FF774C9EF81BD29D34E559D80E2276EE7824812399D3";

// Canonical EIP-712 `encodeType` strings the contract hashes. Spelled out here so a field reorder
// in the SDK fails rather than cancelling out.
const REQUEST_TYPE: &str = "RequestWithdrawal(address user,address asset,uint256 amount,uint256 validAfter,uint256 validBefore,bytes32 nonce)";
const CANCEL_TYPE: &str = "CancelWithdrawal(address user,address asset,uint256 validAfter,uint256 validBefore,bytes32 nonce)";

fn word_address(value: Address) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[12..].copy_from_slice(value.as_slice());
    word
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

fn expected_request_digest(
    domain: B256,
    user: Address,
    asset: Address,
    amount: U256,
    valid_after: U256,
    valid_before: U256,
    nonce: B256,
) -> B256 {
    let mut encoded = Vec::with_capacity(32 * 7);
    encoded.extend_from_slice(keccak256(REQUEST_TYPE.as_bytes()).as_slice());
    encoded.extend_from_slice(&word_address(user));
    encoded.extend_from_slice(&word_address(asset));
    encoded.extend_from_slice(&amount.to_be_bytes::<32>());
    encoded.extend_from_slice(&valid_after.to_be_bytes::<32>());
    encoded.extend_from_slice(&valid_before.to_be_bytes::<32>());
    encoded.extend_from_slice(nonce.as_slice());
    eip712_digest(domain, keccak256(encoded))
}

fn expected_cancel_digest(
    domain: B256,
    user: Address,
    asset: Address,
    valid_after: U256,
    valid_before: U256,
    nonce: B256,
) -> B256 {
    let mut encoded = Vec::with_capacity(32 * 6);
    encoded.extend_from_slice(keccak256(CANCEL_TYPE.as_bytes()).as_slice());
    encoded.extend_from_slice(&word_address(user));
    encoded.extend_from_slice(&word_address(asset));
    encoded.extend_from_slice(&valid_after.to_be_bytes::<32>());
    encoded.extend_from_slice(&valid_before.to_be_bytes::<32>());
    encoded.extend_from_slice(nonce.as_slice());
    eip712_digest(domain, keccak256(encoded))
}

/// Core4Mica's domain separator as the contract builds it, from `EIP712("Core4Mica", "1")`. Spelled
/// out rather than taken from the SDK, so a wrong name or version there cannot cancel out.
fn expected_core_domain(chain_id: u64, contract: Address) -> B256 {
    let mut encoded = Vec::with_capacity(32 * 5);
    encoded.extend_from_slice(
        keccak256(
            b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
                .as_slice(),
        )
        .as_slice(),
    );
    encoded.extend_from_slice(keccak256(b"Core4Mica".as_slice()).as_slice());
    encoded.extend_from_slice(keccak256(b"1".as_slice()).as_slice());
    encoded.extend_from_slice(&U256::from(chain_id).to_be_bytes::<32>());
    encoded.extend_from_slice(&word_address(contract));
    keccak256(encoded)
}

fn selector(signature: &str) -> [u8; 4] {
    let hash = keccak256(signature.as_bytes());
    [hash[0], hash[1], hash[2], hash[3]]
}

/// Every JSON-RPC call the SDK made, so tests can assert that signing stays off the chain and —
/// crucially — whether a transaction was ever broadcast.
#[derive(Default)]
struct CallLog {
    methods: Vec<String>,
    eth_calls: Vec<(Address, [u8; 4])>,
}

impl CallLog {
    fn broadcast_a_transaction(&self) -> bool {
        self.methods
            .iter()
            .any(|method| method == "eth_sendRawTransaction")
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
        // Enough for the wallet provider to build a transaction, so a self-funded fallback gets as
        // far as broadcasting — which is what the fallback tests assert on.
        "eth_getTransactionCount" => json_rpc_result(&id, json!("0x0")),
        "eth_gasPrice" | "eth_maxPriorityFeePerGas" => json_rpc_result(&id, json!("0x1")),
        "eth_estimateGas" => json_rpc_result(&id, json!("0x100000")),
        "eth_blockNumber" => json_rpc_result(&id, json!("0x1")),
        "eth_feeHistory" => json_rpc_result(
            &id,
            json!({
                "oldestBlock": "0x1",
                "baseFeePerGas": ["0x1", "0x1"],
                "gasUsedRatio": [0.5],
                "reward": [["0x1"]],
            }),
        ),
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

            if sel == selector("getGuaranteeVersionConfig(uint64)") {
                return json_rpc_result(&id, json!(encode_guarantee_version_config()));
            }
            // No `DOMAIN_SEPARATOR()` case, deliberately: the separator comes from core over HTTP,
            // so an eth_call for one is a regression and fails here as a JSON-RPC error.
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
        chain_id: CHAIN_ID,
        ethereum_http_rpc_url: eth_rpc_url.to_string(),
        guarantee_domain_separator: format!("0x{}", alloy::hex::encode(GUARANTEE_DOMAIN)),
        guarantee_domains: vec![GuaranteeVersionDomain {
            version: GUARANTEE_CLAIMS_VERSION,
            domain_separator: format!("0x{}", alloy::hex::encode(GUARANTEE_DOMAIN)),
        }],
        core_domain_separator: format!("0x{}", alloy::hex::encode(CORE_DOMAIN)),
        supported_guarantee_versions: vec![GUARANTEE_CLAIMS_VERSION],
        eip712_name: "4Mica".into(),
        eip712_version: "1".into(),
        validators: Vec::new(),
    }
}

#[derive(Default)]
struct FacilitatorLog {
    withdrawals: Vec<Value>,
    verifies: Vec<Value>,
}

/// A stand-in facilitator that records requests and replies with `response`. Deliberately dumb: the
/// point is to observe what the SDK puts on the wire and how it maps the reply back.
async fn spawn_facilitator(
    response: Value,
    log: Arc<Mutex<FacilitatorLog>>,
) -> anyhow::Result<String> {
    let withdraw_log = log.clone();
    spawn(
        Router::new()
            .route(
                "/withdraw",
                post(move |Json(body): Json<Value>| {
                    let log = withdraw_log.clone();
                    let response = response.clone();
                    async move {
                        let response = echoing_request(response, &body);
                        log.lock().unwrap().withdrawals.push(body);
                        Json(response)
                    }
                }),
            )
            .route(
                "/withdraw/verify",
                post(move |Json(body): Json<Value>| {
                    let log = log.clone();
                    async move {
                        log.lock().unwrap().verifies.push(body);
                        Json(json!({ "isValid": true }))
                    }
                }),
            ),
    )
    .await
}

fn success_response() -> Value {
    json!({
        "success": true,
        "txHash": "0x1111111111111111111111111111111111111111111111111111111111111111",
        "network": "eip155:1337",
    })
}

/// Stamps `response` with the user and asset the request carried, as a real facilitator echoes what
/// it acted on. The SDK refuses a receipt naming anything else, and canned values could match
/// neither the signer, which is random per test, nor a withdrawal of an asset other than `TOKEN`.
fn echoing_request(mut response: Value, request: &Value) -> Value {
    // A finalize carries no authorization: it names the user and asset directly.
    let authorization = request.get("authorization");
    for field in ["user", "asset"] {
        let echoed = authorization
            .and_then(|auth| auth.get(field))
            .or_else(|| request.get(field));
        if let (Some(echoed), Some(fields)) = (echoed, response.as_object_mut()) {
            fields.insert(field.into(), echoed.clone());
        }
    }
    response
}

fn rejection(code: &str) -> Value {
    json!({
        "success": false,
        "error": "no",
        "errorCode": code,
        "retryable": false,
    })
}

/// Builds a `Client` pointed at a mock chain, a mock core, and `facilitator_url` if given.
async fn client_with(
    facilitator_url: Option<String>,
) -> anyhow::Result<(Client<PrivateKeySigner>, Address, Arc<Mutex<CallLog>>)> {
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
    let mut builder = ClientBuilder::default()
        .rpc_url(core_url)
        .signer(signer)
        .ethereum_http_rpc_url(eth_url)
        .contract_address(CONTRACT.to_string());
    if let Some(url) = facilitator_url {
        builder = builder.facilitator_url(url);
    }

    let client = Client::connect(builder.build()?).await?;
    // Drop setup traffic so per-test assertions only see the withdrawal calls.
    let mut guard = log.lock().unwrap();
    guard.eth_calls.clear();
    guard.methods.clear();
    drop(guard);
    Ok((client, signer_address, log))
}

async fn client_with_facilitator(
    response: Value,
) -> anyhow::Result<(
    Client<PrivateKeySigner>,
    Address,
    Arc<Mutex<CallLog>>,
    Arc<Mutex<FacilitatorLog>>,
)> {
    let facilitator_log = Arc::new(Mutex::new(FacilitatorLog::default()));
    let url = spawn_facilitator(response, facilitator_log.clone()).await?;
    let (client, signer, chain_log) = client_with(Some(url)).await?;
    Ok((client, signer, chain_log, facilitator_log))
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_secs()
}

// ── signing ─────────────────────────────────────────────────────────────────

/// The one assertion that matters: the digest the SDK signs is the digest the contract checks.
#[tokio::test]
async fn a_signed_request_recovers_to_the_signer_over_the_contracts_digest() -> anyhow::Result<()> {
    let (client, signer, _log) = client_with(None).await?;
    let before = now_secs();

    let auth = client
        .withdraw
        .request(Asset::Erc20(TOKEN), U256::from(AMOUNT))
        .gasless()
        .sign()
        .await?;

    assert_eq!(auth.user, signer);
    assert_eq!(auth.asset, TOKEN);
    assert_eq!(auth.amount, U256::from(AMOUNT));
    assert_eq!(auth.validAfter, U256::ZERO);

    let digest = expected_request_digest(
        CORE_DOMAIN,
        auth.user,
        auth.asset,
        auth.amount,
        auth.validAfter,
        auth.validBefore,
        auth.nonce,
    );
    let signature = Signature::try_from(auth.signature.as_ref())?;
    assert_eq!(signature.recover_address_from_prehash(&digest)?, signer);

    let ttl = auth.validBefore.to::<u64>() - before;
    assert!(
        ttl <= EXPECTED_TTL_SECS && ttl + 5 >= EXPECTED_TTL_SECS,
        "expected a ~{EXPECTED_TTL_SECS}s window, got {ttl}s"
    );
    Ok(())
}

#[tokio::test]
async fn a_signed_cancel_recovers_to_the_signer_over_the_contracts_digest() -> anyhow::Result<()> {
    let (client, signer, _log) = client_with(None).await?;

    let auth = client
        .withdraw
        .cancel(Asset::Erc20(TOKEN))
        .gasless()
        .sign()
        .await?;

    let digest = expected_cancel_digest(
        CORE_DOMAIN,
        auth.user,
        auth.asset,
        auth.validAfter,
        auth.validBefore,
        auth.nonce,
    );
    let signature = Signature::try_from(auth.signature.as_ref())?;
    assert_eq!(signature.recover_address_from_prehash(&digest)?, signer);
    Ok(())
}

/// Unlike a deposit, ETH has a sponsored route — the contract verifies the signature itself rather
/// than leaning on what the asset implements. `Address::ZERO` is how ETH travels.
#[tokio::test]
async fn eth_withdrawals_can_be_signed_too() -> anyhow::Result<()> {
    let (client, signer, _log) = client_with(None).await?;

    let auth = client
        .withdraw
        .request(Asset::Native, U256::from(AMOUNT))
        .gasless()
        .sign()
        .await?;

    assert_eq!(auth.asset, Address::ZERO);
    let digest = expected_request_digest(
        CORE_DOMAIN,
        auth.user,
        auth.asset,
        auth.amount,
        auth.validAfter,
        auth.validBefore,
        auth.nonce,
    );
    let signature = Signature::try_from(auth.signature.as_ref())?;
    assert_eq!(signature.recover_address_from_prehash(&digest)?, signer);
    Ok(())
}

/// Two authorizations must never share a nonce, or the second is dead on arrival: the contract
/// burns the nonce, not the digest.
#[tokio::test]
async fn each_authorization_gets_a_fresh_nonce() -> anyhow::Result<()> {
    let (client, _signer, _log) = client_with(None).await?;

    let first = client
        .withdraw
        .request(Asset::Erc20(TOKEN), U256::from(AMOUNT))
        .gasless()
        .sign()
        .await?;
    let second = client
        .withdraw
        .request(Asset::Erc20(TOKEN), U256::from(AMOUNT))
        .gasless()
        .sign()
        .await?;

    assert_ne!(first.nonce, second.nonce);
    Ok(())
}

/// Signing is pure: the separator comes from core over HTTP and is resolved at startup, so a payer
/// can authorize a withdrawal with no chain access of their own.
#[tokio::test]
async fn signing_never_touches_the_chain() -> anyhow::Result<()> {
    let (client, _signer, log) = client_with(None).await?;

    client
        .withdraw
        .request(Asset::Erc20(TOKEN), U256::from(AMOUNT))
        .gasless()
        .sign()
        .await?;
    client
        .withdraw
        .cancel(Asset::Erc20(TOKEN))
        .gasless()
        .sign()
        .await?;

    let calls = log.lock().unwrap().eth_calls.clone();
    assert!(calls.is_empty(), "signing made chain calls: {calls:?}");
    Ok(())
}

/// A core too old to publish the guarantee domains is no obstacle either — the client reads them
/// off the contract instead, which is the one thing at startup that still needs an endpoint.
#[tokio::test]
async fn a_core_that_publishes_no_guarantee_domains_reads_them_from_the_chain() -> anyhow::Result<()>
{
    let log = Arc::new(Mutex::new(CallLog::default()));
    let eth_url = spawn(
        Router::new()
            .route("/", post(handle_rpc))
            .with_state(log.clone()),
    )
    .await?;

    let mut params = public_params(&eth_url);
    params.guarantee_domains = Vec::new();
    let core_url = spawn(Router::new().route(
        "/core/public-params",
        get(move || {
            let params = params.clone();
            async move { Json(params) }
        }),
    ))
    .await?;

    let client = Client::connect(
        ClientBuilder::default()
            .rpc_url(core_url)
            .signer(PrivateKeySigner::random())
            .ethereum_http_rpc_url(eth_url)
            .contract_address(CONTRACT.to_string())
            .build()?,
    )
    .await?;

    assert_eq!(client.payment.guarantee_domain(), &GUARANTEE_DOMAIN.0);
    let want = selector("getGuaranteeVersionConfig(uint64)");
    let calls = log.lock().unwrap().eth_calls.clone();
    assert!(
        calls.iter().any(|(_, sel)| *sel == want),
        "expected the version config to be read from the contract, saw {calls:?}"
    );
    Ok(())
}

/// A core too old to publish the separator is no obstacle: the contract's domain is fixed, so the
/// client derives it and signs under exactly what the contract will check.
#[tokio::test]
async fn a_core_that_publishes_no_separator_falls_back_to_the_derived_domain() -> anyhow::Result<()>
{
    let log = Arc::new(Mutex::new(CallLog::default()));
    let eth_url = spawn(
        Router::new()
            .route("/", post(handle_rpc))
            .with_state(log.clone()),
    )
    .await?;

    let mut params = public_params(&eth_url);
    params.core_domain_separator = String::new();
    let core_url = spawn(Router::new().route(
        "/core/public-params",
        get(move || {
            let params = params.clone();
            async move { Json(params) }
        }),
    ))
    .await?;

    let config = ClientBuilder::default()
        .rpc_url(core_url)
        .signer(PrivateKeySigner::random())
        .ethereum_http_rpc_url(eth_url)
        .contract_address(CONTRACT.to_string())
        .build()?;

    let client = Client::connect(config).await?;
    let signer = client.signer_address();

    let auth = client
        .withdraw
        .request(Asset::Erc20(TOKEN), U256::from(AMOUNT))
        .gasless()
        .sign()
        .await?;

    let digest = expected_request_digest(
        expected_core_domain(CHAIN_ID, CONTRACT),
        auth.user,
        auth.asset,
        auth.amount,
        auth.validAfter,
        auth.validBefore,
        auth.nonce,
    );
    let signature = Signature::try_from(auth.signature.as_ref())?;
    assert_eq!(signature.recover_address_from_prehash(&digest)?, signer);
    Ok(())
}

/// What core publishes wins, so a deployment whose domain has moved on from the derivation still
/// signs correctly.
#[tokio::test]
async fn a_published_separator_takes_precedence_over_the_derivation() -> anyhow::Result<()> {
    let (client, signer, _log) = client_with(None).await?;

    let auth = client
        .withdraw
        .request(Asset::Erc20(TOKEN), U256::from(AMOUNT))
        .gasless()
        .sign()
        .await?;

    assert_ne!(
        CORE_DOMAIN,
        expected_core_domain(CHAIN_ID, CONTRACT),
        "the mock core must publish something the derivation would not produce"
    );
    let digest = expected_request_digest(
        CORE_DOMAIN,
        auth.user,
        auth.asset,
        auth.amount,
        auth.validAfter,
        auth.validBefore,
        auth.nonce,
    );
    let signature = Signature::try_from(auth.signature.as_ref())?;
    assert_eq!(signature.recover_address_from_prehash(&digest)?, signer);
    Ok(())
}

// ── wire format ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_sponsored_request_puts_the_authorization_on_the_wire() -> anyhow::Result<()> {
    let (client, signer, chain_log, facilitator_log) =
        client_with_facilitator(success_response()).await?;

    let receipt = client
        .withdraw
        .request(Asset::Erc20(TOKEN), U256::from(AMOUNT))
        .gasless()
        .send()
        .await?;

    assert_eq!(receipt.route, Route::Gasless);
    assert!(receipt.route.is_gasless());
    assert!(
        !chain_log.lock().unwrap().broadcast_a_transaction(),
        "a sponsored withdrawal must cost the user no transaction"
    );

    let sent = facilitator_log.lock().unwrap().withdrawals[0].clone();
    assert_eq!(sent["action"], "request");
    assert_eq!(
        sent["authorization"]["user"]
            .as_str()
            .unwrap()
            .to_lowercase(),
        format!("{signer:#x}")
    );
    assert!(sent["authorization"]["signature"].is_string());
    assert!(
        sent.get("user").is_none(),
        "a request carries its user inside the authorization, not alongside it"
    );
    Ok(())
}

#[tokio::test]
async fn a_sponsored_cancel_is_tagged_as_such() -> anyhow::Result<()> {
    let (client, _signer, _chain_log, facilitator_log) =
        client_with_facilitator(success_response()).await?;

    client
        .withdraw
        .cancel(Asset::Erc20(TOKEN))
        .gasless()
        .send()
        .await?;

    let sent = facilitator_log.lock().unwrap().withdrawals[0].clone();
    assert_eq!(sent["action"], "cancel");
    assert!(
        sent["authorization"].get("amount").is_none(),
        "a cancellation clears whatever is pending, so it signs no amount"
    );
    Ok(())
}

/// Finalization is permissionless, so the SDK must send no authorization at all — the user may be
/// long gone by the time the grace period elapses.
#[tokio::test]
async fn a_sponsored_finalize_carries_no_authorization() -> anyhow::Result<()> {
    let (client, signer, chain_log, facilitator_log) =
        client_with_facilitator(success_response()).await?;

    client
        .withdraw
        .finalize(Asset::Erc20(TOKEN))
        .gasless()
        .send()
        .await?;

    let sent = facilitator_log.lock().unwrap().withdrawals[0].clone();
    assert_eq!(sent["action"], "finalize");
    assert!(sent.get("authorization").is_none());
    assert_eq!(
        sent["user"].as_str().unwrap().to_lowercase(),
        format!("{signer:#x}")
    );
    assert!(!chain_log.lock().unwrap().broadcast_a_transaction());
    Ok(())
}

/// An authorization signed here and redeemed through `authorization(…)` must put the same request
/// on the wire as signing and sending in one go.
#[tokio::test]
async fn an_attached_authorization_round_trips_through_send() -> anyhow::Result<()> {
    let (client, signer, _chain_log, facilitator_log) =
        client_with_facilitator(success_response()).await?;

    let authorization = client
        .withdraw
        .request(Asset::Erc20(TOKEN), U256::from(AMOUNT))
        .gasless()
        .sign()
        .await?;
    let receipt = client
        .withdraw
        .request(Asset::Erc20(TOKEN), U256::from(AMOUNT))
        .gasless()
        .authorization(authorization)
        .send()
        .await?;

    assert_eq!(receipt.account, signer);
    let sent = facilitator_log.lock().unwrap().withdrawals[0].clone();
    assert_eq!(sent["action"], "request");
    assert!(sent["authorization"]["signature"].is_string());
    Ok(())
}

/// The authorization names its own terms, so a builder that disagrees is refused before anything
/// reaches the facilitator.
#[tokio::test]
async fn a_mismatched_authorization_is_refused_locally() -> anyhow::Result<()> {
    let (client, _signer, _chain_log, facilitator_log) =
        client_with_facilitator(success_response()).await?;

    let authorization = client
        .withdraw
        .request(Asset::Erc20(TOKEN), U256::from(AMOUNT))
        .gasless()
        .sign()
        .await?;
    let err = client
        .withdraw
        .request(Asset::Erc20(TOKEN), U256::from(AMOUNT + 1))
        .gasless()
        .authorization(authorization)
        .send()
        .await
        .unwrap_err();

    assert!(matches!(err, WithdrawError::InvalidParams(_)), "{err:?}");
    let facilitator = facilitator_log.lock().unwrap();
    assert!(
        facilitator.withdrawals.is_empty() && facilitator.verifies.is_empty(),
        "a mismatch must not reach the facilitator"
    );
    Ok(())
}

#[tokio::test]
async fn finalize_verify_posts_to_the_preflight_endpoint() -> anyhow::Result<()> {
    let (client, signer, _chain_log, facilitator_log) =
        client_with_facilitator(success_response()).await?;

    client
        .withdraw
        .finalize(Asset::Erc20(TOKEN))
        .gasless()
        .verify()
        .await?;

    let facilitator = facilitator_log.lock().unwrap();
    let sent = &facilitator.verifies[0];
    assert_eq!(sent["action"], "finalize");
    assert_eq!(
        sent["user"].as_str().unwrap().to_lowercase(),
        format!("{signer:#x}")
    );
    assert!(
        facilitator.withdrawals.is_empty(),
        "verifying must not submit anything"
    );
    Ok(())
}

#[tokio::test]
async fn native_eth_travels_as_the_zero_address() -> anyhow::Result<()> {
    let (client, _signer, _chain_log, facilitator_log) =
        client_with_facilitator(success_response()).await?;

    client
        .withdraw
        .request(Asset::Native, U256::from(AMOUNT))
        .gasless()
        .send()
        .await?;

    let sent = facilitator_log.lock().unwrap().withdrawals[0].clone();
    assert_eq!(
        sent["authorization"]["asset"]
            .as_str()
            .unwrap()
            .to_lowercase(),
        format!("{:#x}", Address::ZERO)
    );
    Ok(())
}

// ── fallback ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn no_facilitator_means_the_gasless_call_says_so() -> anyhow::Result<()> {
    let (client, _signer, _log) = client_with(None).await?;

    let err = client
        .withdraw
        .request(Asset::Erc20(TOKEN), U256::from(AMOUNT))
        .gasless()
        .send()
        .await
        .expect_err("no facilitator is configured");

    assert!(matches!(
        err,
        WithdrawError::Sponsorship(SponsorshipError::NotConfigured)
    ));
    Ok(())
}

/// With no facilitator, the fallback take goes straight to the user's own transaction rather than
/// failing. The mock chain refuses the broadcast, so the call still errors — but the attempt is the
/// assertion.
#[tokio::test]
async fn request_falls_back_to_self_funding_without_a_facilitator() -> anyhow::Result<()> {
    let (client, _signer, log) = client_with(None).await?;

    let _ = client
        .withdraw
        .request(Asset::Erc20(TOKEN), U256::from(AMOUNT))
        .send()
        .await;

    assert!(
        log.lock().unwrap().broadcast_a_transaction(),
        "expected the SDK to send the user's own transaction"
    );
    Ok(())
}

/// Throttling says nothing about the request, so paying for it directly is the right answer.
#[tokio::test]
async fn a_throttled_facilitator_falls_back_to_self_funding() -> anyhow::Result<()> {
    let (client, _signer, log, facilitator_log) =
        client_with_facilitator(rejection("RATE_LIMITED")).await?;

    let _ = client
        .withdraw
        .request(Asset::Erc20(TOKEN), U256::from(AMOUNT))
        .send()
        .await;

    assert_eq!(facilitator_log.lock().unwrap().withdrawals.len(), 1);
    assert!(
        log.lock().unwrap().broadcast_a_transaction(),
        "throttling is not a verdict on the request, so the user should be able to pay for it"
    );
    Ok(())
}

/// The opposite case: a rejection that names the request would revert the user's own transaction
/// too, so falling back would only cost them gas to learn what they already know.
#[tokio::test]
async fn a_rejection_naming_the_request_is_returned_rather_than_retried() -> anyhow::Result<()> {
    let (client, _signer, log, _facilitator_log) =
        client_with_facilitator(rejection("SIMULATION_REVERTED")).await?;

    let err = client
        .withdraw
        .request(Asset::Erc20(TOKEN), U256::from(AMOUNT))
        .send()
        .await
        .expect_err("the facilitator said this would revert");

    assert!(matches!(
        err,
        WithdrawError::Sponsorship(SponsorshipError::Rejected { .. })
    ));
    assert!(
        !log.lock().unwrap().broadcast_a_transaction(),
        "a doomed request must not be paid for twice"
    );
    Ok(())
}

#[tokio::test]
async fn cancel_falls_back_the_same_way() -> anyhow::Result<()> {
    let (client, _signer, log, _facilitator_log) =
        client_with_facilitator(rejection("RELAYER_BALANCE_TOO_LOW")).await?;

    let _ = client.withdraw.cancel(Asset::Erc20(TOKEN)).send().await;

    assert!(log.lock().unwrap().broadcast_a_transaction());
    Ok(())
}

#[tokio::test]
async fn a_facilitator_that_reports_success_without_a_tx_hash_is_not_believed() -> anyhow::Result<()>
{
    let (client, _signer, _log, _facilitator_log) =
        client_with_facilitator(json!({ "success": true })).await?;

    let err = client
        .withdraw
        .cancel(Asset::Erc20(TOKEN))
        .gasless()
        .send()
        .await
        .expect_err("success without a txHash is not a success");

    assert!(matches!(
        err,
        WithdrawError::Sponsorship(SponsorshipError::OutcomeUnknown(_))
    ));
    Ok(())
}

#[tokio::test]
async fn is_gasless_available_reports_whether_a_facilitator_is_configured() -> anyhow::Result<()> {
    let (bare, _signer, _log) = client_with(None).await?;
    assert!(!bare.withdraw.is_gasless_available());

    let (wired, _signer, _log, _facilitator_log) =
        client_with_facilitator(success_response()).await?;
    assert!(wired.withdraw.is_gasless_available());
    Ok(())
}
