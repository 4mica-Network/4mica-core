//! Tests for claiming a net credit — one's own or someone else's.
//!
//! `claimNetCreditFor` (the only claim entrypoint) pays the address the committed Merkle leaf
//! names, so a submitter can neither redirect the payout nor inflate it — which is what makes it
//! sponsorable. The contract enforces that (see `contracts/test/ClearingHouse.t.sol`); what these
//! cover is the *SDK* half, where the failure mode is quieter: sending the signer's own address
//! where the caller named someone else, which on-chain just reverts as an unprovable claim.
//!
//! With a facilitator configured the claim is routed there instead — the facilitator's relayer
//! pays the gas — falling back to the caller's own transaction only when the facilitator would
//! not sponsor, and never when its refusal names the claim itself.
//!
//! The debit side mirrors the routing but not the trust model: paying pulls money *out of* the
//! debtor's wallet, so what travels to the facilitator is an EIP-3009 authorization — or, for a
//! token that cannot redeem one, a Permit2 authorization — whose bindings — the ClearingHouse as
//! receiver/spender, the leaf's exact amount, the cycle id as nonce — these tests pin
//! byte-for-byte by recomputing the digests from literal type strings.

use alloy::consensus::{Transaction, TxEnvelope};
use alloy::eips::eip2718::Decodable2718;
use alloy::primitives::{Address, B256, Signature, U256, address, keccak256};
use alloy::signers::local::PrivateKeySigner;
use alloy::sol_types::SolCall;
use axum::{Json, Router, extract::Path, routing::get, routing::post};
use crypto::bls::KeyMaterial;
use rpc::{CorePublicParameters, GUARANTEE_CLAIMS_VERSION, GuaranteeVersionDomain};
use sdk_4mica::client::model::{ClaimPath, PayPath};
use sdk_4mica::contract::ClearingHouse::{claimNetCreditForCall, payNetDebitCall};
use sdk_4mica::error::{ClearingSettlementError, SponsorshipError};
use sdk_4mica::{Client, ConfigBuilder};
use serde_json::{Value, json};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;

const CHAIN_ID: u64 = 1337;
const CONTRACT: Address = address!("00000000000000000000000000000000c04e4a1c");
const CLEARING_HOUSE: Address = address!("00000000000000000000000000000000c1ea4111");
const CREDITOR: Address = address!("000000000000000000000000000000000000c0ed");
const TOKEN: Address = address!("000000000000000000000000000000000000d0c5");
const CYCLE_ID: B256 = B256::repeat_byte(0xaa);
const AMOUNT: u64 = 1_000_000;

const GUARANTEE_DOMAIN: B256 = B256::repeat_byte(0x33);
const CORE_DOMAIN: B256 = B256::repeat_byte(0x44);
const TOKEN_DOMAIN: B256 = B256::repeat_byte(0x55);
const BLS_SECRET: &str = "0x4573DBD225C8E065FC30FF774C9EF81BD29D34E559D80E2276EE7824812399D3";

/// What the SDK put on the wire, so a test can assert on the transaction rather than only on the
/// call having been made at all.
#[derive(Default)]
struct ChainLog {
    /// Participant path segments the core action endpoint was asked for.
    action_requests: Vec<String>,
    broadcasts: Vec<TxEnvelope>,
    /// ERC-20 allowance served to the fallback pre-check. `None` reads as unlimited, so tests
    /// that exercise the fallback broadcast need not grant one.
    erc20_allowance: Option<U256>,
}

impl ChainLog {
    fn sole_broadcast(&self) -> &TxEnvelope {
        assert_eq!(self.broadcasts.len(), 1, "expected exactly one transaction");
        &self.broadcasts[0]
    }
}

async fn handle_rpc(
    axum::extract::State(log): axum::extract::State<Arc<Mutex<ChainLog>>>,
    Json(body): Json<Value>,
) -> Json<Value> {
    let id = body.get("id").cloned().unwrap_or(json!(1));
    let method = body
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or_default();

    match method {
        "eth_chainId" => rpc_result(&id, json!(format!("0x{CHAIN_ID:x}"))),
        "eth_call" => {
            let data = body
                .get("params")
                .and_then(|p| p.get(0))
                .and_then(|tx| tx.get("input").or_else(|| tx.get("data")))
                .and_then(Value::as_str)
                .unwrap_or("0x");
            let bytes = alloy::hex::decode(data.trim_start_matches("0x")).unwrap_or_default();
            if bytes.get(..4) == Some(&keccak256(b"allowance(address,address)".as_slice())[..4]) {
                let allowance = log.lock().unwrap().erc20_allowance.unwrap_or(U256::MAX);
                rpc_result(
                    &id,
                    json!(format!(
                        "0x{}",
                        alloy::hex::encode(allowance.to_be_bytes::<32>())
                    )),
                )
            } else {
                Json(json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": {"code": -32601, "message": "mock: unhandled eth_call"},
                }))
            }
        }
        "eth_getTransactionCount" => rpc_result(&id, json!("0x0")),
        "eth_gasPrice" | "eth_maxPriorityFeePerGas" => rpc_result(&id, json!("0x1")),
        "eth_estimateGas" => rpc_result(&id, json!("0x100000")),
        "eth_blockNumber" => rpc_result(&id, json!("0x1")),
        "eth_feeHistory" => rpc_result(
            &id,
            json!({
                "oldestBlock": "0x1",
                "baseFeePerGas": ["0x1", "0x1"],
                "gasUsedRatio": [0.5],
                "reward": [["0x1"]],
            }),
        ),
        "eth_sendRawTransaction" => {
            let raw = body
                .get("params")
                .and_then(|p| p.get(0))
                .and_then(Value::as_str)
                .unwrap_or_default();
            let bytes = alloy::hex::decode(raw.trim_start_matches("0x")).expect("raw transaction");
            let envelope =
                TxEnvelope::decode_2718(&mut bytes.as_slice()).expect("decodable transaction");
            let hash = *envelope.tx_hash();
            log.lock().unwrap().broadcasts.push(envelope);
            rpc_result(&id, json!(format!("{hash:#x}")))
        }
        "eth_getTransactionReceipt" => {
            let hash = body
                .get("params")
                .and_then(|p| p.get(0))
                .cloned()
                .unwrap_or(json!(null));
            rpc_result(
                &id,
                json!({
                    "transactionHash": hash,
                    "transactionIndex": "0x0",
                    "blockHash": format!("{:#x}", B256::repeat_byte(0x01)),
                    "blockNumber": "0x1",
                    "from": format!("{:#x}", Address::ZERO),
                    "to": format!("{CLEARING_HOUSE:#x}"),
                    "cumulativeGasUsed": "0x1",
                    "gasUsed": "0x1",
                    "effectiveGasPrice": "0x1",
                    "logs": [],
                    "logsBloom": format!("0x{}", "00".repeat(256)),
                    "status": "0x1",
                    "type": "0x2",
                }),
            )
        }
        other => Json(json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {"code": -32601, "message": format!("mock: unhandled method {other}")},
        })),
    }
}

fn rpc_result(id: &Value, result: Value) -> Json<Value> {
    Json(json!({"jsonrpc": "2.0", "id": id, "result": result}))
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

/// The claim terms core would serve for `participant`. Echoing the participant back is what lets a
/// test see which one the SDK asked about.
fn claim_action(participant: &str, function_name: &str) -> Value {
    json!({
        "contract_address": CLEARING_HOUSE.to_string(),
        "function_name": function_name,
        "action": "claim_net_credit",
        "cycle_id": format!("{CYCLE_ID:#x}"),
        "cycle_id_text": "eth:1800000000",
        "asset_address": TOKEN.to_string(),
        "participant": participant,
        "amount": AMOUNT.to_string(),
        "payable_value": "0",
        "proof": [format!("{:#x}", B256::repeat_byte(0xbb))],
    })
}

/// The debit terms core would serve for `participant`, for a cycle settling in `asset`.
fn pay_action(participant: &str, asset: Address) -> Value {
    let payable = if asset == Address::ZERO { AMOUNT } else { 0 };
    json!({
        "contract_address": CLEARING_HOUSE.to_string(),
        "function_name": "payNetDebit",
        "action": "pay_net_debit",
        "cycle_id": format!("{CYCLE_ID:#x}"),
        "cycle_id_text": "eth:1800000000",
        "asset_address": asset.to_string(),
        "participant": participant,
        "amount": AMOUNT.to_string(),
        "payable_value": payable.to_string(),
        "proof": [format!("{:#x}", B256::repeat_byte(0xbb))],
    })
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

/// A client against a mock chain and a mock core that answers the clearing-action route the way
/// the real one does: `claimNetCreditFor` for whichever participant was asked about.
async fn test_client() -> anyhow::Result<(Client<PrivateKeySigner>, Address, Arc<Mutex<ChainLog>>)>
{
    test_client_responding(PrivateKeySigner::random(), |participant: String| {
        claim_action(&participant, "claimNetCreditFor")
    })
    .await
}

/// What the mock facilitator saw: the bodies POSTed to its clearing route.
type FacilitatorLog = Arc<Mutex<Vec<Value>>>;

/// A stand-in facilitator that records requests to `path` and replies with `response`.
/// Deliberately dumb: the tests assert on what the SDK sends and how it treats the reply, not on
/// facilitator behavior.
async fn spawn_facilitator(
    path: &'static str,
    response: Value,
    log: FacilitatorLog,
) -> anyhow::Result<String> {
    spawn_facilitator_responding(path, move |_| response.clone(), log).await
}

/// Like [`spawn_facilitator`], but choosing the reply per request — what a scheme-routing test
/// needs to refuse EIP-3009 while accepting Permit2.
async fn spawn_facilitator_responding(
    path: &'static str,
    respond: impl Fn(&Value) -> Value + Clone + Send + Sync + 'static,
    log: FacilitatorLog,
) -> anyhow::Result<String> {
    spawn(Router::new().route(
        path,
        post(move |Json(body): Json<Value>| {
            let respond = respond.clone();
            let log = log.clone();
            async move {
                let response = respond(&body);
                log.lock().unwrap().push(body);
                Json(response)
            }
        }),
    ))
    .await
}

/// Like [`test_client`], but with a facilitator answering `/clearing/claim` with `response`.
async fn test_client_with_facilitator(
    response: Value,
) -> anyhow::Result<(
    Client<PrivateKeySigner>,
    Address,
    Arc<Mutex<ChainLog>>,
    FacilitatorLog,
)> {
    let facilitator_log: FacilitatorLog = Arc::new(Mutex::new(Vec::new()));
    let facilitator_url =
        spawn_facilitator("/clearing/claim", response, facilitator_log.clone()).await?;
    let (client, signer_address, chain_log) = test_client_configured(
        PrivateKeySigner::random(),
        |participant: String| claim_action(&participant, "claimNetCreditFor"),
        Some(facilitator_url),
    )
    .await?;
    Ok((client, signer_address, chain_log, facilitator_log))
}

/// A client whose core serves debit terms in `asset` and whose facilitator answers
/// `/clearing/pay` with `response`.
async fn test_client_paying(
    asset: Address,
    response: Value,
) -> anyhow::Result<(
    Client<PrivateKeySigner>,
    Address,
    Arc<Mutex<ChainLog>>,
    FacilitatorLog,
)> {
    let facilitator_log: FacilitatorLog = Arc::new(Mutex::new(Vec::new()));
    let facilitator_url =
        spawn_facilitator("/clearing/pay", response, facilitator_log.clone()).await?;
    let (client, signer_address, chain_log) = test_client_configured(
        PrivateKeySigner::random(),
        move |participant: String| pay_action(&participant, asset),
        Some(facilitator_url),
    )
    .await?;
    Ok((client, signer_address, chain_log, facilitator_log))
}

async fn test_client_responding<F>(
    signer: PrivateKeySigner,
    respond: F,
) -> anyhow::Result<(Client<PrivateKeySigner>, Address, Arc<Mutex<ChainLog>>)>
where
    F: Fn(String) -> Value + Clone + Send + Sync + 'static,
{
    test_client_configured(signer, respond, None).await
}

async fn test_client_configured<F>(
    signer: PrivateKeySigner,
    respond: F,
    facilitator_url: Option<String>,
) -> anyhow::Result<(Client<PrivateKeySigner>, Address, Arc<Mutex<ChainLog>>)>
where
    F: Fn(String) -> Value + Clone + Send + Sync + 'static,
{
    let log = Arc::new(Mutex::new(ChainLog::default()));
    let eth_url = spawn(
        Router::new()
            .route("/", post(handle_rpc))
            .with_state(log.clone()),
    )
    .await?;

    let params = public_params(&eth_url);
    let action_log = log.clone();
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
                "/core/cycles/{cycle_id}/participants/{participant}/clearing-action",
                get(move |Path((_cycle, participant)): Path<(String, String)>| {
                    let log = action_log.clone();
                    let respond = respond.clone();
                    async move {
                        log.lock()
                            .unwrap()
                            .action_requests
                            .push(participant.clone());
                        Json(respond(participant))
                    }
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

    let signer_address = signer.address();
    let mut builder = ConfigBuilder::default()
        .rpc_url(core_url)
        .signer(signer)
        // Skips the auth handshake, which these tests are not about.
        .bearer_token("test-token".into())
        .ethereum_http_rpc_url(eth_url)
        .contract_address(CONTRACT.to_string());
    if let Some(url) = facilitator_url {
        builder = builder.facilitator_url(url);
    }
    let client = Client::new(builder.build()?).await?;

    Ok((client, signer_address, log))
}

/// The creditor a sponsored claim pays, decoded through the SDK's own binding so the test cannot
/// drift from the ABI.
fn claimed_creditor(input: &[u8]) -> Address {
    claimNetCreditForCall::abi_decode(input)
        .expect("expected the sponsored entrypoint")
        .creditor
}

#[tokio::test]
async fn a_sponsored_claim_names_the_creditor_not_the_signer() -> anyhow::Result<()> {
    let (client, signer, log) = test_client().await?;

    client
        .settlement
        .claim_net_credit_for(CYCLE_ID.to_string(), CREDITOR)
        .await?;

    let log = log.lock().unwrap();
    assert_eq!(
        log.action_requests,
        vec![CREDITOR.to_string()],
        "the claim terms must be fetched for the creditor, not the submitter"
    );

    let sent = log.sole_broadcast();
    assert_eq!(sent.to(), Some(CLEARING_HOUSE));
    assert_eq!(claimed_creditor(sent.input()), CREDITOR);
    assert_ne!(
        claimed_creditor(sent.input()),
        signer,
        "a sponsored claim must not pay the submitter"
    );
    // No value either: the payout comes from the cycle's funded pool, so a submitter that
    // attached ETH would just be handing it over.
    assert_eq!(sent.value(), U256::ZERO);
    Ok(())
}

/// A self-claim is just `claimNetCreditFor` naming the signer — there is no separate entrypoint.
#[tokio::test]
async fn a_self_claim_names_the_signer() -> anyhow::Result<()> {
    let (client, signer, log) = test_client().await?;

    client
        .settlement
        .claim_net_credit(CYCLE_ID.to_string())
        .await?;

    let log = log.lock().unwrap();
    assert_eq!(log.action_requests, vec![signer.to_string()]);
    let sent = log.sole_broadcast();
    assert_eq!(sent.to(), Some(CLEARING_HOUSE));
    let call = claimNetCreditForCall::abi_decode(sent.input()).expect("expected claimNetCreditFor");
    assert_eq!(call.creditor, signer);
    assert_eq!(call.cycleId, CYCLE_ID);
    assert_eq!(call.netCredit, U256::from(AMOUNT));
    Ok(())
}

fn facilitator_success(creditor: Address) -> Value {
    json!({
        "success": true,
        "txHash": format!("{:#x}", B256::repeat_byte(0xcc)),
        "network": "eip155:1337",
        "creditor": format!("{creditor:#x}"),
        "cycleId": format!("{CYCLE_ID:#x}"),
        "amount": AMOUNT.to_string(),
    })
}

fn facilitator_refusal(code: &str) -> Value {
    json!({
        "success": false,
        "error": "refused for the test",
        "errorCode": code,
        "retryable": false,
    })
}

/// With a facilitator configured, the claim is one POST naming the cycle and the creditor — the
/// SDK signs nothing, broadcasts nothing, and the receipt reports the sponsored path.
#[tokio::test]
async fn a_gasless_claim_goes_through_the_facilitator() -> anyhow::Result<()> {
    let (client, _signer, chain_log, facilitator_log) =
        test_client_with_facilitator(facilitator_success(CREDITOR)).await?;

    let receipt = client
        .settlement
        .claim_net_credit_for(CYCLE_ID.to_string(), CREDITOR)
        .await?;

    assert_eq!(receipt.path, ClaimPath::Sponsored);
    assert_eq!(receipt.creditor, CREDITOR);
    assert!(
        chain_log.lock().unwrap().broadcasts.is_empty(),
        "a sponsored claim must not touch the chain from here"
    );

    let sent = facilitator_log.lock().unwrap();
    assert_eq!(sent.len(), 1, "expected exactly one facilitator request");
    assert_eq!(sent[0]["cycleId"], format!("{CYCLE_ID:#x}"));
    let named: Address = sent[0]["creditor"].as_str().unwrap_or_default().parse()?;
    assert_eq!(named, CREDITOR);
    Ok(())
}

/// A facilitator that echoes a different creditor is describing a transaction that paid someone
/// else; the receipt must refuse to describe it as ours.
#[tokio::test]
async fn a_receipt_for_another_creditor_is_refused() -> anyhow::Result<()> {
    let stranger = address!("00000000000000000000000000000000000005ad");
    let (client, _signer, _chain_log, _facilitator_log) =
        test_client_with_facilitator(facilitator_success(stranger)).await?;

    let err = client
        .settlement
        .claim_net_credit_gasless_for(CYCLE_ID.to_string(), CREDITOR)
        .await
        .expect_err("a mis-echoed creditor must be refused");

    assert!(
        matches!(
            err,
            ClearingSettlementError::Sponsorship(SponsorshipError::OutcomeUnknown(_))
        ),
        "unexpected error: {err}"
    );
    Ok(())
}

/// A refusal that names the claim itself would revert the caller's own transaction too, so the
/// auto-routing entrypoint reports it rather than paying gas to rediscover it.
#[tokio::test]
async fn a_refusal_naming_the_claim_does_not_fall_back() -> anyhow::Result<()> {
    let (client, _signer, chain_log, _facilitator_log) =
        test_client_with_facilitator(facilitator_refusal("SIMULATION_REVERTED")).await?;

    let err = client
        .settlement
        .claim_net_credit_for(CYCLE_ID.to_string(), CREDITOR)
        .await
        .expect_err("a claim-naming refusal must surface");

    assert!(
        matches!(
            &err,
            ClearingSettlementError::Sponsorship(SponsorshipError::Rejected { code, .. })
                if code == "SIMULATION_REVERTED"
        ),
        "unexpected error: {err}"
    );
    assert!(
        chain_log.lock().unwrap().broadcasts.is_empty(),
        "nothing may be broadcast when the refusal names the claim"
    );
    Ok(())
}

/// A facilitator that will not pay — throttled, drained, unconfigured for the network — is no
/// reason the claim cannot happen; the caller's own transaction goes out instead.
#[tokio::test]
async fn an_unwilling_facilitator_falls_back_to_self_funding() -> anyhow::Result<()> {
    let (client, _signer, chain_log, facilitator_log) =
        test_client_with_facilitator(facilitator_refusal("RATE_LIMITED")).await?;

    let receipt = client
        .settlement
        .claim_net_credit_for(CYCLE_ID.to_string(), CREDITOR)
        .await?;

    assert_eq!(receipt.path, ClaimPath::SelfFunded);
    assert_eq!(
        facilitator_log.lock().unwrap().len(),
        1,
        "the facilitator must have been asked first"
    );
    let log = chain_log.lock().unwrap();
    let sent = log.sole_broadcast();
    assert_eq!(sent.to(), Some(CLEARING_HOUSE));
    assert_eq!(claimed_creditor(sent.input()), CREDITOR);
    Ok(())
}

/// The SDK reconciles the echoed participant before signing, so a proof served for someone else
/// fails locally with the mismatch named instead of as an on-chain revert after gas is spent.
#[tokio::test]
async fn a_claim_with_a_mismatched_participant_never_reaches_the_chain() -> anyhow::Result<()> {
    let stranger = address!("00000000000000000000000000000000000005ad");
    let (client, _signer, log) = test_client_responding(PrivateKeySigner::random(), move |_| {
        claim_action(&stranger.to_string(), "claimNetCreditFor")
    })
    .await?;

    let err = client
        .settlement
        .claim_net_credit_for(CYCLE_ID.to_string(), CREDITOR)
        .await
        .expect_err("a proof for another participant must be rejected");

    assert!(
        matches!(err, ClearingSettlementError::InvalidParams(_)),
        "unexpected error: {err}"
    );
    assert!(
        log.lock().unwrap().broadcasts.is_empty(),
        "nothing may be broadcast on a mismatch"
    );
    Ok(())
}

fn facilitator_pay_success(debtor: Address) -> Value {
    json!({
        "success": true,
        "txHash": format!("{:#x}", B256::repeat_byte(0xdd)),
        "network": "eip155:1337",
        "debtor": format!("{debtor:#x}"),
        "cycleId": format!("{CYCLE_ID:#x}"),
        "amount": AMOUNT.to_string(),
    })
}

/// The token's `ReceiveWithAuthorization` digest, recomputed from the literal type string so a
/// drift in the SDK's digest code fails the recovery assertion instead of cancelling out.
fn expected_erc3009_digest(
    from: Address,
    to: Address,
    value: U256,
    valid_before: U256,
    nonce: B256,
) -> B256 {
    let type_hash = keccak256(
        b"ReceiveWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"
            .as_slice(),
    );
    let mut encoded = Vec::with_capacity(32 * 7);
    encoded.extend_from_slice(type_hash.as_slice());
    encoded.extend_from_slice(B256::left_padding_from(from.as_slice()).as_slice());
    encoded.extend_from_slice(B256::left_padding_from(to.as_slice()).as_slice());
    encoded.extend_from_slice(&value.to_be_bytes::<32>());
    encoded.extend_from_slice(&U256::ZERO.to_be_bytes::<32>());
    encoded.extend_from_slice(&valid_before.to_be_bytes::<32>());
    encoded.extend_from_slice(nonce.as_slice());
    let struct_hash = keccak256(encoded);

    let mut preimage = Vec::with_capacity(2 + 64);
    preimage.extend_from_slice(b"\x19\x01");
    preimage.extend_from_slice(TOKEN_DOMAIN.as_slice());
    preimage.extend_from_slice(struct_hash.as_slice());
    keccak256(preimage)
}

/// A sponsored payment is one POST carrying the debtor's EIP-3009 authorization, bound to the
/// ClearingHouse as receiver, the leaf's exact amount, and the cycle id as nonce — nothing an
/// intercepting submitter could repoint at another receiver, amount, or cycle.
#[tokio::test]
async fn a_gasless_payment_signs_the_cycle_terms_for_the_clearing_house() -> anyhow::Result<()> {
    let (client, signer, chain_log, facilitator_log) = {
        // The response echoes the debtor, which is only known once the client exists — so build
        // the client first with a placeholder-free flow: spawn, then read the signer.
        let facilitator_log: FacilitatorLog = Arc::new(Mutex::new(Vec::new()));
        let signer = PrivateKeySigner::random();
        let facilitator_url = spawn_facilitator(
            "/clearing/pay",
            facilitator_pay_success(signer.address()),
            facilitator_log.clone(),
        )
        .await?;
        let (client, signer_address, chain_log) = test_client_configured(
            signer,
            |participant: String| pay_action(&participant, TOKEN),
            Some(facilitator_url),
        )
        .await?;
        (client, signer_address, chain_log, facilitator_log)
    };

    let receipt = client
        .settlement
        .pay_net_debit(CYCLE_ID.to_string())
        .await?;

    assert_eq!(receipt.path, PayPath::Sponsored);
    assert_eq!(receipt.debtor, signer);
    assert!(
        chain_log.lock().unwrap().broadcasts.is_empty(),
        "a sponsored payment must not touch the chain from here"
    );

    let sent = facilitator_log.lock().unwrap();
    assert_eq!(sent.len(), 1, "expected exactly one facilitator request");
    assert_eq!(sent[0]["cycleId"], format!("{CYCLE_ID:#x}"));
    assert_eq!(sent[0]["assetTransferMethod"], "eip3009");

    let auth = &sent[0]["authorization"];
    let from: Address = auth["from"].as_str().unwrap_or_default().parse()?;
    assert_eq!(from, signer, "the authorization must bind the signer");
    let nonce: B256 = auth["nonce"].as_str().unwrap_or_default().parse()?;
    assert_eq!(nonce, CYCLE_ID, "the nonce must pin the cycle");

    let valid_before = U256::from_str(auth["validBefore"].as_str().unwrap_or_default())?;
    let digest = expected_erc3009_digest(
        from,
        CLEARING_HOUSE,
        U256::from(AMOUNT),
        valid_before,
        nonce,
    );
    let r: B256 = auth["r"].as_str().unwrap_or_default().parse()?;
    let s: B256 = auth["s"].as_str().unwrap_or_default().parse()?;
    let v = auth["v"].as_u64().unwrap_or_default();
    let recovered =
        Signature::from_scalars_and_parity(r, s, v == 28).recover_address_from_prehash(&digest)?;
    assert_eq!(
        recovered, signer,
        "signature must recover to the signer over a digest binding the ClearingHouse, the leaf \
         amount, and the cycle id"
    );
    Ok(())
}

/// Permit2's `PermitTransferFrom` digest, recomputed from the literal type strings — domain
/// included, since Permit2's domain is derived (canonical singleton address, no version) rather
/// than fetched — so a drift in the SDK's digest code fails the recovery assertion instead of
/// cancelling out.
fn expected_permit2_digest(
    token: Address,
    amount: U256,
    spender: Address,
    nonce: U256,
    deadline: U256,
) -> B256 {
    let domain_typehash = keccak256(
        b"EIP712Domain(string name,uint256 chainId,address verifyingContract)".as_slice(),
    );
    let mut encoded = Vec::with_capacity(32 * 4);
    encoded.extend_from_slice(domain_typehash.as_slice());
    encoded.extend_from_slice(keccak256(b"Permit2".as_slice()).as_slice());
    encoded.extend_from_slice(&U256::from(CHAIN_ID).to_be_bytes::<32>());
    encoded.extend_from_slice(
        B256::left_padding_from(sdk_4mica::contract::PERMIT2_ADDRESS.as_slice()).as_slice(),
    );
    let domain = keccak256(encoded);

    let permissions_typehash =
        keccak256(b"TokenPermissions(address token,uint256 amount)".as_slice());
    let mut encoded = Vec::with_capacity(32 * 3);
    encoded.extend_from_slice(permissions_typehash.as_slice());
    encoded.extend_from_slice(B256::left_padding_from(token.as_slice()).as_slice());
    encoded.extend_from_slice(&amount.to_be_bytes::<32>());
    let token_permissions = keccak256(encoded);

    let permit_typehash = keccak256(
        b"PermitTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline)TokenPermissions(address token,uint256 amount)"
            .as_slice(),
    );
    let mut encoded = Vec::with_capacity(32 * 5);
    encoded.extend_from_slice(permit_typehash.as_slice());
    encoded.extend_from_slice(token_permissions.as_slice());
    encoded.extend_from_slice(B256::left_padding_from(spender.as_slice()).as_slice());
    encoded.extend_from_slice(&nonce.to_be_bytes::<32>());
    encoded.extend_from_slice(&deadline.to_be_bytes::<32>());
    let struct_hash = keccak256(encoded);

    let mut preimage = Vec::with_capacity(2 + 64);
    preimage.extend_from_slice(b"\x19\x01");
    preimage.extend_from_slice(domain.as_slice());
    preimage.extend_from_slice(struct_hash.as_slice());
    keccak256(preimage)
}

/// A token that cannot redeem an EIP-3009 authorization reverts the facilitator's simulation; the
/// SDK then retries over Permit2 with the same cycle terms — the ClearingHouse as spender, the
/// leaf's exact amount, and the cycle id as nonce.
#[tokio::test]
async fn a_token_that_cannot_redeem_eip3009_is_paid_over_permit2() -> anyhow::Result<()> {
    let facilitator_log: FacilitatorLog = Arc::new(Mutex::new(Vec::new()));
    let signer = PrivateKeySigner::random();
    let debtor = signer.address();
    let facilitator_url = spawn_facilitator_responding(
        "/clearing/pay",
        move |body| {
            if body["assetTransferMethod"] == "permit2" {
                facilitator_pay_success(debtor)
            } else {
                facilitator_refusal("SIMULATION_REVERTED")
            }
        },
        facilitator_log.clone(),
    )
    .await?;
    let (client, signer_address, chain_log) = test_client_configured(
        signer,
        |participant: String| pay_action(&participant, TOKEN),
        Some(facilitator_url),
    )
    .await?;

    let receipt = client
        .settlement
        .pay_net_debit(CYCLE_ID.to_string())
        .await?;

    assert_eq!(receipt.path, PayPath::Sponsored);
    assert_eq!(receipt.debtor, signer_address);
    assert!(
        chain_log.lock().unwrap().broadcasts.is_empty(),
        "a sponsored payment must not touch the chain from here"
    );

    let sent = facilitator_log.lock().unwrap();
    assert_eq!(sent.len(), 2, "EIP-3009 must be tried before Permit2");
    assert_eq!(sent[0]["assetTransferMethod"], "eip3009");
    assert_eq!(sent[1]["assetTransferMethod"], "permit2");
    assert_eq!(sent[1]["cycleId"], format!("{CYCLE_ID:#x}"));

    let auth = &sent[1]["permit2Authorization"];
    let from: Address = auth["from"].as_str().unwrap_or_default().parse()?;
    assert_eq!(
        from, signer_address,
        "the authorization must bind the signer"
    );
    let nonce = U256::from_str(auth["nonce"].as_str().unwrap_or_default())?;
    assert_eq!(
        nonce,
        U256::from_be_bytes(CYCLE_ID.0),
        "the nonce must pin the cycle"
    );

    let deadline = U256::from_str(auth["deadline"].as_str().unwrap_or_default())?;
    let digest =
        expected_permit2_digest(TOKEN, U256::from(AMOUNT), CLEARING_HOUSE, nonce, deadline);
    let signature = alloy::hex::decode(
        auth["signature"]
            .as_str()
            .unwrap_or_default()
            .trim_start_matches("0x"),
    )?;
    assert_eq!(signature.len(), 65, "expected a packed 65-byte signature");
    let r = B256::from_slice(&signature[0..32]);
    let s = B256::from_slice(&signature[32..64]);
    let recovered = Signature::from_scalars_and_parity(r, s, signature[64] == 28)
        .recover_address_from_prehash(&digest)?;
    assert_eq!(
        recovered, signer_address,
        "signature must recover to the signer over a digest binding the ClearingHouse as \
         spender, the leaf amount, and the cycle id"
    );
    Ok(())
}

/// A `PERMIT2_ALLOWANCE_REQUIRED` rejection, carrying the owner's EIP-2612 nonce when the token
/// has a permit surface.
fn facilitator_allowance_refusal(eip2612_nonce: Option<&str>) -> Value {
    let mut refusal = json!({
        "success": false,
        "error": "approve(PERMIT2) missing",
        "errorCode": "PERMIT2_ALLOWANCE_REQUIRED",
        "retryable": false,
    });
    if let Some(nonce) = eip2612_nonce {
        refusal["permit2Allowance"] = json!({ "eip2612Nonce": nonce });
    }
    refusal
}

/// The token's EIP-2612 `Permit` digest, recomputed from the literal type string. The spender is
/// always the canonical Permit2 — the permit grants Permit2 its allowance, nothing else.
fn expected_permit_digest(owner: Address, value: U256, nonce: U256, deadline: U256) -> B256 {
    let type_hash = keccak256(
        b"Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"
            .as_slice(),
    );
    let mut encoded = Vec::with_capacity(32 * 6);
    encoded.extend_from_slice(type_hash.as_slice());
    encoded.extend_from_slice(B256::left_padding_from(owner.as_slice()).as_slice());
    encoded.extend_from_slice(
        B256::left_padding_from(sdk_4mica::contract::PERMIT2_ADDRESS.as_slice()).as_slice(),
    );
    encoded.extend_from_slice(&value.to_be_bytes::<32>());
    encoded.extend_from_slice(&nonce.to_be_bytes::<32>());
    encoded.extend_from_slice(&deadline.to_be_bytes::<32>());
    let struct_hash = keccak256(encoded);

    let mut preimage = Vec::with_capacity(2 + 64);
    preimage.extend_from_slice(b"\x19\x01");
    preimage.extend_from_slice(TOKEN_DOMAIN.as_slice());
    preimage.extend_from_slice(struct_hash.as_slice());
    keccak256(preimage)
}

/// A missing Permit2 allowance is recovered from by *signing* the approval: the rejection carries
/// the owner's EIP-2612 nonce, the SDK signs a permit over it, and the retry bundles both — the
/// debtor still never transacts.
#[tokio::test]
async fn a_missing_allowance_is_signed_for_and_retried() -> anyhow::Result<()> {
    let facilitator_log: FacilitatorLog = Arc::new(Mutex::new(Vec::new()));
    let signer = PrivateKeySigner::random();
    let debtor = signer.address();
    let facilitator_url = spawn_facilitator_responding(
        "/clearing/pay",
        move |body| {
            if body["assetTransferMethod"] == "eip3009" {
                facilitator_refusal("SIMULATION_REVERTED")
            } else if body.get("eip2612Permit").is_some() {
                facilitator_pay_success(debtor)
            } else {
                facilitator_allowance_refusal(Some("7"))
            }
        },
        facilitator_log.clone(),
    )
    .await?;
    let (client, signer_address, chain_log) = test_client_configured(
        signer,
        |participant: String| pay_action(&participant, TOKEN),
        Some(facilitator_url),
    )
    .await?;

    let receipt = client
        .settlement
        .pay_net_debit(CYCLE_ID.to_string())
        .await?;

    assert_eq!(receipt.path, PayPath::Sponsored);
    assert!(
        chain_log.lock().unwrap().broadcasts.is_empty(),
        "still chain-free: the nonce came over HTTP, not from an eth_call"
    );

    let sent = facilitator_log.lock().unwrap();
    assert_eq!(
        sent.len(),
        3,
        "eip3009, plain permit2, then permit2 with the permit"
    );
    // The first Permit2 attempt carries no permit — sponsoring an approval the debtor may
    // already have made would waste the facilitator's gas.
    assert!(sent[1].get("eip2612Permit").is_none());

    let permit = &sent[2]["eip2612Permit"];
    assert!(permit.is_object(), "retry must carry a permit: {permit}");
    let value = U256::from_str(permit["value"].as_str().unwrap_or_default())?;
    assert_eq!(
        value,
        U256::MAX,
        "the allowance only lets Permit2 act, so it is unlimited"
    );
    let deadline = U256::from_str(permit["deadline"].as_str().unwrap_or_default())?;
    let v = permit["v"].as_u64().unwrap_or_default();
    let r: B256 = permit["r"].as_str().unwrap_or_default().parse()?;
    let s: B256 = permit["s"].as_str().unwrap_or_default().parse()?;

    // Nonce 7 is what the rejection advertised; a permit signed over any other nonce would be
    // rejected by the token as replayed.
    let digest = expected_permit_digest(signer_address, value, U256::from(7u64), deadline);
    let recovered =
        Signature::from_scalars_and_parity(r, s, v == 28).recover_address_from_prehash(&digest)?;
    assert_eq!(
        recovered, signer_address,
        "permit must recover to the signer over the token's Permit digest"
    );
    Ok(())
}

/// Without an EIP-2612 nonce the approval cannot be signed, so gaslessness is off the table — the
/// composite pays the debit with the caller's own transaction instead of surfacing a dead end.
#[tokio::test]
async fn an_unsponsorable_allowance_falls_back_to_a_self_funded_payment() -> anyhow::Result<()> {
    let facilitator_log: FacilitatorLog = Arc::new(Mutex::new(Vec::new()));
    let facilitator_url = spawn_facilitator_responding(
        "/clearing/pay",
        move |body| {
            if body["assetTransferMethod"] == "eip3009" {
                facilitator_refusal("SIMULATION_REVERTED")
            } else {
                facilitator_allowance_refusal(None)
            }
        },
        facilitator_log.clone(),
    )
    .await?;
    let (client, signer_address, chain_log) = test_client_configured(
        PrivateKeySigner::random(),
        |participant: String| pay_action(&participant, TOKEN),
        Some(facilitator_url),
    )
    .await?;

    let receipt = client
        .settlement
        .pay_net_debit(CYCLE_ID.to_string())
        .await?;

    assert_eq!(receipt.path, PayPath::SelfFunded);
    assert_eq!(receipt.debtor, signer_address);
    assert_eq!(
        facilitator_log.lock().unwrap().len(),
        2,
        "no permit retry without a nonce to sign"
    );
    let log = chain_log.lock().unwrap();
    let sent = log.sole_broadcast();
    let call = payNetDebitCall::abi_decode(sent.input()).expect("expected payNetDebit");
    assert_eq!(call.netDebit, U256::from(AMOUNT));
    Ok(())
}

/// Pinned to the sponsored route, a token with no EIP-2612 surface is a dead end reported as
/// such — never a silent self-funded transaction.
#[tokio::test]
async fn sponsored_permit2_gives_up_when_the_token_has_no_permit() -> anyhow::Result<()> {
    let facilitator_log: FacilitatorLog = Arc::new(Mutex::new(Vec::new()));
    let facilitator_url = spawn_facilitator_responding(
        "/clearing/pay",
        move |_| facilitator_allowance_refusal(None),
        facilitator_log.clone(),
    )
    .await?;
    let (client, _signer, chain_log) = test_client_configured(
        PrivateKeySigner::random(),
        |participant: String| pay_action(&participant, TOKEN),
        Some(facilitator_url),
    )
    .await?;

    let err = client
        .settlement
        .pay_net_debit_sponsored_permit2(CYCLE_ID.to_string())
        .await
        .expect_err("an unsponsorable approval must be reported");

    assert!(
        matches!(
            err,
            ClearingSettlementError::Permit2AllowanceRequired {
                eip2612_nonce: None,
                ..
            }
        ),
        "unexpected error: {err}"
    );
    assert!(
        chain_log.lock().unwrap().broadcasts.is_empty(),
        "the pinned route must not transact"
    );
    Ok(())
}

/// The self-funded fallback needs an ERC-20 allowance the gasless routes never did. Without one
/// the fallback is refused with the fix named, rather than broadcast to revert opaquely inside
/// the token.
#[tokio::test]
async fn a_fallback_without_an_erc20_allowance_is_refused_not_broadcast() -> anyhow::Result<()> {
    let (client, _signer, chain_log, facilitator_log) =
        test_client_paying(TOKEN, facilitator_refusal("RATE_LIMITED")).await?;
    chain_log.lock().unwrap().erc20_allowance = Some(U256::ZERO);

    let err = client
        .settlement
        .pay_net_debit(CYCLE_ID.to_string())
        .await
        .expect_err("a fallback without an allowance must be refused");

    assert!(
        matches!(
            err,
            ClearingSettlementError::Erc20AllowanceRequired { needed, .. }
                if needed == U256::from(AMOUNT)
        ),
        "unexpected error: {err}"
    );
    assert_eq!(
        facilitator_log.lock().unwrap().len(),
        1,
        "the facilitator must have been asked first"
    );
    assert!(
        chain_log.lock().unwrap().broadcasts.is_empty(),
        "nothing may be broadcast without the allowance"
    );
    Ok(())
}

/// A token core publishes no EIP-712 domain separator for. EIP-3009 cannot even be signed for
/// it, but that closes one scheme, not the route.
const UNLISTED_TOKEN: Address = address!("000000000000000000000000000000000000ee75");

/// With no published domain separator the EIP-3009 digest cannot be built — but Permit2's domain
/// derives from the chain id, so the payment still goes out gaslessly, without a wasted EIP-3009
/// request.
#[tokio::test]
async fn a_token_with_no_published_domain_is_paid_over_permit2() -> anyhow::Result<()> {
    let facilitator_log: FacilitatorLog = Arc::new(Mutex::new(Vec::new()));
    let signer = PrivateKeySigner::random();
    let debtor = signer.address();
    let facilitator_url = spawn_facilitator(
        "/clearing/pay",
        facilitator_pay_success(debtor),
        facilitator_log.clone(),
    )
    .await?;
    let (client, signer_address, chain_log) = test_client_configured(
        signer,
        |participant: String| pay_action(&participant, UNLISTED_TOKEN),
        Some(facilitator_url),
    )
    .await?;

    let receipt = client
        .settlement
        .pay_net_debit(CYCLE_ID.to_string())
        .await?;

    assert_eq!(receipt.path, PayPath::Sponsored);
    assert_eq!(receipt.debtor, signer_address);
    assert!(chain_log.lock().unwrap().broadcasts.is_empty());

    let sent = facilitator_log.lock().unwrap();
    assert_eq!(
        sent.len(),
        1,
        "an unsignable EIP-3009 authorization must not reach the facilitator"
    );
    assert_eq!(sent[0]["assetTransferMethod"], "permit2");
    Ok(())
}

/// With no domain separator the EIP-2612 permit cannot be signed either, so a missing allowance
/// leaves no gasless route at all — the composite pays self-funded instead of surfacing the
/// dead end.
#[tokio::test]
async fn a_missing_allowance_without_a_token_domain_falls_back_to_self_funding()
-> anyhow::Result<()> {
    let (client, signer_address, chain_log, facilitator_log) = {
        let facilitator_log: FacilitatorLog = Arc::new(Mutex::new(Vec::new()));
        let facilitator_url = spawn_facilitator(
            "/clearing/pay",
            facilitator_allowance_refusal(Some("7")),
            facilitator_log.clone(),
        )
        .await?;
        let (client, signer_address, chain_log) = test_client_configured(
            PrivateKeySigner::random(),
            |participant: String| pay_action(&participant, UNLISTED_TOKEN),
            Some(facilitator_url),
        )
        .await?;
        (client, signer_address, chain_log, facilitator_log)
    };

    let receipt = client
        .settlement
        .pay_net_debit(CYCLE_ID.to_string())
        .await?;

    assert_eq!(receipt.path, PayPath::SelfFunded);
    assert_eq!(receipt.debtor, signer_address);
    assert_eq!(
        facilitator_log.lock().unwrap().len(),
        1,
        "only the plain permit2 attempt can be made"
    );
    let log = chain_log.lock().unwrap();
    let sent = log.sole_broadcast();
    let call = payNetDebitCall::abi_decode(sent.input()).expect("expected payNetDebit");
    assert_eq!(call.netDebit, U256::from(AMOUNT));
    Ok(())
}

/// When Permit2 fails too, the payment is genuinely bad — the refusal surfaces rather than being
/// papered over by a self-funded transaction that would revert for the same reason.
#[tokio::test]
async fn a_payment_refused_over_both_schemes_surfaces_without_fallback() -> anyhow::Result<()> {
    let (client, _signer, chain_log, facilitator_log) =
        test_client_paying(TOKEN, facilitator_refusal("SIMULATION_REVERTED")).await?;

    let err = client
        .settlement
        .pay_net_debit(CYCLE_ID.to_string())
        .await
        .expect_err("a payment refused over both schemes must surface");

    assert!(
        matches!(
            &err,
            ClearingSettlementError::Sponsorship(SponsorshipError::Rejected { code, .. })
                if code == "SIMULATION_REVERTED"
        ),
        "unexpected error: {err}"
    );
    assert_eq!(
        facilitator_log.lock().unwrap().len(),
        2,
        "both schemes must have been offered"
    );
    assert!(
        chain_log.lock().unwrap().broadcasts.is_empty(),
        "nothing may be broadcast when the refusal names the payment"
    );
    Ok(())
}

/// A refusal that names the payment — a bad signature, a stale window, an insufficient balance —
/// must surface rather than be papered over by a self-funded transaction.
#[tokio::test]
async fn a_refusal_naming_the_payment_does_not_fall_back() -> anyhow::Result<()> {
    let (client, _signer, chain_log, _facilitator_log) =
        test_client_paying(TOKEN, facilitator_refusal("SIGNATURE_MISMATCH")).await?;

    let err = client
        .settlement
        .pay_net_debit(CYCLE_ID.to_string())
        .await
        .expect_err("a payment-naming refusal must surface");

    assert!(
        matches!(
            &err,
            ClearingSettlementError::Sponsorship(SponsorshipError::Rejected { code, .. })
                if code == "SIGNATURE_MISMATCH"
        ),
        "unexpected error: {err}"
    );
    assert!(
        chain_log.lock().unwrap().broadcasts.is_empty(),
        "nothing may be broadcast when the refusal names the payment"
    );
    Ok(())
}

/// A facilitator that will not pay is no reason the debt cannot be settled; the caller's own
/// transaction goes out instead.
#[tokio::test]
async fn an_unwilling_facilitator_falls_back_to_a_self_funded_payment() -> anyhow::Result<()> {
    let (client, signer, chain_log, facilitator_log) =
        test_client_paying(TOKEN, facilitator_refusal("RATE_LIMITED")).await?;

    let receipt = client
        .settlement
        .pay_net_debit(CYCLE_ID.to_string())
        .await?;

    assert_eq!(receipt.path, PayPath::SelfFunded);
    assert_eq!(receipt.debtor, signer);
    assert_eq!(
        facilitator_log.lock().unwrap().len(),
        1,
        "the facilitator must have been asked first"
    );
    let log = chain_log.lock().unwrap();
    let sent = log.sole_broadcast();
    assert_eq!(sent.to(), Some(CLEARING_HOUSE));
    let call = payNetDebitCall::abi_decode(sent.input()).expect("expected payNetDebit");
    assert_eq!(call.cycleId, CYCLE_ID);
    assert_eq!(call.netDebit, U256::from(AMOUNT));
    Ok(())
}

/// A native-asset debit cannot be pulled by signature, so the facilitator is never asked and the
/// caller's own transaction carries the value.
#[tokio::test]
async fn a_native_cycle_goes_straight_to_self_funding() -> anyhow::Result<()> {
    let (client, _signer, chain_log, facilitator_log) =
        test_client_paying(Address::ZERO, facilitator_pay_success(Address::ZERO)).await?;

    let receipt = client
        .settlement
        .pay_net_debit(CYCLE_ID.to_string())
        .await?;

    assert_eq!(receipt.path, PayPath::SelfFunded);
    assert!(
        facilitator_log.lock().unwrap().is_empty(),
        "a native debit must not be offered to the facilitator"
    );
    let log = chain_log.lock().unwrap();
    let sent = log.sole_broadcast();
    assert_eq!(sent.value(), U256::from(AMOUNT), "the debit rides as value");
    Ok(())
}

/// A facilitator that echoes a different debtor is describing a transaction that pulled someone
/// else's funds; the receipt must refuse to describe it as ours.
#[tokio::test]
async fn a_payment_receipt_for_another_debtor_is_refused() -> anyhow::Result<()> {
    let stranger = address!("00000000000000000000000000000000000005ad");
    let (client, _signer, _chain_log, _facilitator_log) =
        test_client_paying(TOKEN, facilitator_pay_success(stranger)).await?;

    let err = client
        .settlement
        .pay_net_debit_gasless(CYCLE_ID.to_string())
        .await
        .expect_err("a mis-echoed debtor must be refused");

    assert!(
        matches!(
            err,
            ClearingSettlementError::Sponsorship(SponsorshipError::OutcomeUnknown(_))
        ),
        "unexpected error: {err}"
    );
    Ok(())
}

/// The SDK reconciles the echoed participant before signing anything, so debit terms served for
/// someone else fail locally instead of producing an authorization at all.
#[tokio::test]
async fn a_payment_with_a_mismatched_participant_signs_nothing() -> anyhow::Result<()> {
    let stranger = address!("00000000000000000000000000000000000005ad");
    let (client, _signer, chain_log, facilitator_log) = {
        let facilitator_log: FacilitatorLog = Arc::new(Mutex::new(Vec::new()));
        let facilitator_url = spawn_facilitator(
            "/clearing/pay",
            facilitator_pay_success(stranger),
            facilitator_log.clone(),
        )
        .await?;
        let (client, signer_address, chain_log) = test_client_configured(
            PrivateKeySigner::random(),
            move |_| pay_action(&stranger.to_string(), TOKEN),
            Some(facilitator_url),
        )
        .await?;
        (client, signer_address, chain_log, facilitator_log)
    };

    let err = client
        .settlement
        .pay_net_debit(CYCLE_ID.to_string())
        .await
        .expect_err("terms for another participant must be rejected");

    assert!(
        matches!(err, ClearingSettlementError::InvalidParams(_)),
        "unexpected error: {err}"
    );
    assert!(
        facilitator_log.lock().unwrap().is_empty(),
        "no authorization may be sent on a mismatch"
    );
    assert!(
        chain_log.lock().unwrap().broadcasts.is_empty(),
        "nothing may be broadcast on a mismatch"
    );
    Ok(())
}
