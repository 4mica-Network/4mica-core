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
//! debtor's wallet, so what travels to the facilitator is an EIP-3009 authorization whose
//! bindings — the ClearingHouse as receiver, the leaf's exact amount, the cycle id as nonce —
//! these tests pin byte-for-byte by recomputing the digest from literal type strings.

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
    spawn(Router::new().route(
        path,
        post(move |Json(body): Json<Value>| {
            let response = response.clone();
            let log = log.clone();
            async move {
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
