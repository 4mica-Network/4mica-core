//! Tests for claiming a net credit on someone else's behalf.
//!
//! `claimNetCreditFor` pays the address the committed Merkle leaf names, so a submitter can neither
//! redirect the payout nor inflate it — which is what makes it sponsorable. The contract enforces
//! that (see `contracts/test/ClearingHouse.t.sol`); what these cover is the *SDK* half, where the
//! failure mode is quieter: sending the signer's own address where the caller named someone else,
//! which on-chain just reverts as an unprovable claim.

use alloy::consensus::{Transaction, TxEnvelope};
use alloy::eips::eip2718::Decodable2718;
use alloy::primitives::{Address, B256, U256, address, keccak256};
use alloy::signers::local::PrivateKeySigner;
use axum::{Json, Router, extract::Path, routing::get, routing::post};
use crypto::bls::KeyMaterial;
use rpc::{CorePublicParameters, GUARANTEE_CLAIMS_VERSION, GuaranteeVersionDomain};
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
const BLS_SECRET: &str = "0x4573DBD225C8E065FC30FF774C9EF81BD29D34E559D80E2276EE7824812399D3";

fn selector(signature: &str) -> [u8; 4] {
    let hash = keccak256(signature.as_bytes());
    [hash[0], hash[1], hash[2], hash[3]]
}

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
fn claim_action(participant: &str) -> Value {
    json!({
        "contract_address": CLEARING_HOUSE.to_string(),
        "function_name": "claimNetCredit",
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

async fn test_client() -> anyhow::Result<(Client<PrivateKeySigner>, Address, Arc<Mutex<ChainLog>>)>
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
                    async move {
                        log.lock()
                            .unwrap()
                            .action_requests
                            .push(participant.clone());
                        Json(claim_action(&participant))
                    }
                }),
            ),
    )
    .await?;

    let signer = PrivateKeySigner::random();
    let signer_address = signer.address();
    let client = Client::new(
        ConfigBuilder::default()
            .rpc_url(core_url)
            .signer(signer)
            // Skips the auth handshake, which these tests are not about.
            .bearer_token("test-token".into())
            .ethereum_http_rpc_url(eth_url)
            .contract_address(CONTRACT.to_string())
            .build()?,
    )
    .await?;

    Ok((client, signer_address, log))
}

/// The calldata's leading address word, which for `claimNetCreditFor` is the creditor being paid.
fn claimed_creditor(input: &[u8]) -> Address {
    assert_eq!(
        input[..4],
        selector("claimNetCreditFor(address,bytes32,uint256,bytes32[])"),
        "expected the sponsored entrypoint"
    );
    Address::from_slice(&input[16..36])
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
    Ok(())
}

/// Claiming for oneself is the same call with the signer's own address, so both paths stay on one
/// entrypoint rather than drifting apart.
#[tokio::test]
async fn claiming_for_oneself_names_the_signer() -> anyhow::Result<()> {
    let (client, signer, log) = test_client().await?;

    client
        .settlement
        .claim_net_credit(CYCLE_ID.to_string())
        .await?;

    let log = log.lock().unwrap();
    assert_eq!(log.action_requests, vec![signer.to_string()]);
    assert_eq!(claimed_creditor(log.sole_broadcast().input()), signer);
    Ok(())
}

/// A sponsored claim carries no value: the payout comes from the cycle's funded pool, so a
/// submitter that attached ETH would just be handing it over.
#[tokio::test]
async fn a_sponsored_claim_sends_no_value() -> anyhow::Result<()> {
    let (client, _signer, log) = test_client().await?;

    client
        .settlement
        .claim_net_credit_for(CYCLE_ID.to_string(), CREDITOR)
        .await?;

    assert_eq!(log.lock().unwrap().sole_broadcast().value(), U256::ZERO);
    Ok(())
}
