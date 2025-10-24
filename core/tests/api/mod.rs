use alloy::{
    primitives::{Address, Signature, U256},
    signers::Signer,
    sol_types::{SolStruct, eip712_domain, sol},
};
use alloy_sol_types::SolValue;
use chrono::{Duration, Utc};
use core_service::config::{AppConfig, DEFAULT_ASSET_ADDRESS};
use core_service::persist::{PersistCtx, repo};
use core_service::{auth::verify_promise_signature, util::u256_to_string};
use entities::{collateral_event, guarantee};
use rand::random;
use rpc::{
    common::{
        CreatePaymentTabRequest, PaymentGuaranteeClaims, PaymentGuaranteeRequest, SigningScheme,
    },
    core::{CoreApiClient, CorePublicParameters},
    proxy::RpcProxy,
};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter};
use serial_test::serial;
use std::str::FromStr;
use test_log::test;
use uuid::Uuid;

#[path = "../common/mod.rs"]
mod common;
use common::fixtures::{
    clear_all_tables, ensure_user_with_collateral, init_test_env, random_address,
};

const STABLE_ASSET_ADDRESS: &str = "0x1111111111111111111111111111111111111111";

pub(super) async fn setup_clean_db() -> (AppConfig, RpcProxy, PersistCtx) {
    let (config, ctx) = init_test_env().await.expect("init test env");
    let core_addr = format!(
        "http://{}:{}",
        config.server_config.host, config.server_config.port
    );
    let core_client = RpcProxy::new(&core_addr).expect("connect RPC");

    clear_all_tables(&ctx).await.expect("clear all tables");

    (config, core_client, ctx)
}

pub(super) async fn insert_user_with_collateral(ctx: &PersistCtx, addr: &str, amount: U256) {
    ensure_user_with_collateral(ctx, addr, amount)
        .await
        .expect("seed user collateral");
}

pub(super) async fn insert_user_with_asset_collateral(
    ctx: &PersistCtx,
    addr: &str,
    asset: &str,
    amount: U256,
) {
    common::fixtures::ensure_user(ctx, addr)
        .await
        .expect("ensure user exists");
    repo::deposit(ctx, addr.to_string(), asset.to_string(), amount)
        .await
        .expect("seed user collateral for asset");
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn build_signed_req(
    public_params: &CorePublicParameters,
    user_addr: &str,
    recipient_addr: &str,
    tab_id: U256,
    req_id: U256,
    amount: U256,
    wallet: &alloy::signers::local::PrivateKeySigner,
    timestamp: Option<u64>,
    asset_address: &str,
) -> PaymentGuaranteeRequest {
    sol! {
        struct PaymentGuarantee {
            address user;
            address recipient;
            uint256 tabId;
            uint256  reqId;
            uint256 amount;
            uint64  timestamp;
        }
    }

    let ts = timestamp.unwrap_or_else(|| Utc::now().timestamp() as u64);
    let domain = eip712_domain!(
        name: public_params.eip712_name.clone(),
        version: public_params.eip712_version.clone(),
        chain_id: public_params.chain_id,
    );
    let msg = PaymentGuarantee {
        user: Address::from_str(user_addr).unwrap(),
        recipient: Address::from_str(recipient_addr).unwrap(),
        tabId: tab_id,
        reqId: req_id,
        amount,
        timestamp: ts,
    };
    let digest = msg.eip712_signing_hash(&domain);
    let sig: Signature = wallet.sign_hash(&digest).await.unwrap();
    PaymentGuaranteeRequest {
        claims: PaymentGuaranteeClaims {
            user_address: user_addr.to_string(),
            recipient_address: recipient_addr.to_string(),
            tab_id,
            req_id,
            amount,
            timestamp: ts,
            asset_address: asset_address.to_string(),
        },
        signature: crypto::hex::encode_hex(&sig.as_bytes()),
        scheme: SigningScheme::Eip712,
    }
}

pub(super) async fn build_eip712_signed_request(
    params: &CorePublicParameters,
    wallet: &alloy::signers::local::PrivateKeySigner,
) -> PaymentGuaranteeRequest {
    sol! {
        struct PaymentGuarantee {
            address user;
            address recipient;
            uint256  tabId;
            uint256  reqId;
            uint256 amount;
            uint64  timestamp;
        }
    }

    let timestamp = Utc::now().timestamp() as u64;
    let req_id_u64 = 0u64;

    let domain = eip712_domain!(
        name:     params.eip712_name.clone(),
        version:  params.eip712_version.clone(),
        chain_id: params.chain_id,
    );

    let recipient = Address::from(random::<[u8; 20]>());
    let msg = PaymentGuarantee {
        user: wallet.address(),
        recipient,
        tabId: U256::from(0x7461622d6f6b32u128),
        reqId: U256::from(req_id_u64),
        amount: U256::from(42u64),
        timestamp,
    };
    let digest = msg.eip712_signing_hash(&domain);
    let sig: Signature = wallet.sign_hash(&digest).await.unwrap();

    PaymentGuaranteeRequest {
        claims: PaymentGuaranteeClaims {
            user_address: wallet.address().to_string(),
            recipient_address: recipient.to_string(),
            tab_id: U256::from(0x7461622d6f6b32u128),
            req_id: U256::from(0u64),
            amount: U256::from(42u64),
            timestamp,
            asset_address: "0x0000000000000000000000000000000000000000".into(),
        },
        signature: crypto::hex::encode_hex(&sig.as_bytes()),
        scheme: SigningScheme::Eip712,
    }
}

mod guarantee;
mod tabs;
mod payments;
mod collateral;
mod signing;
