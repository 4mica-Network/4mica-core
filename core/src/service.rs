// service.rs

use crate::{
    config::AppConfig,
    error::{PersistDbError, ServiceError, ServiceResult, service_error_to_rpc},
    ethereum::EthereumListener,
    persist::{PersistCtx, repo},
};
use alloy::providers::fillers::{
    BlobGasFiller, ChainIdFiller, FillProvider, GasFiller, JoinFill, NonceFiller,
};
use alloy::providers::{Identity, ProviderBuilder, RootProvider, WsConnect};
use alloy::rpc::types::Transaction;
use alloy_primitives::U256;
use anyhow::anyhow;
use async_trait::async_trait;
use blockchain::txtools;
use chrono::{TimeZone, Utc};
use crypto::bls::BLSCert;
use log::{error, info};
use rpc::{
    RpcResult,
    common::*,
    core::{CoreApiServer, CorePublicParameters},
};
use std::str::FromStr;

type EthereumProvider = FillProvider<
    JoinFill<
        Identity,
        JoinFill<GasFiller, JoinFill<BlobGasFiller, JoinFill<NonceFiller, ChainIdFiller>>>,
    >,
    RootProvider,
>;

pub struct CoreService {
    config: AppConfig,
    public_params: CorePublicParameters,
    persist_ctx: PersistCtx,
}

impl CoreService {
    pub async fn new(config: AppConfig) -> anyhow::Result<Self> {
        let public_key = crypto::bls::pub_key_from_priv_key(&config.secrets.bls_private_key)?;
        info!("BLS Public Key: {}", hex::encode(&public_key));

        let persist_ctx = PersistCtx::new().await?;

        EthereumListener::new(config.ethereum_config.clone(), persist_ctx.clone())
            .run()
            .await?;

        Ok(Self {
            config,
            public_params: CorePublicParameters { public_key },
            persist_ctx,
        })
    }

    pub fn ws_connection_details(&self) -> WsConnect {
        WsConnect::new(&self.config.ethereum_config.ws_rpc_url)
    }

    pub async fn get_ethereum_provider(&self) -> ServiceResult<EthereumProvider> {
        ProviderBuilder::new()
            .connect_ws(self.ws_connection_details())
            .await
            .map_err(|err| {
                error!("Failed to connect to Ethereum provider: {err}");
                ServiceError::Other(anyhow!(err))
            })
    }

    fn verify_promise_signature(&self, _p: &PaymentGuaranteeClaims) -> bool {
        // TODO: implement real signature verification
        true
    }

    pub fn validate_transaction(
        tx: &Transaction,
        sender_address: &str,
        recipient_address: &str,
        amount: U256,
    ) -> ServiceResult<()> {
        let user = txtools::parse_eth_address(sender_address, "user")
            .map_err(|e| ServiceError::InvalidParams(e.to_string()))?;
        let recipient = txtools::parse_eth_address(recipient_address, "recipient")
            .map_err(|e| ServiceError::InvalidParams(e.to_string()))?;
        txtools::validate_transaction(tx, user, recipient, amount)
            .map_err(|e| ServiceError::InvalidParams(e.to_string()))
    }

    /// Perform validations for promises.
    async fn preflight_promise_checks(
        &self,
        promise: &PaymentGuaranteeClaims,
    ) -> ServiceResult<()> {
        // small helper for brevity
        let invalid =
            |msg: &str| -> ServiceResult<()> { Err(ServiceError::InvalidParams(msg.to_string())) };

        // 1) signature
        if !self.verify_promise_signature(promise) {
            error!(
                "preflight: invalid signature tab_id={} user={} req_id={}",
                promise.tab_id, promise.user_address, promise.req_id
            );
            return invalid("invalid signature");
        }

        // 2) req_id & start_ts checks against the most recent guarantee for this tab
        let last_opt = repo::get_last_guarantee_for_tab(&self.persist_ctx, &promise.tab_id)
            .await
            .map_err(|e| {
                error!(
                    "preflight: get_last_guarantee_for_tab failed: tab_id={} err={}",
                    promise.tab_id, e
                );
                ServiceError::from(e)
            })?;

        let cur_req_id = promise.req_id.parse::<u64>().map_err(|e| {
            error!(
                "preflight: invalid req_id: tab_id={} req_id='{}' err={}",
                promise.tab_id, promise.req_id, e
            );
            ServiceError::InvalidParams("invalid req_id".into())
        })?;

        if let Some(last) = last_opt.as_ref() {
            let prev_req_id = last.req_id.parse::<u64>().map_err(|e| {
                error!(
                    "preflight: invalid previous req_id in DB: tab_id={} prev_req_id='{}' err={}",
                    promise.tab_id, last.req_id, e
                );
                ServiceError::Other(anyhow!("invalid previous req_id"))
            })?;

            let expected = prev_req_id.saturating_add(1);
            if cur_req_id != expected {
                error!(
                    "preflight: req_id not incremented: tab_id={} prev_req_id={} expected={} got={}",
                    promise.tab_id, prev_req_id, expected, cur_req_id
                );
                return invalid("req_id not incremented");
            }

            // DB has NaiveDateTime; guard against negatives before casting to u64
            let prev_ts_i64 = last.start_ts.and_utc().timestamp();
            if prev_ts_i64 < 0 {
                error!(
                    "preflight: negative previous start_ts in DB: tab_id={} prev_ts_i64={}",
                    promise.tab_id, prev_ts_i64
                );
                return Err(ServiceError::Other(anyhow!("negative previous start_ts")));
            }
            let prev_start_ts = prev_ts_i64 as u64;

            if promise.timestamp != prev_start_ts {
                error!(
                    "preflight: modified start_ts: tab_id={} expected={} got={}",
                    promise.tab_id, prev_start_ts, promise.timestamp
                );
                return invalid("modified start_ts");
            }
        }

        // 3) time-based validations (using client-provided start_ts)
        let now_i64 = Utc::now().timestamp();
        if now_i64 < 0 {
            error!("preflight: system time before epoch: now_i64={}", now_i64);
            return Err(ServiceError::Other(anyhow!("system time before epoch")));
        }
        let now_secs = now_i64 as u64;

        if now_secs < promise.timestamp {
            error!(
                "preflight: future timestamp: tab_id={} now={} start_ts={}",
                promise.tab_id, now_secs, promise.timestamp
            );
            return invalid("future timestamp");
        }

        // 4) TTL from repo::tabs::ttl — require positive TTL
        let ttl_secs = match repo::get_tab_ttl_seconds(&self.persist_ctx, &promise.tab_id).await {
            Ok(ttl) if ttl > 0 => ttl as u64,
            Ok(ttl) => {
                error!(
                    "preflight: invalid tab TTL (<=0): tab_id={} ttl={}",
                    promise.tab_id, ttl
                );
                return invalid("invalid tab TTL");
            }
            Err(e) => {
                error!(
                    "preflight: failed to read tab TTL: tab_id={} err={}",
                    promise.tab_id, e
                );
                return Err(ServiceError::from(e));
            }
        };

        let expiry = promise.timestamp.saturating_add(ttl_secs);
        if expiry < now_secs {
            error!(
                "preflight: tab closed: tab_id={} start_ts={} ttl={} expiry={} now={}",
                promise.tab_id, promise.timestamp, ttl_secs, expiry, now_secs
            );
            return invalid("tab closed");
        }

        Ok(())
    }

    async fn handle_promise(&self, promise: PaymentGuaranteeClaims) -> ServiceResult<BLSCert> {
        info!("Received guarantee request for promise: {:?}", promise);
        self.preflight_promise_checks(&promise).await?;
        self.lock_collateral(&promise.user_address, promise.amount)
            .await?;
        let guarantee = self.create_guarantee(&promise).await?;
        self.persist_guarantee(&promise, &guarantee).await?;
        Ok(guarantee)
    }

    async fn persist_guarantee(
        &self,
        promise: &PaymentGuaranteeClaims,
        cert: &BLSCert,
    ) -> ServiceResult<()> {
        let cert_str = serde_json::to_string(cert).map_err(|err| {
            error!("Failed to serialize the payment guarantee cert: {err}");
            ServiceError::Other(anyhow!(err))
        })?;

        // store the *claim’s* start_ts, not “now”
        let start_dt = match Utc.timestamp_opt(promise.timestamp as i64, 0).single() {
            Some(dt) => dt.naive_utc(),
            None => return Err(ServiceError::InvalidParams("invalid timestamp".into())),
        };

        repo::store_guarantee(
            &self.persist_ctx,
            promise.tab_id.clone(),
            promise.req_id.clone(),
            promise.user_address.clone(),
            promise.recipient_address.clone(),
            promise.amount,
            start_dt,
            cert_str,
        )
        .await
        .map_err(|err| {
            error!("Failed to store guarantee: {err}");
            ServiceError::from(err)
        })
    }

    /// Check user free collateral & optimistic lock using repo helpers only.
    async fn lock_collateral(&self, user_address: &str, amount: U256) -> ServiceResult<()> {
        let user = match repo::get_user(&self.persist_ctx, user_address).await {
            Ok(u) => u,
            Err(PersistDbError::UserNotFound(_)) => {
                return Err(ServiceError::InvalidParams("User not registered".into()));
            }
            Err(e) => {
                error!("DB error: {e}");
                return Err(ServiceError::from(e));
            }
        };

        let total_collateral = U256::from_str(&user.collateral)
            .map_err(|_| ServiceError::InvalidParams("invalid collateral value".into()))?;
        let current_locked = U256::from_str(&user.locked_collateral)
            .map_err(|_| ServiceError::InvalidParams("invalid locked collateral value".into()))?;

        let free_collateral = total_collateral.saturating_sub(current_locked);
        if free_collateral < amount {
            return Err(ServiceError::InvalidParams(
                "Not enough free collateral".into(),
            ));
        }
        let new_locked = current_locked
            .checked_add(amount)
            .ok_or_else(|| ServiceError::InvalidParams("overflow on locked collateral".into()))?;

        // Use new Result<(), PersistDbError> signature.
        match repo::update_user_lock_and_version(
            &self.persist_ctx,
            user_address,
            user.version,
            new_locked,
        )
        .await
        {
            Ok(()) => Ok(()),
            Err(PersistDbError::OptimisticLockConflict { .. }) => {
                Err(ServiceError::OptimisticLockConflict)
            }
            Err(e) => {
                error!("DB error: {e}");
                Err(ServiceError::from(e))
            }
        }
    }

    async fn create_guarantee(&self, promise: &PaymentGuaranteeClaims) -> ServiceResult<BLSCert> {
        let claims = PaymentGuaranteeClaims {
            user_address: promise.user_address.clone(),
            recipient_address: promise.recipient_address.clone(),
            tab_id: promise.tab_id.clone(),
            req_id: promise.req_id.clone(),
            amount: promise.amount,
            timestamp: promise.timestamp,
        };
        BLSCert::new(&self.config.secrets.bls_private_key, claims).map_err(|err| {
            error!("Failed to issue the payment guarantee cert: {err}");
            ServiceError::Other(anyhow!(err))
        })
    }
}

#[async_trait]
impl CoreApiServer for CoreService {
    async fn get_public_params(&self) -> RpcResult<CorePublicParameters> {
        Ok(self.public_params.clone())
    }

    async fn issue_guarantee(
        &self,
        user_address: String,
        recipient_addr: String,
        tab_id: String,
        req_id: String,
        amount: U256,
    ) -> RpcResult<BLSCert> {
        let promise = PaymentGuaranteeClaims {
            user_address,
            recipient_address: recipient_addr,
            tab_id,
            req_id,
            amount,
            timestamp: Utc::now().timestamp() as u64,
        };
        self.handle_promise(promise)
            .await
            .map_err(service_error_to_rpc)
    }
}
