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

    fn verify_promise_signature(&self, _p: &PaymentGuaranteeClaims) -> ServiceResult<bool> {
        // TODO(#24): implement real signature verification
        Ok(true)
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

    async fn preflight_promise_checks(
        &self,
        promise: &PaymentGuaranteeClaims,
    ) -> ServiceResult<()> {
        self.verify_promise_signature(promise)
            .map_err(|_| ServiceError::InvalidParams("Invalid signature".into()))?;

        let last_opt = repo::get_last_guarantee_for_tab(&self.persist_ctx, &promise.req_id)
            .await
            .map_err(|e| ServiceError::from(e))?;

        let cur_req_id = promise
            .req_id
            .parse::<u64>()
            .map_err(|_| ServiceError::InvalidParams("Invalid req_id".into()))?;

        match last_opt {
            None => {
                if promise.req_id != "0" {
                    return Err(ServiceError::InvalidRequestID);
                }
            }
            Some(ref last) => {
                let prev_req_id = last
                    .req_id
                    .parse::<u64>()
                    .map_err(|_| ServiceError::Other(anyhow!("Invalid previous req_id")))?;

                let expected = prev_req_id.saturating_add(1);
                if expected.wrapping_sub(cur_req_id) != 1 {
                    return Err(ServiceError::InvalidRequestID);
                }

                let prev_ts_i64 = last.start_ts.and_utc().timestamp();
                if prev_ts_i64 < 0 {
                    return Err(ServiceError::Other(anyhow!("Negative previous start_ts")));
                }

                let prev_start_ts = prev_ts_i64 as u64;
                if promise.timestamp != prev_start_ts {
                    return Err(ServiceError::ModifiedStartTs);
                }
            }
        }

        let now_i64 = Utc::now().timestamp();
        if now_i64 < 0 {
            return Err(ServiceError::Other(anyhow!("System time before epoch")));
        }
        let now_secs = now_i64 as u64;

        if now_secs < promise.timestamp {
            return Err(ServiceError::FutureTimestamp);
        }

        let ttl_secs = repo::get_tab_ttl_seconds(&self.persist_ctx, &promise.tab_id)
            .await
            .map_err(|e| ServiceError::from(e))?;

        if ttl_secs <= 0 {
            return Err(ServiceError::InvalidParams("Invalid tab TTL".into()));
        }

        let expiry = promise.timestamp.saturating_add(ttl_secs as u64);
        if expiry < now_secs {
            return Err(ServiceError::TabClosed);
        }

        Ok(())
    }

    async fn handle_promise(&self, promise: PaymentGuaranteeClaims) -> ServiceResult<BLSCert> {
        info!("Received guarantee request for promise: {:?}", promise);
        self.preflight_promise_checks(&promise).await?;
        self.lock_collateral(&promise.user_address, promise.amount)
            .await?;
        let guarantee = self.create_bls_cert(promise.clone()).await?;
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

        let start_dt = Utc
            .timestamp_opt(promise.timestamp as i64, 0)
            .single()
            .ok_or_else(|| ServiceError::InvalidParams("invalid timestamp".into()))?
            .naive_utc();

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

    async fn lock_collateral(&self, user_address: &str, amount: U256) -> ServiceResult<()> {
        let user = repo::get_user(&self.persist_ctx, user_address)
            .await
            .map_err(|e| match e {
                PersistDbError::UserNotFound(_) => ServiceError::UserNotRegistered,
                other => {
                    error!("DB error: {other}");
                    ServiceError::from(other)
                }
            })?;

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

        repo::update_user_lock_and_version(
            &self.persist_ctx,
            user_address,
            user.version,
            new_locked,
        )
        .await
        .map_err(|e| match e {
            PersistDbError::OptimisticLockConflict { .. } => ServiceError::OptimisticLockConflict,
            other => ServiceError::from(other),
        })
    }

    async fn create_bls_cert(&self, promise: PaymentGuaranteeClaims) -> ServiceResult<BLSCert> {
        BLSCert::new(&self.config.secrets.bls_private_key, promise)
            .map_err(|err| ServiceError::Other(anyhow!(err)))
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
