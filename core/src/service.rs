use crate::{
    auth::verify_promise_signature,
    config::{AppConfig, DEFAULT_TTL_SECS},
    error::{PersistDbError, ServiceError, ServiceResult, service_error_to_rpc},
    ethereum::EthereumListener,
    persist::{PersistCtx, repo},
};
use alloy::{
    providers::{
        Identity, ProviderBuilder, RootProvider, WsConnect,
        fillers::{BlobGasFiller, ChainIdFiller, FillProvider, GasFiller, JoinFill, NonceFiller},
    },
    rpc::types::Transaction,
};
use alloy_primitives::U256;
use anyhow::anyhow;
use async_trait::async_trait;
use blockchain::txtools;
use blockchain::txtools::PaymentTx;
use chrono::TimeZone;
use crypto::bls::BLSCert;
use log::{error, info};
use rpc::{
    RpcResult,
    common::*,
    core::{CoreApiServer, CorePublicParameters},
};
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::{
    spawn,
    time::{Duration, sleep},
};
use tokio_cron_scheduler::{Job, JobScheduler};

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
    provider: RwLock<Option<EthereumProvider>>,
}

impl CoreService {
    pub async fn new(config: AppConfig) -> anyhow::Result<Self> {
        let public_key = crypto::bls::pub_key_from_priv_key(&config.secrets.bls_private_key)?;
        info!(
            "Operator started with BLS Public Key: {}",
            hex::encode(&public_key)
        );

        let chain_id = config.ethereum_config.chain_id;
        let persist_ctx = PersistCtx::new().await?;
        let persist_ctx_clone = persist_ctx.clone();
        let eth_cfg = config.ethereum_config.clone();

        spawn(async move {
            let mut delay = Duration::from_secs(1);
            loop {
                match EthereumListener::new(eth_cfg.clone(), persist_ctx_clone.clone())
                    .run()
                    .await
                {
                    Ok(_) => {
                        info!("EthereumListener exited gracefully");
                        break;
                    }
                    Err(e) => {
                        error!("EthereumListener error: {e}. Restarting in {delay:?}…");
                        sleep(delay).await;
                        delay = (delay * 2).min(Duration::from_secs(60));
                    }
                }
            }
        });

        let eip712_name = config.eip712.name.clone();
        let eip712_version = config.eip712.version.clone();
        Ok(Self {
            config,
            public_params: CorePublicParameters {
                public_key,
                eip712_name,
                eip712_version,
                chain_id,
            },
            persist_ctx,
            provider: RwLock::new(None),
        })
    }

    /// Periodically scan Ethereum for tab payments.
    async fn scan_blockchain(&self, lookback: u64) {
        match self.get_ethereum_provider().await {
            Ok(provider) => match txtools::scan_tab_payments(&provider, lookback).await {
                Ok(events) => match self.handle_discovered_payments(events).await {
                    Ok(_) => {}
                    Err(e) => error!("failed to persist discovered payments: {e}"),
                },
                Err(e) => error!("scan_tab_payments failed: {e}"),
            },
            Err(e) => error!("get_ethereum_provider failed: {e}"),
        }
    }

    /// Persist and remunerate for each discovered on-chain payment.
    async fn handle_discovered_payments(&self, events: Vec<PaymentTx>) -> ServiceResult<()> {
        for ev in events {
            let from = format!("{:?}", ev.from);
            let to = format!("{:?}", ev.to);
            let tx_hash = format!("{:?}", ev.tx_hash);
            let amount = ev.amount;

            info!(
                "Persisting payment tx: block={} from={} to={} tab_id={} req_id={} amount={} hash={}",
                ev.block_number, from, to, ev.tab_id, ev.req_id, amount, tx_hash
            );

            repo::submit_payment_transaction(
                &self.persist_ctx,
                from.clone(),
                to.clone(),
                tx_hash,
                amount,
            )
            .await?;

            repo::remunerate_recipient(&self.persist_ctx, ev.tab_id.clone(), amount).await?;
        }
        Ok(())
    }

    /// Spawn a background cron scheduler that periodically
    /// checks Ethereum and updates user collateral / tab status.
    ///
    /// Now takes &Arc<Self> directly, so we don't need clone_for_task anymore.
    pub fn monitor_transactions(self: &Arc<Self>) {
        let cron_expr = self.config.ethereum_config.cron_job_settings.clone();
        let num_blocks = self.config.ethereum_config.number_of_blocks_to_confirm;

        let service = Arc::clone(self);

        tokio::spawn(async move {
            if let Err(e) = CoreService::start_scheduler(service, &cron_expr, num_blocks).await {
                error!("scheduler exited with error: {e}");
            }
        });
    }

    async fn start_scheduler(
        service: Arc<Self>,
        cron_expr: &str,
        lookback: u64,
    ) -> anyhow::Result<()> {
        let sched = JobScheduler::new().await?;
        let job_service = Arc::clone(&service);

        let job = Job::new_async(cron_expr, move |_id, _lock| {
            let s = Arc::clone(&job_service);
            Box::pin(async move { s.scan_blockchain(lookback).await })
        })?;

        sched.add(job).await?;
        sched.start().await?;
        tokio::signal::ctrl_c().await?;
        Ok(())
    }

    pub fn ws_connection_details(&self) -> WsConnect {
        WsConnect::new(&self.config.ethereum_config.ws_rpc_url)
    }

    pub async fn get_ethereum_provider(&self) -> ServiceResult<EthereumProvider> {
        match self.provider.read().await.as_ref() {
            Some(p) => Ok(p.clone()),
            None => {
                let p = ProviderBuilder::new()
                    .connect_ws(self.ws_connection_details())
                    .await
                    .map_err(|err| {
                        error!("Failed to connect to Ethereum provider: {err}");
                        ServiceError::Other(anyhow!(err))
                    })?;
                *self.provider.write().await = Some(p.clone());
                Ok(p)
            }
        }
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

    async fn preflight_promise_checks(&self, req: &PaymentGuaranteeRequest) -> ServiceResult<()> {
        verify_promise_signature(&self.public_params, req)?;

        let promise = &req.claims;
        let last_opt = repo::get_last_guarantee_for_tab(&self.persist_ctx, &promise.tab_id)
            .await
            .map_err(ServiceError::from)?;

        let cur_req_id = promise
            .req_id
            .parse::<u64>()
            .map_err(|_| ServiceError::InvalidParams("Invalid req_id".into()))?;

        match last_opt {
            Some(ref last) => {
                let prev_req_id = last
                    .req_id
                    .parse::<u64>()
                    .map_err(|_| ServiceError::Other(anyhow!("Invalid previous req_id")))?;

                if cur_req_id.wrapping_sub(prev_req_id) != 1 {
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
            None => {
                if promise.req_id != "0" {
                    return Err(ServiceError::InvalidRequestID);
                }
            }
        }

        let now_i64 = chrono::Utc::now().timestamp();
        if now_i64 < 0 {
            return Err(ServiceError::Other(anyhow!("System time before epoch")));
        }
        let now_secs = now_i64 as u64;

        if now_secs < promise.timestamp {
            return Err(ServiceError::FutureTimestamp);
        }

        let ttl_secs = match repo::get_tab_ttl_seconds(&self.persist_ctx, &promise.tab_id).await {
            Ok(ttl) => ttl,
            Err(PersistDbError::TabNotFound(_)) if promise.req_id == "0" => {
                let default_ttl: u64 = DEFAULT_TTL_SECS;
                let start_ts = chrono::Utc
                    .timestamp_opt(promise.timestamp as i64, 0)
                    .single()
                    .ok_or_else(|| ServiceError::InvalidParams("invalid timestamp".into()))?
                    .naive_utc();
                repo::create_tab(
                    &self.persist_ctx,
                    &promise.tab_id,
                    &promise.user_address,
                    &promise.recipient_address,
                    start_ts,
                    default_ttl as i64,
                )
                .await
                .map_err(ServiceError::from)?;
                default_ttl
            }
            Err(e) => return Err(ServiceError::from(e)),
        };

        if ttl_secs <= 0 {
            return Err(ServiceError::InvalidParams("Invalid tab TTL".into()));
        }

        let expiry = promise.timestamp.saturating_add(ttl_secs as u64);
        if expiry < now_secs {
            return Err(ServiceError::TabClosed);
        }

        Ok(())
    }

    async fn handle_promise(&self, req: PaymentGuaranteeRequest) -> ServiceResult<BLSCert> {
        let promise = req.claims.clone();

        info!(
            "Received guarantee request; tab_id={}, req_id={}, amount={}",
            promise.tab_id, promise.req_id, promise.amount
        );
        self.preflight_promise_checks(&req).await?;
        let cert = self.create_bls_cert(promise.clone()).await?;

        repo::lock_and_store_guarantee(&self.persist_ctx, &promise, &cert)
            .await
            .map_err(ServiceError::from)?;
        Ok(cert)
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

    async fn issue_guarantee(&self, req: PaymentGuaranteeRequest) -> RpcResult<BLSCert> {
        self.handle_promise(req).await.map_err(service_error_to_rpc)
    }
}
#[derive(Clone)]
pub struct CoreServiceRpc(pub Arc<CoreService>);
#[async_trait]
impl CoreApiServer for CoreServiceRpc {
    async fn get_public_params(&self) -> RpcResult<CorePublicParameters> {
        Ok(self.0.public_params.clone())
    }

    async fn issue_guarantee(&self, req: PaymentGuaranteeRequest) -> RpcResult<BLSCert> {
        self.0
            .handle_promise(req)
            .await
            .map_err(service_error_to_rpc)
    }
}
