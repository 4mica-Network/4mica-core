use crate::{
    auth::verify_promise_signature,
    config::{AppConfig, DEFAULT_TTL_SECS},
    error::{ServiceError, ServiceResult, service_error_to_rpc},
    ethereum::{contract_abi::Core4Mica, EthereumListener, EthereumWriter, PaymentWriter},
    persist::{PersistCtx, repo},
    util::u256_to_string,
};
use alloy::{
    primitives::{Address, U256},
    providers::{
        Identity, Provider, ProviderBuilder, RootProvider, WsConnect,
        fillers::{BlobGasFiller, ChainIdFiller, FillProvider, GasFiller, JoinFill, NonceFiller},
    },
    rpc::types::Transaction,
};
use anyhow::anyhow;
use async_trait::async_trait;
use blockchain::txtools;
use blockchain::txtools::PaymentTx;
use chrono::TimeZone;
use crypto::bls::BLSCert;
use entities::sea_orm_active_enums::TabStatus;
use log::{error, info};
use rpc::{
    RpcResult,
    common::*,
    core::{CoreApiServer, CorePublicParameters},
};
use std::{str::FromStr, sync::Arc};
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

#[cfg_attr(not(test), allow(dead_code))]
pub mod test_hooks {
    use once_cell::sync::Lazy;
    use std::sync::{Arc, Mutex};

    pub type SchedulerCallback = Arc<dyn Fn(&str, u64) + Send + Sync + 'static>;
    pub type ScanCallback = Arc<dyn Fn(u64) -> bool + Send + Sync + 'static>;

    static SCHEDULER_CALLBACK: Lazy<Mutex<Option<SchedulerCallback>>> =
        Lazy::new(|| Mutex::new(None));
    static SCAN_CALLBACK: Lazy<Mutex<Option<ScanCallback>>> = Lazy::new(|| Mutex::new(None));

    pub fn set_scheduler_callback(callback: SchedulerCallback) {
        *SCHEDULER_CALLBACK
            .lock()
            .expect("scheduler callback poisoned") = Some(callback);
    }

    pub fn clear_scheduler_callback() {
        *SCHEDULER_CALLBACK
            .lock()
            .expect("scheduler callback poisoned") = None;
    }

    pub fn invoke_scheduler_callback(cron_expr: &str, lookback: u64) {
        if let Some(cb) = SCHEDULER_CALLBACK
            .lock()
            .expect("scheduler callback poisoned")
            .clone()
        {
            cb(cron_expr, lookback);
        }
    }

    pub fn set_scan_callback(callback: ScanCallback) {
        *SCAN_CALLBACK.lock().expect("scan callback poisoned") = Some(callback);
    }

    pub fn clear_scan_callback() {
        *SCAN_CALLBACK.lock().expect("scan callback poisoned") = None;
    }

    /// Returns `true` if the callback handled the scan and the caller should short-circuit.
    pub fn invoke_scan_callback(lookback: u64) -> bool {
        if let Some(cb) = SCAN_CALLBACK
            .lock()
            .expect("scan callback poisoned")
            .clone()
        {
            return cb(lookback);
        }
        false
    }
}

pub struct CoreService {
    config: AppConfig,
    public_params: CorePublicParameters,
    persist_ctx: PersistCtx,
    provider: RwLock<Option<EthereumProvider>>,
    payment_writer: Arc<dyn PaymentWriter>,
}

impl CoreService {
    pub async fn new(config: AppConfig) -> anyhow::Result<Self> {
        if config.secrets.bls_private_key.bytes().len() != 32 {
            anyhow::bail!("BLS private key must be 32 bytes");
        }

        let persist_ctx = PersistCtx::new().await?;
        let persist_ctx_clone = persist_ctx.clone();
        let eth_cfg = config.ethereum_config.clone();
        let listener_cfg = eth_cfg.clone();

        let provider = ProviderBuilder::new()
            .connect(&eth_cfg.http_rpc_url)
            .await
            .map_err(|e| anyhow!("failed to connect to Ethereum RPC: {e}"))?;
        let actual_chain_id = provider
            .get_chain_id()
            .await
            .map_err(|e| anyhow!("failed to fetch chain id from Ethereum RPC: {e}"))?;

        if actual_chain_id != eth_cfg.chain_id {
            anyhow::bail!(
                "ETHEREUM_CHAIN_ID ({}) does not match node-reported chain id ({actual_chain_id}).",
                eth_cfg.chain_id
            );
        }

        let contract_addr = Address::from_str(&eth_cfg.contract_address)
            .map_err(|e| anyhow!("invalid contract address: {}", e))?;
        let contract = Core4Mica::new(contract_addr, provider);
        let on_chain_domain = contract
            .guaranteeDomainSeparator()
            .call()
            .await
            .map_err(|e| anyhow!("failed to read on-chain domain separator: {e}"))?;
        let domain_bytes: [u8; 32] = on_chain_domain.into();
        crypto::guarantee::set_guarantee_domain_separator(domain_bytes)
            .map_err(|e| anyhow!("failed to set guarantee domain: {e}"))?;

        spawn(async move {
            let mut delay = Duration::from_secs(1);
            loop {
                match EthereumListener::new(listener_cfg.clone(), persist_ctx_clone.clone())
                    .run()
                    .await
                {
                    Ok(_) => {
                        info!("EthereumListener connected successfully.");
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

        let payment_writer: Arc<dyn PaymentWriter> = Arc::new(
            EthereumWriter::new(eth_cfg.clone())
                .await
                .map_err(|e| anyhow!(e))?,
        );

        Self::new_with_dependencies(config, persist_ctx, payment_writer, actual_chain_id)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn new_with_dependencies(
        config: AppConfig,
        persist_ctx: PersistCtx,
        payment_writer: Arc<dyn PaymentWriter>,
        chain_id: u64,
    ) -> anyhow::Result<Self> {
        let bls_private_key = config.secrets.bls_private_key.bytes();
        if bls_private_key.len() != 32 {
            anyhow::bail!("BLS private key must be 32 bytes");
        }

        let public_key = crypto::bls::pub_key_from_scalar(bls_private_key.try_into()?)?;
        info!(
            "Operator started with BLS Public Key: {}",
            hex::encode(&public_key)
        );

        let eip712_name = config.eip712.name.clone();
        let eip712_version = config.eip712.version.clone();
        let eth_config = config.ethereum_config.clone();
        let domain = crypto::guarantee::guarantee_domain_separator()?;
        info!("Guarantee domain separator: 0x{}", hex::encode(domain));

        Ok(Self {
            config,
            public_params: CorePublicParameters {
                public_key,
                contract_address: eth_config.contract_address.clone(),
                ethereum_http_rpc_url: eth_config.http_rpc_url.clone(),
                eip712_name,
                eip712_version,
                chain_id,
            },
            persist_ctx,
            provider: RwLock::new(None),
            payment_writer,
        })
    }

    fn bls_private_key(&self) -> [u8; 32] {
        self.config
            .secrets
            .bls_private_key
            .bytes()
            .try_into()
            .expect("BLS private key must be 32 bytes")
    }

    /// Periodically scan Ethereum for tab payments.
    async fn scan_blockchain(&self, lookback: u64) -> anyhow::Result<()> {
        if test_hooks::invoke_scan_callback(lookback) {
            return Ok(());
        }

        let provider = self.get_ethereum_provider().await.inspect_err(|e| {
            error!("get_ethereum_provider failed: {e}");
        })?;
        let events = txtools::scan_tab_payments(&provider, lookback)
            .await
            .inspect_err(|e| {
                error!("scan_tab_payments failed: {e}");
            })?;

        self.handle_discovered_payments(events)
            .await
            .inspect_err(|e| {
                error!("failed to persist discovered payments: {e}");
            })?;

        Ok(())
    }

    /// Persist and unlock user collateral for each discovered on-chain payment.
    async fn handle_discovered_payments(&self, events: Vec<PaymentTx>) -> ServiceResult<()> {
        for ev in events {
            let tab_id_str = u256_to_string(ev.tab_id);
            let tx_hash = format!("{:#x}", ev.tx_hash);
            let amount = ev.amount;

            info!(
                "Processing discovered payment: block={} tab_id={} req_id={} amount={} tx={}",
                ev.block_number,
                tab_id_str,
                u256_to_string(ev.req_id),
                amount,
                tx_hash
            );

            if repo::payment_transaction_exists(&self.persist_ctx, &tx_hash).await? {
                info!(
                    "Skipping already processed payment tx {} for tab {}",
                    tx_hash, tab_id_str
                );
                continue;
            }

            let Some(tab) = repo::get_tab_by_id(&self.persist_ctx, ev.tab_id).await? else {
                error!(
                    "Tab {} not found while processing payment tx {}. Skipping.",
                    tab_id_str, tx_hash
                );
                continue;
            };

            repo::submit_payment_transaction(
                &self.persist_ctx,
                tab.user_address.clone(),
                tab.server_address.clone(),
                tx_hash.clone(),
                amount,
            )
            .await?;

            if let Err(err) = self.payment_writer.record_payment(ev.tab_id, amount).await {
                error!(
                    "Failed to record payment on-chain for tab {} (tx {}): {err}",
                    tab_id_str, tx_hash
                );
                return Err(ServiceError::Other(anyhow!(
                    "failed to record payment on-chain for tab {tab_id_str}: {err}"
                )));
            }

            repo::unlock_user_collateral(&self.persist_ctx, ev.tab_id, amount).await?;
        }
        Ok(())
    }

    /// Spawn a background cron scheduler that periodically
    /// checks Ethereum and updates user collateral / tab status.
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
        test_hooks::invoke_scheduler_callback(cron_expr, lookback);

        let sched = JobScheduler::new().await?;
        let job_service = Arc::clone(&service);

        let job = Job::new_async(cron_expr, move |_id, _lock| {
            let s = Arc::clone(&job_service);
            Box::pin(async move {
                s.scan_blockchain(lookback).await.ok();
            })
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
        let last_opt = repo::get_last_guarantee_for_tab(&self.persist_ctx, promise.tab_id)
            .await
            .map_err(ServiceError::from)?;

        let cur_req_id = promise.req_id;
        match last_opt {
            Some(ref last) => {
                let prev_req_id = U256::from_str(&last.req_id).map_err(|e| {
                    ServiceError::InvalidParams(format!("Invalid prev_req_id: {}", e))
                })?;

                if cur_req_id.wrapping_sub(prev_req_id) != U256::from(1u8) {
                    info!(
                        "Invalid req_id: current={}, previous={}",
                        cur_req_id, prev_req_id
                    );
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
                info!(
                    "No previous guarantee found for tab_id={}. This must be the first request. req_id = {}",
                    promise.tab_id, promise.req_id
                );
                if promise.req_id != U256::ZERO {
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

        let Some(tab) = repo::get_tab_by_id(&self.persist_ctx, promise.tab_id).await? else {
            return Err(ServiceError::NotFound(u256_to_string(promise.tab_id)));
        };

        if (tab.status == TabStatus::Pending) != (promise.req_id == U256::ZERO) {
            return Err(ServiceError::InvalidRequestID);
        }

        if tab.status == TabStatus::Pending {
            let start_ts = chrono::Utc
                .timestamp_opt(promise.timestamp as i64, 0)
                .single()
                .ok_or_else(|| ServiceError::InvalidParams("invalid timestamp".into()))?
                .naive_utc();
            repo::open_tab(&self.persist_ctx, promise.tab_id, start_ts).await?;
        }

        if tab.ttl <= 0 {
            return Err(ServiceError::InvalidParams("Invalid tab TTL".into()));
        }

        let expiry = promise.timestamp.saturating_add(tab.ttl as u64);
        if expiry < now_secs {
            return Err(ServiceError::TabClosed);
        }

        Ok(())
    }

    async fn create_bls_cert(&self, promise: PaymentGuaranteeClaims) -> ServiceResult<BLSCert> {
        BLSCert::new(&self.bls_private_key(), promise)
            .map_err(|err| ServiceError::Other(anyhow!(err)))
    }

    async fn handle_promise(&self, req: PaymentGuaranteeRequest) -> ServiceResult<BLSCert> {
        let promise = req.claims.clone();

        info!(
            "Received guarantee request; tab_id={}, req_id={}, amount={}",
            promise.tab_id, promise.req_id, promise.amount
        );
        self.preflight_promise_checks(&req).await?;
        let cert: BLSCert = self.create_bls_cert(promise.clone()).await?;

        repo::lock_and_store_guarantee(&self.persist_ctx, &promise, &cert)
            .await
            .map_err(ServiceError::from)?;
        Ok(cert)
    }

    async fn create_payment_tab(
        &self,
        req: CreatePaymentTabRequest,
    ) -> ServiceResult<CreatePaymentTabResult> {
        let ttl = req.ttl.unwrap_or(DEFAULT_TTL_SECS);
        let tab_id = crate::util::generate_tab_id(&req.user_address, &req.recipient_address, ttl);

        let now = crate::util::now_naive();
        if now.and_utc().timestamp() < 0 {
            return Err(ServiceError::Other(anyhow!("System time before epoch")));
        }

        repo::create_pending_tab(
            &self.persist_ctx,
            tab_id,
            &req.user_address,
            &req.recipient_address,
            now,
            ttl as i64,
        )
        .await?;

        Ok(CreatePaymentTabResult {
            id: tab_id,
            user_address: req.user_address,
            recipient_address: req.recipient_address,
        })
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

    async fn create_payment_tab(
        &self,
        req: CreatePaymentTabRequest,
    ) -> RpcResult<CreatePaymentTabResult> {
        self.create_payment_tab(req)
            .await
            .map_err(service_error_to_rpc)
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

    async fn create_payment_tab(
        &self,
        req: CreatePaymentTabRequest,
    ) -> RpcResult<CreatePaymentTabResult> {
        self.0
            .create_payment_tab(req)
            .await
            .map_err(service_error_to_rpc)
    }
}
