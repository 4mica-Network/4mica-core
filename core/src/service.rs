use crate::config::AppConfig;
use crate::error::PersistDbError;
use crate::ethereum::EthereumListener;
use crate::persist::{IntoUserTxInfo, PersistCtx, repo};
use alloy::providers::fillers::{
    BlobGasFiller, ChainIdFiller, FillProvider, GasFiller, JoinFill, NonceFiller,
};
use alloy::providers::{Identity, ProviderBuilder, RootProvider, WsConnect};
use alloy::rpc::types::Transaction;
use alloy_primitives::U256;
use async_trait::async_trait;
use blockchain::txtools;
use chrono::Utc;
use crypto::bls::BLSCert;
use log::{error, info};
use rpc::RpcResult;
use rpc::common::*;
use rpc::core::{CoreApiServer, CorePublicParameters};

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

    pub async fn get_ethereum_provider(&self) -> RpcResult<EthereumProvider> {
        ProviderBuilder::new()
            .connect_ws(self.ws_connection_details())
            .await
            .map_err(|err| {
                error!("Failed to connect to Ethereum provider: {err}");
                rpc::internal_error()
            })
    }

    pub fn validate_transaction(
        tx: &Transaction,
        sender_address: &str,
        recipient_address: &str,
        amount: U256,
    ) -> RpcResult<()> {
        let user = txtools::parse_eth_address(sender_address, "user")?;
        let recipient = txtools::parse_eth_address(recipient_address, "recipient")?;
        txtools::validate_transaction(tx, user, recipient, amount)
    }

    async fn handle_promise(&self, promise: PaymentGuaranteeClaims) -> RpcResult<BLSCert> {
        info!("Received guarantee request for promise: {:?}", promise);

        self.locked_collateral(&promise.user_address, promise.amount)
            .await?;
        let guarantee = self.create_guarantee(&promise).await?;
        self.persist_guarantee(&promise, &guarantee).await?;
        Ok(guarantee)
    }

    /// Check user free collateral & optimistic lock using repo helpers only.
    async fn locked_collateral(&self, user_address: &str, amount: U256) -> RpcResult<()> {
        let user = match repo::get_user(&self.persist_ctx, user_address).await {
            Ok(u) => u,
            Err(PersistDbError::UserNotFound(_)) => {
                return Err(rpc::invalid_params_error("User not registered"));
            }
            Err(e) => {
                error!("DB error: {e}");
                return Err(rpc::internal_error());
            }
        };

        let total_collateral = U256::from_str(&user.collateral)
            .map_err(|_| rpc::invalid_params_error("invalid collateral value"))?;
        let current_locked = U256::from_str(&user.locked_collateral)
            .map_err(|_| rpc::invalid_params_error("invalid locked collateral value"))?;

        let free_collateral = total_collateral.saturating_sub(current_locked);
        if free_collateral < amount {
            return Err(rpc::invalid_params_error("Not enough free collateral"));
        }
        let new_locked = current_locked
            .checked_add(amount)
            .ok_or_else(|| rpc::invalid_params_error("overflow on locked collateral"))?;

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
                Err(rpc::invalid_params_error("Invalid parameters"))
            }
            Err(e) => {
                error!("DB error: {e}");
                Err(rpc::internal_error())
            }
        }
    }

    async fn create_guarantee(&self, promise: &PaymentGuaranteeClaims) -> RpcResult<BLSCert> {
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
            rpc::internal_error()
        })
    }

    async fn persist_guarantee(
        &self,
        promise: &PaymentGuaranteeClaims,
        cert: &BLSCert,
    ) -> RpcResult<()> {
        let cert_str = serde_json::to_string(cert).map_err(|err| {
            error!("Failed to serialize the payment guarantee cert: {err}");
            rpc::internal_error()
        })?;
        repo::store_guarantee(
            &self.persist_ctx,
            promise.tab_id.clone(),
            promise.req_id.clone(),
            promise.user_address.clone(),
            promise.recipient_address.clone(),
            promise.amount,
            Utc::now().naive_utc(),
            cert_str,
        )
        .await
        .map_err(|err| {
            error!("Failed to store guarantee: {err}");
            rpc::internal_error()
        })
    }
}

#[async_trait]
impl CoreApiServer for CoreService {
    async fn get_public_params(&self) -> RpcResult<CorePublicParameters> {
        Ok(self.public_params.clone())
    }

    async fn deposit(&self, user_address: String, amount: U256) -> RpcResult<()> {
        repo::deposit(&self.persist_ctx, user_address, amount)
            .await
            .map_err(|err| {
                error!("Failed to deposit: {err}");
                rpc::internal_error()
            })?;
        Ok(())
    }

    async fn get_user(&self, user_address: String) -> RpcResult<Option<UserInfo>> {
        let user = match repo::get_user(&self.persist_ctx, &user_address).await {
            Ok(u) => u,
            Err(PersistDbError::UserNotFound(_)) => return Ok(None),
            Err(err) => {
                error!("Failed to get user: {err}");
                return Err(rpc::internal_error());
            }
        };
        let transactions = repo::get_user_transactions(&self.persist_ctx, &user_address)
            .await
            .map_err(|err| {
                error!("Failed to load user transactions: {err}");
                rpc::internal_error()
            })?;

        let not_usable = U256::from_str(&user.locked_collateral).map_err(|e| {
            error!("Invalid locked collateral value: {e}");
            rpc::internal_error()
        })?;

        let collateral: U256 = U256::from_str(&user.collateral).map_err(|e| {
            error!("Invalid collateral value: {e}");
            rpc::internal_error()
        })?;
        let available = collateral.saturating_sub(not_usable);

        Ok(Some(UserInfo {
            collateral,
            available_collateral: available,
            guarantees: vec![],
            transactions: transactions
                .into_iter()
                .map(|tx| tx.into_user_tx_info())
                .collect(),
        }))
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
            user_address: user_address,
            recipient_address: recipient_addr,
            tab_id,
            req_id,
            amount,
            timestamp: Utc::now().timestamp() as u64,
        };
        self.handle_promise(promise).await
    }

    async fn get_transactions_by_hash(
        &self,
        hashes: Vec<String>,
    ) -> RpcResult<Vec<UserTransactionInfo>> {
        let transactions = repo::get_transactions_by_hash(&self.persist_ctx, hashes)
            .await
            .map_err(|err| {
                error!("Failed to get transactions {err}");
                rpc::internal_error()
            })?;
        Ok(transactions
            .into_iter()
            .map(|tx| tx.into_user_tx_info())
            .collect())
    }
}
