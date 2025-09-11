use crate::config::AppConfig;
use crate::ethereum::EthereumListener;
use crate::persist::repo::{self, SubmitPaymentTxnError};
use crate::persist::{IntoUserTxInfo, PersistCtx};

use alloy::primitives::{B256, U256};
use alloy::providers::fillers::{
    BlobGasFiller, ChainIdFiller, FillProvider, GasFiller, JoinFill, NonceFiller,
};
use alloy::providers::{Identity, ProviderBuilder, RootProvider, WsConnect};
use alloy::rpc::types::Transaction;
use async_trait::async_trait;
use blockchain::txtools;
use crypto::bls::BLSCert;
use entities::user_transaction;
use log::{error, info};
use rpc::RpcResult;
use rpc::common::{
    PaymentGuaranteeClaims, TransactionVerificationResult, UserInfo, UserTransactionInfo,
};
use rpc::core::{CoreApiServer, CorePublicParameters};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};

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

    /// Get the details for the websocket connection
    pub fn ws_connection_details(&self) -> WsConnect {
        WsConnect::new(&self.config.ethereum_config.ws_rpc_url)
    }

    /// Obtain an [`EthereumProvider`], given the connection details in `self.config`.
    pub async fn get_ethereum_provider(&self) -> RpcResult<EthereumProvider> {
        ProviderBuilder::new()
            .connect_ws(self.ws_connection_details())
            .await
            .map_err(|err| {
                error!("Failed to connect to Ethereum provider: {err}");
                rpc::internal_error()
            })
    }

    /// Validate that a given [`Transaction`] has a given `sender`, `recipient` and `amount`.
    pub fn validate_transaction(
        tx: &Transaction,
        sender_address: &str,
        recipient_address: &str,
        amount: U256,
    ) -> RpcResult<()> {
        let user = txtools::parse_eth_address(sender_address, "user")?;
        let recipient = txtools::parse_eth_address(recipient_address, "recipient")?;
        let expected = amount;
        txtools::validate_transaction(tx, user, recipient, expected)
    }
}

#[async_trait]
impl CoreApiServer for CoreService {
    async fn get_public_params(&self) -> RpcResult<CorePublicParameters> {
        Ok(self.public_params.clone())
    }

    async fn deposit(&self, user_addr: String, amount: U256) -> RpcResult<()> {
        repo::deposit(&self.persist_ctx, user_addr, amount)
            .await
            .map_err(|err| {
                error!("Failed to deposit: {err}");
                rpc::internal_error()
            })?;
        Ok(())
    }
    async fn get_user(&self, user_addr: String) -> RpcResult<Option<UserInfo>> {
        let Some(user) = repo::get_user(&self.persist_ctx, user_addr.clone())
            .await
            .map_err(|err| {
                error!("Failed to get user: {err}");
                rpc::internal_error()
            })?
        else {
            return Ok(None);
        };

        // Fetch ALL transactions for this user (SeaORM)
        let transactions = user_transaction::Entity::find()
            .filter(user_transaction::Column::UserAddress.eq(user_addr))
            .all(&*self.persist_ctx.db)
            .await
            .map_err(|err| {
                error!("Failed to load user transactions: {err}");
                rpc::internal_error()
            })?;

        // Compute reserved (not usable) portion
        let not_usable: U256 = transactions
            .iter()
            .filter(|tx| !tx.finalized)
            .map(|tx| {
                tx.amount
                    .parse::<U256>()
                    .unwrap_or_else(|_| U256::from(0u64))
            })
            .fold(U256::from(0u64), |acc, x| acc.saturating_add(x));

        // Parse user collateral
        let collateral: U256 = user.collateral.parse::<U256>().map_err(|e| {
            error!("Invalid collateral value: {e}");
            rpc::internal_error()
        })?;

        // Available = collateral - reserved (saturating to zero if underflow)
        let available = collateral.checked_sub(not_usable).unwrap();

        Ok(Some(UserInfo {
            deposit: collateral,
            available_deposit: available,
            transactions: transactions
                .into_iter()
                .map(|tx| tx.into_user_tx_info())
                .collect(),
        }))
    }
    async fn issue_payment_cert(
        &self,
        user_addr: String,
        recipient_addr: String,
        transaction_id: String,
        amount: U256,
    ) -> RpcResult<BLSCert> {
        info!(
            "Issuing cert for user: {user_addr}, recipient: {recipient_addr}, tx_hash: {transaction_id}, amount: {amount}"
        );

        let provider = self.get_ethereum_provider().await?;

        let tx_hash = transaction_id
            .as_bytes()
            .try_into()
            .map_err(|err| {
                error!("Invalid transaction hash: {err}");
                rpc::invalid_params_error("Invalid transaction hash")
            })
            .map(B256::new)?;
        let tx = txtools::fetch_transaction(&provider, tx_hash).await?;
        Self::validate_transaction(&tx, &user_addr, &recipient_addr, amount)?;

        let claims = PaymentGuaranteeClaims {
            user_addr: user_addr.clone(),
            recipient_addr: recipient_addr.clone(),
            tx_hash: transaction_id.clone(),
            amount,
        };
        let cert = BLSCert::new(&self.config.secrets.bls_private_key, claims).map_err(|err| {
            error!("Failed to issue the payment guarantee cert: {err}");
            rpc::internal_error()
        })?;

        let cert_str = serde_json::to_string(&cert).map_err(|err| {
            error!("Failed to serialize the payment guarantee cert: {err}");
            rpc::internal_error()
        })?;
        repo::submit_payment_transaction(
            &self.persist_ctx,
            user_addr.clone(),
            recipient_addr.clone(),
            transaction_id.clone(),
            amount,
            cert_str,
        )
        .await
        .map_err(|err| match err {
            SubmitPaymentTxnError::Db(db_err) => {
                error!("{db_err}");
                rpc::internal_error()
            }
            SubmitPaymentTxnError::UserNotRegistered
            | SubmitPaymentTxnError::NotEnoughDeposit
            // TODO, what happens in case of conflict?
            | SubmitPaymentTxnError::ConflictingTransactions => {
                rpc::invalid_params_error(&format!("{err}"))
            }
        })?;

        Ok(cert)
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

    async fn verify_transaction(
        &self,
        tx_hash: String,
    ) -> RpcResult<TransactionVerificationResult> {
        let verified = repo::verify_transaction(&self.persist_ctx, tx_hash)
            .await
            .map_err(|err| {
                error!("Failed to verify transaction {err}");
                rpc::internal_error()
            })?;

        Ok(verified)
    }
}
