use crate::config::AppConfig;
use crate::ethereum::EthereumListener;
use crate::persist::repo::{self, SubmitPaymentTxnError};
use crate::persist::PersistCtx;

use async_trait::async_trait;
use blockchain::txtools;
use crypto::bls::BLSCert;
use ethers::providers::{Provider, Ws};
use ethers::types::H256;
use log::{error, info};
use rpc::common::{
    PaymentGuaranteeClaims, TransactionVerificationResult, UserInfo, UserTransactionInfo,
};
use rpc::core::{CoreApiServer, CorePublicParameters};
use rpc::RpcResult;
use std::sync::Arc;

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
}

#[async_trait]
impl CoreApiServer for CoreService {
    async fn get_public_params(&self) -> RpcResult<CorePublicParameters> {
        Ok(self.public_params.clone())
    }

    async fn register_user(&self, user_addr: String) -> RpcResult<()> {
        repo::register_user(&self.persist_ctx, user_addr)
            .await
            .map_err(|err| {
                error!("Failed to register user {}", err);
                rpc::internal_error()
            })?;
        Ok(())
    }

    async fn get_user(&self, user_addr: String) -> RpcResult<Option<UserInfo>> {
        let Some(user) = repo::get_user(&self.persist_ctx, user_addr)
            .await
            .map_err(|err| {
                error!("Failed to get user {}", err);
                rpc::internal_error()
            })?
        else {
            return Ok(None);
        };

        let transactions = user.transactions.unwrap();
        let not_usable_deposit = transactions
            .iter()
            .filter_map(|tx| if !tx.finalized { Some(tx.amount) } else { None })
            .sum::<f64>();

        Ok(Some(UserInfo {
            deposit: user.deposit,
            available_deposit: user.deposit - not_usable_deposit,
            transactions: transactions.into_iter().map(|tx| tx.into()).collect(),
        }))
    }

    async fn issue_payment_cert(
        &self,
        user_addr: String,
        recipient_addr: String,
        transaction_id: String,
        amount: f64,
    ) -> RpcResult<BLSCert> {
        info!("Issuing cert for user: {user_addr}, recipient: {recipient_addr}, tx_hash: {transaction_id}, amount: {amount}");
        let provider = Arc::new(
            Provider::<Ws>::connect(&self.config.ethereum_config.ws_rpc_url)
                .await
                .map_err(|err| {
                    error!("Failed to connect to Ethereum provider: {err}");
                    rpc::internal_error()
                })?,
        );
        let tx_hash: H256 = transaction_id.parse().map_err(|err| {
            error!("Invalid transaction hash: {err}");
            rpc::invalid_params_error("Invalid transaction hash")
        })?;

        let tx = txtools::fetch_transaction(&provider, tx_hash).await?;

        let user_address = txtools::parse_eth_address(&user_addr, "user")?;
        let recipient_address = txtools::parse_eth_address(&recipient_addr, "recipient")?;
        let expected_amount = txtools::convert_amount_to_u256(amount)?;

        txtools::validate_transaction(&tx, user_address, recipient_address, expected_amount)?;

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

        let submit_tx_result = repo::submit_payment_transaction(
            &self.persist_ctx,
            user_addr.clone(),
            recipient_addr.clone(),
            transaction_id.clone(),
            amount,
            cert_str,
        )
        .await;

        if let Err(err) = submit_tx_result {
            let err = match err {
                SubmitPaymentTxnError::QueryError(query_error) => {
                    error!("{query_error}");
                    rpc::internal_error()
                }
                SubmitPaymentTxnError::UserNotRegistered
                | SubmitPaymentTxnError::NotEnoughDeposit
                // We should retry it ourselves if there was a conflict!
                | SubmitPaymentTxnError::ConflictingTransactions => {
                    rpc::invalid_params_error(&format!("{err}"))
                }
            };
            return Err(err);
        }

        Ok(cert)
    }

    async fn get_transactions_by_hash(
        &self,
        hashes: Vec<String>,
    ) -> RpcResult<Vec<UserTransactionInfo>> {
        let transactions = repo::get_transactions_by_hash(&self.persist_ctx, hashes)
            .await
            .map_err(|err| {
                error!("Failed to get user {}", err);
                rpc::internal_error()
            })?;

        Ok(transactions.into_iter().map(|tx| tx.into()).collect())
    }

    async fn verify_transaction(
        &self,
        tx_hash: String,
    ) -> RpcResult<TransactionVerificationResult> {
        let verified = repo::verify_transaction(&self.persist_ctx, tx_hash)
            .await
            .map_err(|err| {
                error!("Failed to verify transaction {}", err);
                rpc::internal_error()
            })?;

        Ok(verified)
    }
}
