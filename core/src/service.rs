use crate::config::AppConfig;
use crate::ethereum::EthereumListener;
use crate::persist::repo::{self, SubmitPaymentTxnError};
use crate::persist::PersistCtx;
use async_trait::async_trait;
use crypto::bls::BLSCert;
use log::{error, info};
use rpc::common::{PaymentGuaranteeClaims, UserInfo};
use rpc::core::{CoreApiServer, CorePublicParameters};
use rpc::RpcResult;

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
        transaction_id: String,
        amount: f64,
    ) -> RpcResult<BLSCert> {
        // TODO: Make sure the user_pk is the source of this transaction.
        // TODO: Listen to blockchain events and update the status of transactions.

        let submit_tx_result = repo::submit_payment_transaction(
            &self.persist_ctx,
            user_addr.clone(),
            transaction_id.clone(),
            amount,
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

        let claims = PaymentGuaranteeClaims {
            user_addr,
            tx_hash: transaction_id,
            amount,
        };
        let cert = BLSCert::new(&self.config.secrets.bls_private_key, claims).map_err(|err| {
            error!("Failed to issue the payment guarantee cert: {err}");
            rpc::internal_error()
        })?;

        Ok(cert)
    }
}
