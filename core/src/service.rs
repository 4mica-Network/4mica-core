use crate::config::AppConfig;
use crate::persist::repo::{CoreDatabaseConnector, EthereumConnector};
use crate::persist::PersistCtx;

use alloy::primitives::{Address, B256};
use alloy::providers::fillers::{
    BlobGasFiller, ChainIdFiller, FillProvider, GasFiller, JoinFill, NonceFiller,
};
use alloy::providers::{Identity, ProviderBuilder, RootProvider, WsConnect};
use async_trait::async_trait;
use futures_util::TryFutureExt;
use crypto::bls::BLSCert;
use log::{error, info};
use rpc::common::{
    PaymentGuaranteeClaims, TransactionVerificationResult, UserInfo, UserTransactionInfo,
};
use rpc::core::{CoreApiServer, CorePublicParameters};
use rpc::RpcResult;

type EthereumProvider = FillProvider<
    JoinFill<
        Identity,
        JoinFill<GasFiller, JoinFill<BlobGasFiller, JoinFill<NonceFiller, ChainIdFiller>>>,
    >,
    RootProvider,
>;

/// Convert a `&str` into an [`Address`].
pub fn string_to_address(val: &str) -> RpcResult<Address> {
    val
        .as_bytes()
        .try_into()
        .map_err(|_| rpc::invalid_params_error("Invalid address string"))
        .map(Address::new)
}

/// Convert a `&str` into a [`B256`].
///
/// Primarily useful in converting transaction hashes.
pub fn string_to_b256(val: &str) -> RpcResult<B256> {
    val
        .as_bytes()
        .try_into()
        .map_err(|_| rpc::invalid_params_error("Invalid B256 string"))
        .map(B256::new)
}

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

    /// Obtain a connection to the database
    pub async fn get_db_connector(&self) -> RpcResult<impl CoreDatabaseConnector> {
        Ok(EthereumConnector(self.get_ethereum_provider().await?))
    }

    /// Validate that a given [`UserTransactionInfo`] has a given `sender`, `recipient` and `amount`.
    pub fn validate_transaction(
        tx: &UserTransactionInfo,
        sender_address: &str,
        recipient_address: &str,
        amount: f64,
    ) -> RpcResult<()> {
        if tx.user_addr != sender_address {
            return Err(rpc::invalid_params_error(
                "User address does not match transaction sender",
            ));
        }

        if tx.recipient_addr != recipient_address {
            return Err(rpc::invalid_params_error(
                "Recipient address does not match transaction recipient",
            ));
        }

        if tx.amount != amount {
            return Err(rpc::invalid_params_error(
                "Transaction amount does not match",
            ));
        }

        Ok(())
    }
}

#[async_trait]
impl CoreApiServer for CoreService {
    async fn get_public_params(&self) -> RpcResult<CorePublicParameters> {
        Ok(self.public_params.clone())
    }

    async fn register_user(&self, user_addr: String) -> RpcResult<()> {
        // TODO(#10): implement when using REDIS as database
        Ok(())
    }

    async fn get_user(&self, user_addr: String) -> RpcResult<Option<UserInfo>> {
        let connector = self.get_db_connector().await?;
        let user_address = string_to_address(&user_addr)?;

        let total_deposit = connector.get_user_deposit_total(user_address)
            .map_err(|_| rpc::execution_failed("user not found"))
            .await?;

        let locked_deposit = connector.get_user_deposit_locked(user_address)
            .map_err(|_| rpc::execution_failed("user not found"))
            .await?;

        let user_transactions = connector
            .get_user_transactions_info(user_address)
            .map_err(|err| rpc::internal_error())
            .await?;

        Ok(Some(UserInfo {
            deposit: total_deposit,
            available_deposit: total_deposit - locked_deposit,
            transactions: user_transactions,
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

        let connector = self.get_db_connector().await?;

        let tx_hash = string_to_b256(&transaction_id)?;
        let tx = connector.get_transaction_info(tx_hash)
            .map_err(|_| rpc::invalid_params_error("Invalid transaction hash"))
            .await?;
        Self::validate_transaction(&tx, &user_addr, &recipient_addr, amount)?;

        let user_info = self
            .get_user(user_addr)
            .await?
            .ok_or(|_| Err(rpc::internal_error()))?;
        if user_info.available_deposit < amount {
            return Err(rpc::invalid_params_error("Not enough deposit available!"));
        }

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

        Ok(cert)
    }

    async fn get_transactions_by_hash(
        &self,
        hashes: Vec<String>,
    ) -> RpcResult<Vec<UserTransactionInfo>> {
        let hashes = hashes.into_iter().map(|hash| string_to_b256(&hash)).collect()?;
        self.get_db_connector()
            .await?
            .get_transactions_info(hashes)
            .await
            .map_err(|err| rpc::invalid_params_error("Invalid transactions"))
    }

    async fn verify_transaction(
        &self,
        tx_hash: String,
    ) -> RpcResult<TransactionVerificationResult> {
        // TODO(#10): implement when using REDIS as database
        Ok(TransactionVerificationResult::Verified)
    }
}
