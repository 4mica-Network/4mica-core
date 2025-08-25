use alloy::contract::{ContractInstance, Interface};
use alloy::dyn_abi::DynSolValue;
use alloy::json_abi::JsonAbi;
use alloy::primitives::{address, Address, TxHash, B256};
use alloy::primitives::utils::format_units;
use alloy::providers::fillers::{BlobGasFiller, ChainIdFiller, FillProvider, GasFiller, JoinFill, NonceFiller};
use alloy::providers::{Identity, RootProvider};
use alloy::sol;
use futures_util::future::join_all;
use crate::persist::prisma::{user, user_transaction};
use crate::persist::PersistCtx;
use prisma_client_rust::QueryError;
use rpc::common::{TransactionVerificationResult, UserTransactionInfo};
use thiserror::Error;
use blockchain::txtools::fetch_transaction;
pub(crate) use crate::persist::connector::CoreDatabaseConnector;

// TODO: this is a duplicate from elsewhere
type EthereumProvider = FillProvider<
    JoinFill<
        Identity,
        JoinFill<GasFiller, JoinFill<BlobGasFiller, JoinFill<NonceFiller, ChainIdFiller>>>,
    >,
    RootProvider,
>;

pub(crate) struct EthereumConnector(pub(crate) EthereumProvider);

// TODO: load core contract address from .env
const CORE_CONTRACT_ADDRESS_4MICA: Address = address!("1234123412341234123412341234123412341234");

// TODO: fix ABI path
sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    Core4MicaContract,
    "../contracts/src/core/AuthorityContract.json"
);

impl EthereumConnector {
    /// Obtain the 4MICA Core Contract.
    fn get_core_contract(&self) -> anyhow::Result<ContractInstance<EthereumProvider>> {
        Core4MicaContract::new(CORE_CONTRACT_ADDRESS_4MICA, self.0.clone())
    }
}

impl CoreDatabaseConnector for EthereumConnector {
    /// Get the total deposit posted by the user associated with `user_address`.
    ///
    /// Note: the returned value is the total deposit, i.e., the sum of locked and available.
    async fn get_user_deposit_total(&self, user_address: String) -> anyhow::Result<f64> {
        let user_address = DynSolValue::from(user_address);
        let user = self
            .get_core_contract()?
            .function("users", &[user_address])?
            .call()
            .await?
            .first()
            .ok_or(anyhow::Error::msg("user not registered"))?
            .as_custom_struct()
            .ok_or(anyhow::Error::msg("internal error: failed to convert collateral to f64"))?;

        // TODO: quit hardcoding field indices
        let collateral = user.2[1]
            .as_uint()
            .ok_or(anyhow::Error::msg("internal error: failed to convert collateral to f64"))?
            .0;

        format_units(collateral, "eth")?
            .parse::<f64>()
            .map_err(anyhow::Error::new)
    }

    /// Get the [`TransactionDetails`] of all [`Transaction`] associated with `user_address`.
    async fn get_user_transaction_details(&self, user_address: String) -> anyhow::Result<Vec<UserTransactionInfo>> {
        let user_address = DynSolValue::from(user_address);
        let transaction_hashes = self.get_core_contract()?
            // TODO: fix function name
            .function("transactions", &[user_address])?
            .call()
            .await?;

        let transaction_details =transaction_hashes.iter()
            .map(|tx_hash| B256::from(tx_hash.as_uint().expect("valid transaction").0))
            .map(async |tx_hash| {
                self.get_transaction_details(tx_hash)
                    .await
                    .map_err(|_| anyhow::Error::msg(format!("invalid transaction: {tx_hash}")))
            });

        join_all(transaction_details)
            .await
            .into_iter()
            .collect()
    }

    /// Obtain the [`TransactionDetails`] for the transaction with hash `tx_hash`.
    async fn get_transaction_details(&self, tx_hash: TxHash) -> anyhow::Result<UserTransactionInfo> {
        let raw_tx = fetch_transaction(&self.0, tx_hash).await?;

        // TODO: convert into UserTransactionInfo
        Ok(())
    }
}

pub async fn register_user(ctx: &PersistCtx, user_addr: String) -> anyhow::Result<()> {
    let _ = ctx
        .client
        .user()
        .upsert(
            user::address::equals(user_addr.clone()),
            user::create(user_addr, vec![]),
            vec![],
        )
        .exec()
        .await?;
    Ok(())
}

pub async fn get_user(ctx: &PersistCtx, user_addr: String) -> anyhow::Result<Option<user::Data>> {
    let user = ctx
        .client
        .user()
        .find_unique(user::address::equals(user_addr))
        .with(user::transactions::fetch(vec![]))
        .exec()
        .await?;
    Ok(user)
}

pub async fn register_user_with_deposit(
    ctx: &PersistCtx,
    user_addr: String,
    deposit: f64,
) -> anyhow::Result<()> {
    let _ = ctx
        .client
        .user()
        .upsert(
            user::address::equals(user_addr.clone()),
            user::create(user_addr, vec![user::deposit::set(deposit)]),
            vec![user::deposit::set(deposit), user::version::increment(1)],
        )
        .exec()
        .await?;
    Ok(())
}

pub async fn add_user_deposit(
    ctx: &PersistCtx,
    user_addr: String,
    deposit: f64,
) -> anyhow::Result<()> {
    let _ = ctx
        .client
        .user()
        .update(
            user::address::equals(user_addr),
            vec![user::deposit::increment(deposit)],
        )
        .exec()
        .await?;
    Ok(())
}

pub async fn get_transactions_by_hash(
    ctx: &PersistCtx,
    hashes: Vec<String>,
) -> anyhow::Result<Vec<user_transaction::Data>> {
    let transactions = ctx
        .client
        .user_transaction()
        .find_many(vec![user_transaction::tx_id::in_vec(hashes)])
        .exec()
        .await?;
    Ok(transactions)
}

pub async fn get_unfinalized_transactions(
    ctx: &PersistCtx,
) -> anyhow::Result<Vec<user_transaction::Data>> {
    let transactions = ctx
        .client
        .user_transaction()
        .find_many(vec![user_transaction::finalized::equals(false)])
        .exec()
        .await?;
    Ok(transactions)
}

pub async fn confirm_transaction(ctx: &PersistCtx, transaction_hash: String) -> anyhow::Result<()> {
    let _updated_transactions = ctx
        .client
        .user_transaction()
        .update(
            user_transaction::tx_id::equals(transaction_hash),
            vec![user_transaction::finalized::set(true)],
        )
        .exec()
        .await?;
    Ok(())
}

#[derive(Debug, Error)]
pub enum SubmitPaymentTxnError {
    #[error("Internal query error occurred: {0:?}")]
    QueryError(#[from] QueryError),

    #[error("User is not registered yet!")]
    UserNotRegistered,

    #[error("Not enough deposit available!")]
    NotEnoughDeposit,

    #[error("Found conflicting transactions!")]
    ConflictingTransactions,
}

pub async fn submit_payment_transaction(
    ctx: &PersistCtx,
    user_addr: String,
    recipient_address: String,
    transaction_id: String,
    amount: f64,
    cert: String,
) -> Result<(), SubmitPaymentTxnError> {
    ctx.client
        ._transaction()
        .run::<SubmitPaymentTxnError, _, _, _>(|client| async move {
            let Some(user) = client
                .user()
                .find_unique(user::address::equals(user_addr.clone()))
                // Fetching the user's not-yet-finalized transactions
                .with(user::transactions::fetch(vec![
                    user_transaction::finalized::equals(false),
                    user_transaction::tx_id::not(transaction_id.clone()),
                ]))
                .exec()
                .await?
            else {
                return Err(SubmitPaymentTxnError::UserNotRegistered);
            };

            let transactions = user.transactions.unwrap();
            let not_usable_deposit = transactions.iter().map(|tx| tx.amount).sum::<f64>();

            if not_usable_deposit + amount > user.deposit {
                return Err(SubmitPaymentTxnError::NotEnoughDeposit);
            }

            client
                .user_transaction()
                .upsert(
                    user_transaction::tx_id::equals(transaction_id.clone()),
                    user_transaction::create(
                        transaction_id,
                        recipient_address,
                        amount,
                        user::address::equals(user_addr.clone()),
                        vec![user_transaction::cert::set(Some(cert))],
                    ),
                    vec![],
                )
                .exec()
                .await?;

            // For now, we implement the optimistic lock strategy using the user's version, because prisma
            //  doesn't support SELECT FOR UPDATE yet.
            let updated_user = client
                .user()
                .update(
                    user::address::equals(user_addr),
                    vec![user::version::increment(1)],
                )
                .exec()
                .await?;

            // There was a conflicting version, so we return error here...
            if updated_user.version != user.version + 1 {
                return Err(SubmitPaymentTxnError::ConflictingTransactions);
            }

            Ok(())
        })
        .await?;

    Ok(())
}

pub async fn fail_transaction(
    ctx: &PersistCtx,
    user_addr: String,
    transaction_id: String,
) -> anyhow::Result<()> {
    ctx.client
        ._transaction()
        .run::<QueryError, _, _, _>(|client| async move {
            let updated_tx = client
                .user_transaction()
                .update(
                    user_transaction::tx_id::equals(transaction_id),
                    vec![
                        user_transaction::finalized::set(true),
                        user_transaction::failed::set(true),
                    ],
                )
                .exec()
                .await?;

            client
                .user()
                .update(
                    user::address::equals(user_addr),
                    vec![user::deposit::decrement(updated_tx.amount)],
                )
                .exec()
                .await?;

            Ok(())
        })
        .await?;

    Ok(())
}

pub async fn verify_transaction(
    ctx: &PersistCtx,
    transaction_id: String,
) -> anyhow::Result<TransactionVerificationResult> {
    let result = ctx
        .client
        ._transaction()
        .run::<QueryError, _, _, _>(|client| async move {
            let tx = client
                .user_transaction()
                .find_unique(user_transaction::tx_id::equals(transaction_id.clone()))
                .exec()
                .await?;

            let Some(tx) = tx else {
                return Ok(TransactionVerificationResult::NotFound);
            };

            if tx.verified {
                return Ok(TransactionVerificationResult::AlreadyVerified);
            }

            // Mark the transaction as verified
            client
                .user_transaction()
                .update(
                    user_transaction::tx_id::equals(transaction_id),
                    vec![user_transaction::verified::set(true)],
                )
                .exec()
                .await?;

            Ok(TransactionVerificationResult::Verified)
        })
        .await?;

    Ok(result)
}
