//! Withdrawing collateral. A request opens a waiting period, after which it can be finalized —
//! or cancelled at any point before that.

use alloy::{
    network::TxSigner,
    primitives::U256,
    rpc::types::TransactionReceipt,
    signers::{Signature, Signer},
};

use crate::{
    client::{ClientCtx, model::Asset},
    error::{CancelWithdrawalError, FinalizeWithdrawalError, RequestWithdrawalError},
};

pub struct WithdrawClient<S> {
    ctx: ClientCtx<S>,
}

impl<S> Clone for WithdrawClient<S> {
    fn clone(&self) -> Self {
        Self {
            ctx: self.ctx.clone(),
        }
    }
}

impl<S> WithdrawClient<S> {
    pub(super) fn new(ctx: ClientCtx<S>) -> Self {
        Self { ctx }
    }
}

impl<S> WithdrawClient<S>
where
    S: Signer + TxSigner<Signature> + Send + Sync + Clone + 'static,
{
    /// Requests a withdrawal of `amount` of `asset`, starting its waiting period.
    pub async fn request(
        &self,
        asset: Asset,
        amount: U256,
    ) -> Result<TransactionReceipt, RequestWithdrawalError> {
        let contract = self.ctx.get_write_contract().await?;
        let send_result = match asset {
            Asset::Erc20(token) => contract.requestWithdrawal_1(token, amount).send().await,
            Asset::Native => contract.requestWithdrawal_0(amount).send().await,
        };

        send_result
            .map_err(RequestWithdrawalError::from)?
            .get_receipt()
            .await
            .map_err(alloy::contract::Error::from)
            .map_err(RequestWithdrawalError::from)
    }

    /// Cancels the pending withdrawal request for `asset`, returning the collateral to use.
    pub async fn cancel(&self, asset: Asset) -> Result<TransactionReceipt, CancelWithdrawalError> {
        let contract = self.ctx.get_write_contract().await?;
        let send_result = match asset {
            Asset::Erc20(token) => contract.cancelWithdrawal_1(token).send().await,
            Asset::Native => contract.cancelWithdrawal_0().send().await,
        };

        send_result
            .map_err(CancelWithdrawalError::from)?
            .get_receipt()
            .await
            .map_err(alloy::contract::Error::from)
            .map_err(CancelWithdrawalError::from)
    }

    /// Pays out a withdrawal request whose waiting period has elapsed.
    pub async fn finalize(
        &self,
        asset: Asset,
    ) -> Result<TransactionReceipt, FinalizeWithdrawalError> {
        let contract = self.ctx.get_write_contract().await?;
        let send_result = match asset {
            Asset::Erc20(token) => contract.finalizeWithdrawal_1(token).send().await,
            Asset::Native => contract.finalizeWithdrawal_0().send().await,
        };

        send_result
            .map_err(FinalizeWithdrawalError::from)?
            .get_receipt()
            .await
            .map_err(alloy::contract::Error::from)
            .map_err(FinalizeWithdrawalError::from)
    }
}
