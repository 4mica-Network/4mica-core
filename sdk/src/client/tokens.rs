//! Token utilities shared by the deposit and settlement flows.

use alloy::{
    network::TxSigner,
    primitives::{Address, U256},
    rpc::types::TransactionReceipt,
    signers::{Signature, Signer},
};
use rpc::SupportedTokensResponse;

use crate::{
    client::{ClientCtx, await_receipt},
    error::TokenError,
};

pub struct TokensClient<S> {
    ctx: ClientCtx<S>,
}

impl<S> Clone for TokensClient<S> {
    fn clone(&self) -> Self {
        Self {
            ctx: self.ctx.clone(),
        }
    }
}

impl<S> TokensClient<S> {
    pub(super) fn new(ctx: ClientCtx<S>) -> Self {
        Self { ctx }
    }

    /// The assets that can be deposited, with the metadata needed to sign for them.
    pub async fn supported(&self) -> Result<SupportedTokensResponse, TokenError> {
        Ok(self.ctx.supported_tokens().await?)
    }
}

impl<S> TokensClient<S>
where
    S: Signer + TxSigner<Signature> + Send + Sync + Clone + 'static,
{
    /// Allows the 4Mica contract to spend `amount` of `token` on the signer's behalf.
    ///
    /// Only self-funded deposits need this; gasless routes carry their own authorization — and a
    /// deposit builder resolves the same approval itself via `deposit.of(…).self_funded().approve()`.
    /// For the contract that settles a clearing cycle, use
    /// `settlement.pay(…).self_funded().approve()` instead.
    pub async fn approve(
        &self,
        token: Address,
        amount: U256,
    ) -> Result<TransactionReceipt, TokenError> {
        let spender = self.ctx.contract_address();
        let contract = self.ctx.get_erc20_write_contract(token).await?;

        Ok(await_receipt(contract.approve(spender, amount).send().await).await?)
    }
}
