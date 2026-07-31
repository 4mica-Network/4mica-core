use alloy::{primitives::Address, signers::Signer};
use rpc::{ApiClientError, SupportedTokensResponse};

use crate::{
    auth::AuthTokens,
    config::Config,
    error::{AuthError, ClientError},
};

use self::{
    account::AccountClient, deposit::DepositClient, payment::PaymentClient,
    settlement::SettlementClient, withdraw::WithdrawClient,
};

mod ctx;
mod facilitator;
mod sig;

pub mod account;
pub mod deposit;
pub mod model;
pub mod payment;
pub mod settlement;
pub mod withdraw;

pub(crate) use ctx::ClientCtx;

/// Entry point to the SDK
pub struct Client<S> {
    ctx: ClientCtx<S>,
    /// Depositing collateral, sponsored or self-funded.
    pub deposit: DepositClient<S>,
    /// Requesting, cancelling and finalizing withdrawals.
    pub withdraw: WithdrawClient<S>,
    /// Signing, issuing and verifying payment guarantees.
    pub payment: PaymentClient<S>,
    /// Settling a clearing cycle, from either side.
    pub settlement: SettlementClient<S>,
    /// Reading the signer's own balances and positions.
    pub account: AccountClient<S>,
}

impl<S: Clone> Clone for Client<S> {
    fn clone(&self) -> Self {
        Self {
            ctx: self.ctx.clone(),
            deposit: self.deposit.clone(),
            withdraw: self.withdraw.clone(),
            payment: self.payment.clone(),
            settlement: self.settlement.clone(),
            account: self.account.clone(),
        }
    }
}

impl<S> Client<S> {
    pub async fn new(cfg: Config<S>) -> Result<Self, ClientError>
    where
        S: Signer + Sync + Clone,
    {
        let ctx = ClientCtx::new(cfg).await?;

        Ok(Self {
            deposit: DepositClient::new(ctx.clone()),
            withdraw: WithdrawClient::new(ctx.clone()),
            payment: PaymentClient::new(ctx.clone()),
            settlement: SettlementClient::new(ctx.clone()),
            account: AccountClient::new(ctx.clone()),
            ctx,
        })
    }

    /// The address this client signs as, and therefore the account every deposit credits.
    ///
    /// Saves callers from keeping the signer alongside the client just to recover its address.
    pub fn signer_address(&self) -> Address
    where
        S: Signer,
    {
        self.ctx.signer_address()
    }

    pub async fn login(&self) -> Result<AuthTokens, AuthError>
    where
        S: Signer + Sync,
    {
        self.ctx.login().await
    }

    /// The assets that can be deposited, with the metadata needed to sign for them.
    pub async fn supported_tokens(&self) -> Result<SupportedTokensResponse, ApiClientError> {
        self.ctx.supported_tokens().await
    }
}
