use std::{fmt::Display, str::FromStr};

use alloy::signers::local::PrivateKeySigner;
use alloy::{
    network::Ethereum, primitives::Address, providers::PendingTransactionBuilder,
    rpc::types::TransactionReceipt, signers::Signer,
};

use crate::{
    auth::AuthTokens,
    config::{ClientBuilder, Config},
    error::{AuthError, ClientError},
};

use self::{
    account::AccountClient, deposit::DepositClient, payment::PaymentClient,
    settlement::SettlementClient, tokens::TokensClient, withdraw::WithdrawClient,
};

mod ctx;
mod facilitator;
mod sig;

pub mod account;
pub mod deposit;
pub mod model;
pub mod payment;
pub mod route;
pub mod settlement;
pub mod tokens;
pub mod withdraw;

pub(crate) use ctx::ClientCtx;

/// Waits for a sent transaction to be mined.
///
/// Broadcasting and waiting fail with different error types; folding them into the contract error
/// leaves callers a single `?` that decodes the revert into their own error.
pub(crate) async fn await_receipt(
    sent: Result<PendingTransactionBuilder<Ethereum>, alloy::contract::Error>,
) -> Result<TransactionReceipt, alloy::contract::Error> {
    sent?.get_receipt().await.map_err(Into::into)
}

/// Checks a value the facilitator echoed back against what was asked for, taking the request's own
/// value when the facilitator omits it.
///
/// Echoed fields exist for reconciliation, so one that disagrees — or that cannot be read — means
/// the receipt would describe a transaction nobody asked for. `mismatch` builds the error for that.
pub(crate) fn confirm_echoed<T, E>(
    field: &str,
    raw: Option<&str>,
    expected: T,
    mismatch: impl FnOnce(String) -> E,
) -> Result<T, E>
where
    T: FromStr + PartialEq + Display,
{
    let Some(raw) = raw else {
        return Ok(expected);
    };
    match raw.parse::<T>() {
        Ok(echoed) if echoed == expected => Ok(expected),
        _ => Err(mismatch(format!(
            "facilitator echoed {field} {raw}, expected {expected}"
        ))),
    }
}

/// Entry point to the SDK.
///
/// Each field is an intent-builder client: an entry captures what to do
/// (`client.deposit.of(…)`), a route pin narrows how (`.gasless()`, `.self_funded()`), and a
/// terminal does it (`.send()`, `.sign()`).
pub struct Client<S = PrivateKeySigner> {
    ctx: ClientCtx<S>,
    /// Depositing collateral, gasless or self-funded.
    pub deposit: DepositClient<S>,
    /// Requesting, cancelling and finalizing withdrawals.
    pub withdraw: WithdrawClient<S>,
    /// Signing, issuing and verifying payment guarantees.
    pub payment: PaymentClient<S>,
    /// Settling a clearing cycle, from either side.
    pub settlement: SettlementClient<S>,
    /// Reading the signer's own balances and positions.
    pub account: AccountClient<S>,
    /// Supported-token metadata and ERC-20 approvals.
    pub tokens: TokensClient<S>,
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
            tokens: self.tokens.clone(),
        }
    }
}

impl<S> Client<S> {
    /// Starts a [`ClientBuilder`]; finish with
    /// [`connect()`](crate::config::ClientBuilder::connect).
    pub fn builder() -> ClientBuilder<S> {
        ClientBuilder::default()
    }

    /// Connects with an already-built [`Config`]. Reaches core for its public parameters, which is
    /// why construction is fallible and async.
    pub async fn connect(cfg: Config<S>) -> Result<Self, ClientError>
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
            tokens: TokensClient::new(ctx.clone()),
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
}

#[cfg(test)]
mod tests {
    use alloy::primitives::U256;

    use super::*;

    /// The one echo that is not a disagreement: the facilitator said nothing about the field, which
    /// cannot contradict what was asked for.
    #[test]
    fn an_omitted_echo_takes_the_value_that_was_asked_for() {
        let expected = Address::repeat_byte(0x11);
        assert_eq!(
            confirm_echoed("user", None, expected, Mismatch).unwrap(),
            expected
        );
    }

    #[test]
    fn a_matching_echo_is_accepted_whatever_its_casing() {
        let expected = Address::repeat_byte(0x11);
        let lowercase = format!("{expected:?}").to_lowercase();

        assert_eq!(
            confirm_echoed("user", Some(&lowercase), expected, Mismatch).unwrap(),
            expected
        );
    }

    #[test]
    fn an_echo_that_disagrees_is_a_mismatch() {
        let other = format!("{:?}", Address::repeat_byte(0x22));

        let reported =
            confirm_echoed("user", Some(&other), Address::repeat_byte(0x11), Mismatch).unwrap_err();
        assert!(reported.0.contains(&other), "{}", reported.0);

        confirm_echoed("amount", Some("41"), U256::from(42), Mismatch).unwrap_err();
    }

    /// An echo that cannot be read is no confirmation that it matched.
    #[test]
    fn an_unparseable_echo_is_a_mismatch() {
        confirm_echoed("asset", Some("not-an-address"), Address::ZERO, Mismatch).unwrap_err();
        confirm_echoed("amount", Some("forty-two"), U256::from(42), Mismatch).unwrap_err();
    }

    #[derive(Debug)]
    struct Mismatch(String);
}
