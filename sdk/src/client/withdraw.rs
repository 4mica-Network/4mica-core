//! Withdrawing collateral. A request opens a waiting period, after which it can be finalized —
//! or cancelled at any point before that.
//!
//! Each step is an intent builder: [`WithdrawClient::request`], [`WithdrawClient::cancel`] and
//! [`WithdrawClient::finalize`] capture what to do, a route pin (`gasless()`, `self_funded()`)
//! narrows how, and a terminal (`send()`, `sign()`, `verify()`) does it. An authorization signed
//! elsewhere attaches to a gasless pin with `authorization(…)`. Unpinned, `send()` prefers the
//! gasless route and falls back to the user's own transaction. Every route applies to the signer,
//! so the choice only changes who pays — [`WithdrawReceipt::route`] reports which one ran.
//!
//! Finalization is the exception: it offers no `sign()`, because it needs no signature at all —
//! the payout goes to the user and the amount was fixed when they requested it. That matters here:
//! the grace period is weeks long, so requiring a fresh signature would mean being around to
//! produce one.

use std::marker::PhantomData;

use alloy::{
    network::TxSigner,
    primitives::{Address, B256, U256},
    rpc::types::TransactionReceipt,
    signers::{Signature, Signer},
};
use serde::{Deserialize, Serialize};

use crate::{
    client::{
        ClientCtx, await_receipt, confirm_echoed,
        facilitator::FacilitatorFailure,
        model::{Asset, Route, WithdrawReceipt},
        route, sig,
    },
    contract::Core4Mica::{WithdrawalCancelAuthorization, WithdrawalRequestAuthorization},
    error::{SponsorshipError, WithdrawError},
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

    /// Whether the gasless route is available at all. Callers that want to decide for themselves
    /// rather than let the auto route fall back can branch on this instead of on an error.
    pub fn is_gasless_available(&self) -> bool {
        self.ctx.facilitator().is_configured()
    }

    /// Starts a withdrawal request for `amount` of `asset`. Nothing happens until a terminal
    /// (`send()`, `sign()`, `verify()`) runs.
    pub fn request(&self, asset: Asset, amount: U256) -> RequestBuilder<S, route::Auto> {
        RequestBuilder {
            ctx: self.ctx.clone(),
            asset,
            amount,
            route: route::Auto,
        }
    }

    /// Starts a cancellation of the pending withdrawal request for `asset`.
    pub fn cancel(&self, asset: Asset) -> CancelBuilder<S, route::Auto> {
        CancelBuilder {
            ctx: self.ctx.clone(),
            asset,
            route: route::Auto,
        }
    }

    /// Starts a finalization of the elapsed withdrawal request for `asset`.
    pub fn finalize(&self, asset: Asset) -> FinalizeBuilder<S, route::Auto> {
        FinalizeBuilder {
            ctx: self.ctx.clone(),
            asset,
            _route: PhantomData,
        }
    }
}

/// A withdrawal request being built. Terminal signer bounds are per route: the gasless pin needs
/// only a [`Signer`], the self-funded pin a transaction signer too.
#[must_use = "a builder does nothing until a terminal method (`send`, `sign`, `verify`) runs"]
pub struct RequestBuilder<S, R = route::Auto> {
    ctx: ClientCtx<S>,
    asset: Asset,
    amount: U256,
    route: R,
}

impl<S, R> RequestBuilder<S, R> {
    fn with_route<T>(self, route: T) -> RequestBuilder<S, T> {
        RequestBuilder {
            ctx: self.ctx,
            asset: self.asset,
            amount: self.amount,
            route,
        }
    }
}

impl<S> RequestBuilder<S, route::Auto> {
    /// Pins the gasless route: the facilitator submits and pays, with no self-funded fallback.
    pub fn gasless(self) -> RequestBuilder<S, route::Gasless> {
        self.with_route(route::Gasless)
    }

    /// Pins the user's own transaction.
    pub fn self_funded(self) -> RequestBuilder<S, route::SelfFunded> {
        self.with_route(route::SelfFunded)
    }

    /// Requests the withdrawal, gaslessly where possible.
    ///
    /// Falls back to the user's own transaction when no facilitator is configured or the
    /// facilitator declines to sponsor. A rejection that names the request itself — an amount
    /// above the available balance, say — is returned rather than retried, since the user's own
    /// transaction would revert for the same reason after paying for the privilege.
    ///
    /// [`SponsorshipError::OutcomeUnknown`] is also returned rather than retried: the facilitator
    /// may have submitted the request already, and requesting again would overwrite it and restart
    /// the grace period. Read the pending request off the chain before deciding.
    ///
    /// Read [`WithdrawReceipt::route`] to see which route ran.
    pub async fn send(self) -> Result<WithdrawReceipt, WithdrawError>
    where
        S: Signer + TxSigner<Signature> + Send + Sync + Clone + 'static,
    {
        if !self.ctx.facilitator().is_configured() {
            return self.with_route(route::SelfFunded).send().await;
        }
        let gasless = RequestBuilder {
            ctx: self.ctx.clone(),
            asset: self.asset,
            amount: self.amount,
            route: route::Gasless,
        };
        match gasless.send().await {
            Err(err) if sponsorship_unavailable(&err) => {
                self.with_route(route::SelfFunded).send().await
            }
            outcome => outcome,
        }
    }
}

impl<S> RequestBuilder<S, route::Gasless> {
    /// Signs the request without submitting it, for callers that redeem it elsewhere — a hardware
    /// wallet, another process, or a later session. Redeem by attaching it to a fresh builder:
    /// `withdraw.request(asset, amount).gasless().authorization(auth).send()`.
    pub async fn sign(self) -> Result<WithdrawalRequestAuthorization, WithdrawError>
    where
        S: Signer + Send + Sync,
    {
        Ok(
            sig::request_withdrawal_authorization(&self.ctx, self.asset.address(), self.amount)
                .await?,
        )
    }

    /// Attaches a request authorization signed elsewhere. It is self-contained, so it need not
    /// have been signed here.
    pub fn authorization(
        self,
        authorization: WithdrawalRequestAuthorization,
    ) -> RequestBuilder<S, route::Authorized<WithdrawalRequestAuthorization>> {
        self.with_route(route::Authorized {
            auth: authorization,
        })
    }

    /// Requests the withdrawal gaslessly. The user needs no native balance and makes no
    /// transaction.
    ///
    /// Unlike a deposit this works for ETH too: Core4Mica verifies the signature itself rather
    /// than leaning on what the asset implements.
    pub async fn send(self) -> Result<WithdrawReceipt, WithdrawError>
    where
        S: Signer + Send + Sync,
    {
        let authorization =
            sig::request_withdrawal_authorization(&self.ctx, self.asset.address(), self.amount)
                .await?;
        let (user, asset) = (authorization.user, authorization.asset);
        Ok(submit(
            &self.ctx,
            WithdrawRequest::Request { authorization },
            user,
            asset,
        )
        .await?)
    }
}

impl<S> RequestBuilder<S, route::Authorized<WithdrawalRequestAuthorization>> {
    /// The authorization names its asset and amount, so a builder that disagrees with it would
    /// submit terms the caller never stated.
    fn checked(&self) -> Result<(), WithdrawError> {
        let auth = &self.route.auth;
        if auth.asset != self.asset.address() || auth.amount != self.amount {
            return Err(WithdrawError::InvalidParams(format!(
                "authorization signs {} of {}, but the builder asks {} of {}",
                auth.amount,
                auth.asset,
                self.amount,
                self.asset.address(),
            )));
        }
        Ok(())
    }

    /// Preflight: runs every check a real submission would run, without spending anyone's gas.
    ///
    /// Worth doing before handing an authorization to a user-facing flow, since it tells a
    /// permanently unusable authorization apart from a transient failure.
    pub async fn verify(&self) -> Result<(), WithdrawError> {
        self.checked()?;
        Ok(verify(
            &self.ctx,
            WithdrawRequest::Request {
                authorization: self.route.auth.clone(),
            },
        )
        .await?)
    }

    /// Requests the withdrawal with the attached authorization. The submitter needs no signer of
    /// their own.
    pub async fn send(self) -> Result<WithdrawReceipt, WithdrawError> {
        self.checked()?;
        let (user, asset) = (self.route.auth.user, self.route.auth.asset);
        Ok(submit(
            &self.ctx,
            WithdrawRequest::Request {
                authorization: self.route.auth,
            },
            user,
            asset,
        )
        .await?)
    }
}

impl<S> RequestBuilder<S, route::SelfFunded> {
    /// Requests the withdrawal with the user's own transaction, reported in the same shape as a
    /// gasless one.
    pub async fn send(self) -> Result<WithdrawReceipt, WithdrawError>
    where
        S: Signer + TxSigner<Signature> + Send + Sync + Clone + 'static,
    {
        let contract = self.ctx.get_write_contract().await?;
        let sent = match self.asset {
            Asset::Erc20(token) => {
                contract
                    .requestWithdrawal_1(token, self.amount)
                    .send()
                    .await
            }
            Asset::Native => contract.requestWithdrawal_0(self.amount).send().await,
        };

        Ok(self_funded_receipt(
            &self.ctx,
            await_receipt(sent).await?,
            self.asset,
        ))
    }
}

/// A withdrawal cancellation being built.
#[must_use = "a builder does nothing until a terminal method (`send`, `sign`, `verify`) runs"]
pub struct CancelBuilder<S, R = route::Auto> {
    ctx: ClientCtx<S>,
    asset: Asset,
    route: R,
}

impl<S, R> CancelBuilder<S, R> {
    fn with_route<T>(self, route: T) -> CancelBuilder<S, T> {
        CancelBuilder {
            ctx: self.ctx,
            asset: self.asset,
            route,
        }
    }
}

impl<S> CancelBuilder<S, route::Auto> {
    /// Pins the gasless route: the facilitator submits and pays, with no self-funded fallback.
    pub fn gasless(self) -> CancelBuilder<S, route::Gasless> {
        self.with_route(route::Gasless)
    }

    /// Pins the user's own transaction.
    pub fn self_funded(self) -> CancelBuilder<S, route::SelfFunded> {
        self.with_route(route::SelfFunded)
    }

    /// Cancels the pending withdrawal request, gaslessly where possible.
    pub async fn send(self) -> Result<WithdrawReceipt, WithdrawError>
    where
        S: Signer + TxSigner<Signature> + Send + Sync + Clone + 'static,
    {
        if !self.ctx.facilitator().is_configured() {
            return self.with_route(route::SelfFunded).send().await;
        }
        let gasless = CancelBuilder {
            ctx: self.ctx.clone(),
            asset: self.asset,
            route: route::Gasless,
        };
        match gasless.send().await {
            Err(err) if sponsorship_unavailable(&err) => {
                self.with_route(route::SelfFunded).send().await
            }
            outcome => outcome,
        }
    }
}

impl<S> CancelBuilder<S, route::Gasless> {
    /// Signs the cancellation without submitting it. Redeem by attaching it to a fresh builder:
    /// `withdraw.cancel(asset).gasless().authorization(auth).send()`.
    pub async fn sign(self) -> Result<WithdrawalCancelAuthorization, WithdrawError>
    where
        S: Signer + Send + Sync,
    {
        Ok(sig::cancel_withdrawal_authorization(&self.ctx, self.asset.address()).await?)
    }

    /// Attaches a cancellation authorization signed elsewhere.
    pub fn authorization(
        self,
        authorization: WithdrawalCancelAuthorization,
    ) -> CancelBuilder<S, route::Authorized<WithdrawalCancelAuthorization>> {
        self.with_route(route::Authorized {
            auth: authorization,
        })
    }

    /// Cancels the pending withdrawal request gaslessly.
    pub async fn send(self) -> Result<WithdrawReceipt, WithdrawError>
    where
        S: Signer + Send + Sync,
    {
        let authorization =
            sig::cancel_withdrawal_authorization(&self.ctx, self.asset.address()).await?;
        let (user, asset) = (authorization.user, authorization.asset);
        Ok(submit(
            &self.ctx,
            WithdrawRequest::Cancel { authorization },
            user,
            asset,
        )
        .await?)
    }
}

impl<S> CancelBuilder<S, route::Authorized<WithdrawalCancelAuthorization>> {
    /// The authorization names its asset, so a builder that disagrees with it would cancel a
    /// request the caller never stated.
    fn checked(&self) -> Result<(), WithdrawError> {
        let auth = &self.route.auth;
        if auth.asset != self.asset.address() {
            return Err(WithdrawError::InvalidParams(format!(
                "authorization cancels for {}, but the builder asks {}",
                auth.asset,
                self.asset.address(),
            )));
        }
        Ok(())
    }

    /// Preflight: runs every check a real submission would run, without spending anyone's gas.
    pub async fn verify(&self) -> Result<(), WithdrawError> {
        self.checked()?;
        Ok(verify(
            &self.ctx,
            WithdrawRequest::Cancel {
                authorization: self.route.auth.clone(),
            },
        )
        .await?)
    }

    /// Cancels the pending withdrawal request with the attached authorization. The submitter
    /// needs no signer of their own.
    pub async fn send(self) -> Result<WithdrawReceipt, WithdrawError> {
        self.checked()?;
        let (user, asset) = (self.route.auth.user, self.route.auth.asset);
        Ok(submit(
            &self.ctx,
            WithdrawRequest::Cancel {
                authorization: self.route.auth,
            },
            user,
            asset,
        )
        .await?)
    }
}

impl<S> CancelBuilder<S, route::SelfFunded> {
    /// Cancels with the user's own transaction.
    pub async fn send(self) -> Result<WithdrawReceipt, WithdrawError>
    where
        S: Signer + TxSigner<Signature> + Send + Sync + Clone + 'static,
    {
        let contract = self.ctx.get_write_contract().await?;
        let sent = match self.asset {
            Asset::Erc20(token) => contract.cancelWithdrawal_1(token).send().await,
            Asset::Native => contract.cancelWithdrawal_0().send().await,
        };

        Ok(self_funded_receipt(
            &self.ctx,
            await_receipt(sent).await?,
            self.asset,
        ))
    }
}

/// A withdrawal finalization being built. No `sign()` on any route: `finalizeWithdrawalFor` is
/// permissionless because it pays the user, so there is nothing to sign.
#[must_use = "a builder does nothing until a terminal method (`send`, `verify`) runs"]
/// `PhantomData` rather than a stored route: with no authorization to carry, no finalize state
/// holds data.
pub struct FinalizeBuilder<S, R = route::Auto> {
    ctx: ClientCtx<S>,
    asset: Asset,
    _route: PhantomData<R>,
}

impl<S, R> FinalizeBuilder<S, R> {
    fn with_route<T>(self) -> FinalizeBuilder<S, T> {
        FinalizeBuilder {
            ctx: self.ctx,
            asset: self.asset,
            _route: PhantomData,
        }
    }
}

impl<S> FinalizeBuilder<S, route::Auto> {
    /// Pins the gasless route: the facilitator submits and pays, with no self-funded fallback.
    pub fn gasless(self) -> FinalizeBuilder<S, route::Gasless> {
        self.with_route()
    }

    /// Pins the user's own transaction.
    pub fn self_funded(self) -> FinalizeBuilder<S, route::SelfFunded> {
        self.with_route()
    }

    /// Pays out the elapsed withdrawal request, gaslessly where possible.
    pub async fn send(self) -> Result<WithdrawReceipt, WithdrawError>
    where
        S: Signer + TxSigner<Signature> + Send + Sync + Clone + 'static,
    {
        if !self.ctx.facilitator().is_configured() {
            return self.with_route::<route::SelfFunded>().send().await;
        }
        let gasless = FinalizeBuilder {
            ctx: self.ctx.clone(),
            asset: self.asset,
            _route: PhantomData::<route::Gasless>,
        };
        match gasless.send().await {
            Err(err) if sponsorship_unavailable(&err) => {
                self.with_route::<route::SelfFunded>().send().await
            }
            outcome => outcome,
        }
    }
}

impl<S> FinalizeBuilder<S, route::Gasless> {
    /// Preflight: runs every check a real submission would run, without spending anyone's gas —
    /// worth more here than elsewhere, since finalization is the one step that can be refused
    /// purely by the clock.
    pub async fn verify(&self) -> Result<(), WithdrawError>
    where
        S: Signer,
    {
        let request = WithdrawRequest::Finalize {
            user: self.ctx.signer_address(),
            asset: self.asset.address(),
        };
        Ok(verify(&self.ctx, request).await?)
    }

    /// Finalizes gaslessly. Takes no signature: `finalizeWithdrawalFor` pays the user whoever
    /// submits it.
    pub async fn send(self) -> Result<WithdrawReceipt, WithdrawError>
    where
        S: Signer,
    {
        let (user, asset) = (self.ctx.signer_address(), self.asset.address());
        Ok(submit(
            &self.ctx,
            WithdrawRequest::Finalize { user, asset },
            user,
            asset,
        )
        .await?)
    }
}

impl<S> FinalizeBuilder<S, route::SelfFunded> {
    /// Finalizes with the user's own transaction.
    pub async fn send(self) -> Result<WithdrawReceipt, WithdrawError>
    where
        S: Signer + TxSigner<Signature> + Send + Sync + Clone + 'static,
    {
        let contract = self.ctx.get_write_contract().await?;
        let sent = match self.asset {
            Asset::Erc20(token) => contract.finalizeWithdrawal_1(token).send().await,
            Asset::Native => contract.finalizeWithdrawal_0().send().await,
        };

        Ok(self_funded_receipt(
            &self.ctx,
            await_receipt(sent).await?,
            self.asset,
        ))
    }
}

fn self_funded_receipt<S: Signer>(
    ctx: &ClientCtx<S>,
    receipt: TransactionReceipt,
    asset: Asset,
) -> WithdrawReceipt {
    WithdrawReceipt {
        tx_hash: receipt.transaction_hash,
        route: Route::SelfFunded,
        account: ctx.signer_address(),
        asset: asset.address(),
        network: None,
    }
}

/// `user` and `asset` are what the receipt falls back to when the facilitator does not echo them;
/// they must describe the same action the request does.
async fn submit<S>(
    ctx: &ClientCtx<S>,
    request: WithdrawRequest,
    user: Address,
    asset: Address,
) -> Result<WithdrawReceipt, SponsorshipError> {
    let response: WithdrawResponse = ctx.facilitator().post("withdraw", &request).await?;
    response.into_receipt(user, asset)
}

async fn verify<S>(ctx: &ClientCtx<S>, request: WithdrawRequest) -> Result<(), SponsorshipError> {
    let response: WithdrawVerifyResponse =
        ctx.facilitator().post("withdraw/verify", &request).await?;
    if response.is_valid {
        return Ok(());
    }
    Err(response
        .failure
        .into_sponsorship_error(response.invalid_reason))
}

/// Whether an error means "nobody sponsored this", as opposed to "this request is bad" or "we do
/// not know what happened".
///
/// Only the first is worth paying for a retry. A rejection that names the request itself would
/// revert the user's own transaction too, after they had already paid for it; an unknown outcome
/// might mean the facilitator already submitted, and a second `requestWithdrawal` would overwrite
/// the first and restart the grace period without anyone noticing.
fn sponsorship_unavailable(err: &WithdrawError) -> bool {
    match err {
        WithdrawError::Sponsorship(SponsorshipError::Rejected { code, .. }) => {
            !names_the_request(code)
        }
        WithdrawError::Sponsorship(SponsorshipError::OutcomeUnknown(_)) => false,
        WithdrawError::Sponsorship(_) => true,
        _ => false,
    }
}

/// Rejections that describe the request rather than the facilitator's willingness to pay. Retrying
/// these self-funded just burns the user's gas on a revert.
fn names_the_request(code: &str) -> bool {
    matches!(
        code,
        "INVALID_REQUEST"
            | "MALFORMED_SIGNATURE"
            | "SIGNATURE_MISMATCH"
            | "EXPIRED"
            | "NOT_YET_VALID"
            | "NONCE_ALREADY_USED"
            | "SIMULATION_REVERTED"
    )
}

/// Wire format for `POST /withdraw` and `POST /withdraw/verify`.
#[derive(Debug, Serialize)]
#[serde(
    tag = "action",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
enum WithdrawRequest {
    Request {
        authorization: WithdrawalRequestAuthorization,
    },
    Cancel {
        authorization: WithdrawalCancelAuthorization,
    },
    /// No authorization: `finalizeWithdrawalFor` is permissionless because it pays `user`.
    Finalize { user: Address, asset: Address },
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct WithdrawResponse {
    success: bool,
    tx_hash: Option<String>,
    network: Option<String>,
    user: Option<String>,
    asset: Option<String>,
    error: Option<String>,
    #[serde(flatten)]
    failure: FacilitatorFailure,
}

impl WithdrawResponse {
    /// `user` and `asset` fall back to what was asked for: they are echoed for reconciliation, and
    /// a facilitator that omits them has not changed what the contract did. One that echoes
    /// something else has, and the receipt is refused rather than made to describe it.
    fn into_receipt(
        self,
        user: Address,
        asset: Address,
    ) -> Result<WithdrawReceipt, SponsorshipError> {
        if !self.success {
            return Err(self.failure.into_sponsorship_error(self.error));
        }

        let tx_hash = self
            .tx_hash
            .as_deref()
            .and_then(|raw| raw.parse::<B256>().ok())
            .ok_or_else(|| {
                SponsorshipError::OutcomeUnknown(
                    "facilitator reported success without a txHash".into(),
                )
            })?;

        Ok(WithdrawReceipt {
            tx_hash,
            route: Route::Gasless,
            account: confirm_echoed(
                "user",
                self.user.as_deref(),
                user,
                SponsorshipError::OutcomeUnknown,
            )?,
            asset: confirm_echoed(
                "asset",
                self.asset.as_deref(),
                asset,
                SponsorshipError::OutcomeUnknown,
            )?,
            network: self.network,
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct WithdrawVerifyResponse {
    is_valid: bool,
    invalid_reason: Option<String>,
    #[serde(flatten)]
    failure: FacilitatorFailure,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rejected(code: &str) -> WithdrawError {
        SponsorshipError::Rejected {
            code: code.into(),
            message: "nope".into(),
            retryable: false,
        }
        .into()
    }

    #[test]
    fn a_missing_facilitator_falls_back_to_self_funding() {
        let err: WithdrawError = SponsorshipError::NotConfigured.into();
        assert!(sponsorship_unavailable(&err));
    }

    #[test]
    fn throttling_falls_back_to_self_funding() {
        assert!(sponsorship_unavailable(&rejected("RATE_LIMITED")));
        assert!(sponsorship_unavailable(&rejected(
            "RELAYER_BALANCE_TOO_LOW"
        )));
    }

    /// The user's own transaction would revert for the same reason, so falling back would cost them
    /// gas to learn what the facilitator already told them for free.
    #[test]
    fn a_rejection_naming_the_request_does_not_fall_back() {
        assert!(!sponsorship_unavailable(&rejected("SIMULATION_REVERTED")));
        assert!(!sponsorship_unavailable(&rejected("SIGNATURE_MISMATCH")));
        assert!(!sponsorship_unavailable(&rejected("EXPIRED")));
    }

    /// A code this SDK predates is treated as "the facilitator would not pay", which costs the user
    /// one transaction at worst and keeps a new facilitator rejection from stranding them.
    #[test]
    fn an_unknown_code_falls_back_to_self_funding() {
        assert!(sponsorship_unavailable(&rejected("SOMETHING_NEW")));
    }

    /// Every step has something to lose from a second transaction it did not need: a request would
    /// overwrite the first and restart the grace period, while a cancel or a finalize would revert
    /// and report failure for a step that worked.
    #[test]
    fn an_unknown_outcome_does_not_fall_back() {
        let unknown: WithdrawError = SponsorshipError::OutcomeUnknown("timed out".into()).into();
        assert!(!sponsorship_unavailable(&unknown));
    }

    /// A request that never reached the facilitator cannot have been submitted.
    #[test]
    fn an_undelivered_request_falls_back_to_self_funding() {
        let undelivered: WithdrawError =
            SponsorshipError::Transport("connection refused".into()).into();
        assert!(sponsorship_unavailable(&undelivered));
    }

    #[test]
    fn a_local_failure_is_not_a_sponsorship_problem() {
        assert!(!sponsorship_unavailable(&WithdrawError::AmountZero));
    }
}
