//! Withdrawing collateral. A request opens a waiting period, after which it can be finalized —
//! or cancelled at any point before that.
//!
//! Each step either costs the user a transaction or it does not. On the sponsored route the user
//! signs an EIP-712 authorization that the facilitator submits and pays for; on the self-funded
//! route they send it themselves. Every route applies to the signer, so the choice only changes who
//! pays — [`WithdrawReceipt::path`] reports which one ran.
//!
//! Finalization is the exception: it needs no signature at all, because the payout goes to the user
//! and the amount was fixed when they requested it. That matters here — the grace period is weeks
//! long, so requiring a fresh signature would mean being around to produce one.

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
        model::{Asset, WithdrawPath, WithdrawReceipt},
        sig,
    },
    contract::Core4Mica::{WithdrawalCancelAuthorization, WithdrawalRequestAuthorization},
    error::{
        CancelWithdrawalError, FinalizeWithdrawalError, RequestWithdrawalError, SponsorshipError,
    },
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

    /// Whether the sponsored route is available at all. Callers that want to decide for themselves
    /// rather than let the `*_gasless` methods fall back can branch on this instead of on an error.
    pub fn is_gasless_available(&self) -> bool {
        self.ctx.facilitator().is_configured()
    }
}

impl<S> WithdrawClient<S>
where
    S: Signer + Send + Sync,
{
    /// Requests a withdrawal of `amount` of `asset` gaslessly. The user needs no native balance and
    /// makes no transaction.
    ///
    /// Unlike a deposit this works for ETH too: Core4Mica verifies the signature itself rather than
    /// leaning on what the asset implements.
    pub async fn request_gasless(
        &self,
        asset: Asset,
        amount: U256,
    ) -> Result<WithdrawReceipt, RequestWithdrawalError> {
        let authorization = self.sign_request(asset, amount).await?;
        self.submit_request(authorization).await
    }

    /// Cancels the pending withdrawal request for `asset` gaslessly.
    pub async fn cancel_gasless(
        &self,
        asset: Asset,
    ) -> Result<WithdrawReceipt, CancelWithdrawalError> {
        let authorization = self.sign_cancel(asset).await?;
        self.submit_cancel(authorization).await
    }

    /// Finalizes the elapsed withdrawal request for `asset` gaslessly.
    ///
    /// Takes no signature: `finalizeWithdrawalFor` pays the user whoever submits it.
    pub async fn finalize_gasless(
        &self,
        asset: Asset,
    ) -> Result<WithdrawReceipt, FinalizeWithdrawalError> {
        let (user, asset) = (self.ctx.signer_address(), asset.address());
        Ok(self
            .submit(WithdrawRequest::Finalize { user, asset }, user, asset)
            .await?)
    }

    /// Signs a withdrawal request without submitting it, for callers that redeem it elsewhere — a
    /// hardware wallet, another process, or a later session.
    pub async fn sign_request(
        &self,
        asset: Asset,
        amount: U256,
    ) -> Result<WithdrawalRequestAuthorization, RequestWithdrawalError> {
        Ok(sig::request_withdrawal_authorization(&self.ctx, asset.address(), amount).await?)
    }

    /// Signs a cancellation without submitting it.
    pub async fn sign_cancel(
        &self,
        asset: Asset,
    ) -> Result<WithdrawalCancelAuthorization, CancelWithdrawalError> {
        Ok(sig::cancel_withdrawal_authorization(&self.ctx, asset.address()).await?)
    }

    /// Submits a withdrawal request signed elsewhere. The authorization is self-contained, so it
    /// need not have been signed here.
    pub async fn submit_request(
        &self,
        authorization: WithdrawalRequestAuthorization,
    ) -> Result<WithdrawReceipt, RequestWithdrawalError> {
        let (user, asset) = (authorization.user, authorization.asset);
        Ok(self
            .submit(WithdrawRequest::Request { authorization }, user, asset)
            .await?)
    }

    /// Submits a cancellation signed elsewhere.
    pub async fn submit_cancel(
        &self,
        authorization: WithdrawalCancelAuthorization,
    ) -> Result<WithdrawReceipt, CancelWithdrawalError> {
        let (user, asset) = (authorization.user, authorization.asset);
        Ok(self
            .submit(WithdrawRequest::Cancel { authorization }, user, asset)
            .await?)
    }

    /// Preflight: runs every check a real submission would run, without spending anyone's gas.
    ///
    /// Worth doing before handing an authorization to a user-facing flow, since it tells a
    /// permanently unusable authorization apart from a transient failure.
    pub async fn verify_request(
        &self,
        authorization: WithdrawalRequestAuthorization,
    ) -> Result<(), RequestWithdrawalError> {
        Ok(self
            .verify(WithdrawRequest::Request { authorization })
            .await?)
    }

    /// Preflight for a cancellation. See [`Self::verify_request`].
    pub async fn verify_cancel(
        &self,
        authorization: WithdrawalCancelAuthorization,
    ) -> Result<(), CancelWithdrawalError> {
        Ok(self
            .verify(WithdrawRequest::Cancel { authorization })
            .await?)
    }

    /// Preflight for a finalization — worth more here than elsewhere, since it is the one step that
    /// can be refused purely by the clock.
    pub async fn verify_finalize(&self, asset: Asset) -> Result<(), FinalizeWithdrawalError> {
        let request = WithdrawRequest::Finalize {
            user: self.ctx.signer_address(),
            asset: asset.address(),
        };
        Ok(self.verify(request).await?)
    }

    /// `user` and `asset` are what the receipt falls back to when the facilitator does not echo
    /// them; they must describe the same action the request does.
    async fn submit(
        &self,
        request: WithdrawRequest,
        user: Address,
        asset: Address,
    ) -> Result<WithdrawReceipt, SponsorshipError> {
        let response: WithdrawResponse = self.ctx.facilitator().post("withdraw", &request).await?;
        response.into_receipt(user, asset)
    }

    async fn verify(&self, request: WithdrawRequest) -> Result<(), SponsorshipError> {
        let response: WithdrawVerifyResponse = self
            .ctx
            .facilitator()
            .post("withdraw/verify", &request)
            .await?;
        if response.is_valid {
            return Ok(());
        }
        Err(response
            .failure
            .into_sponsorship_error(response.invalid_reason))
    }
}

impl<S> WithdrawClient<S>
where
    S: Signer + TxSigner<Signature> + Send + Sync + Clone + 'static,
{
    /// Requests a withdrawal of `amount` of `asset`, sponsored where possible.
    ///
    /// Falls back to the user's own transaction when no facilitator is configured or the
    /// facilitator declines to sponsor. A rejection that names the request itself — an amount above
    /// the available balance, say — is returned rather than retried, since the user's own
    /// transaction would revert for the same reason after paying for the privilege.
    ///
    /// [`SponsorshipError::OutcomeUnknown`] is also returned rather than retried: the facilitator
    /// may have submitted the request already, and requesting again would overwrite it and restart
    /// the grace period. Read the pending request off the chain before deciding.
    ///
    /// Read [`WithdrawReceipt::path`] to see which route ran.
    pub async fn request(
        &self,
        asset: Asset,
        amount: U256,
    ) -> Result<WithdrawReceipt, RequestWithdrawalError> {
        if !self.is_gasless_available() {
            return self.request_self_funded(asset, amount).await;
        }
        match self.request_gasless(asset, amount).await {
            Err(err) if err.sponsorship_unavailable() => {
                self.request_self_funded(asset, amount).await
            }
            outcome => outcome,
        }
    }

    /// Cancels the pending withdrawal request for `asset`, sponsored where possible.
    pub async fn cancel(&self, asset: Asset) -> Result<WithdrawReceipt, CancelWithdrawalError> {
        if !self.is_gasless_available() {
            return self.cancel_self_funded(asset).await;
        }
        match self.cancel_gasless(asset).await {
            Err(err) if err.sponsorship_unavailable() => self.cancel_self_funded(asset).await,
            outcome => outcome,
        }
    }

    /// Pays out a withdrawal request whose waiting period has elapsed, sponsored where possible.
    pub async fn finalize(&self, asset: Asset) -> Result<WithdrawReceipt, FinalizeWithdrawalError> {
        if !self.is_gasless_available() {
            return self.finalize_self_funded(asset).await;
        }
        match self.finalize_gasless(asset).await {
            Err(err) if err.sponsorship_unavailable() => self.finalize_self_funded(asset).await,
            outcome => outcome,
        }
    }

    /// Requests a withdrawal with the user's own transaction, reported in the same shape as a
    /// sponsored one.
    pub async fn request_self_funded(
        &self,
        asset: Asset,
        amount: U256,
    ) -> Result<WithdrawReceipt, RequestWithdrawalError> {
        let contract = self.ctx.get_write_contract().await?;
        let sent = match asset {
            Asset::Erc20(token) => contract.requestWithdrawal_1(token, amount).send().await,
            Asset::Native => contract.requestWithdrawal_0(amount).send().await,
        };

        Ok(self.self_funded_receipt(await_receipt(sent).await?, asset))
    }

    /// Cancels with the user's own transaction.
    pub async fn cancel_self_funded(
        &self,
        asset: Asset,
    ) -> Result<WithdrawReceipt, CancelWithdrawalError> {
        let contract = self.ctx.get_write_contract().await?;
        let sent = match asset {
            Asset::Erc20(token) => contract.cancelWithdrawal_1(token).send().await,
            Asset::Native => contract.cancelWithdrawal_0().send().await,
        };

        Ok(self.self_funded_receipt(await_receipt(sent).await?, asset))
    }

    /// Finalizes with the user's own transaction.
    pub async fn finalize_self_funded(
        &self,
        asset: Asset,
    ) -> Result<WithdrawReceipt, FinalizeWithdrawalError> {
        let contract = self.ctx.get_write_contract().await?;
        let sent = match asset {
            Asset::Erc20(token) => contract.finalizeWithdrawal_1(token).send().await,
            Asset::Native => contract.finalizeWithdrawal_0().send().await,
        };

        Ok(self.self_funded_receipt(await_receipt(sent).await?, asset))
    }

    fn self_funded_receipt(&self, receipt: TransactionReceipt, asset: Asset) -> WithdrawReceipt {
        WithdrawReceipt {
            tx_hash: receipt.transaction_hash,
            path: WithdrawPath::SelfFunded,
            user: self.ctx.signer_address(),
            asset: asset.address(),
            network: None,
        }
    }
}

/// Whether an error means "nobody sponsored this", as opposed to "this request is bad" or "we do
/// not know what happened".
///
/// Only the first is worth paying for a retry. A rejection that names the request itself would
/// revert the user's own transaction too, after they had already paid for it; an unknown outcome
/// might mean the facilitator already submitted, and a second `requestWithdrawal` would overwrite
/// the first and restart the grace period without anyone noticing.
trait SponsorshipUnavailable {
    fn sponsorship_unavailable(&self) -> bool;
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

macro_rules! impl_sponsorship_unavailable {
    ($error:ty) => {
        impl SponsorshipUnavailable for $error {
            fn sponsorship_unavailable(&self) -> bool {
                match self {
                    Self::Sponsorship(SponsorshipError::Rejected { code, .. }) => {
                        !names_the_request(code)
                    }
                    Self::Sponsorship(SponsorshipError::OutcomeUnknown(_)) => false,
                    Self::Sponsorship(_) => true,
                    _ => false,
                }
            }
        }
    };
}

impl_sponsorship_unavailable!(RequestWithdrawalError);
impl_sponsorship_unavailable!(CancelWithdrawalError);
impl_sponsorship_unavailable!(FinalizeWithdrawalError);

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
            path: WithdrawPath::Sponsored,
            user: confirm_echoed(
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

    fn rejected(code: &str) -> RequestWithdrawalError {
        SponsorshipError::Rejected {
            code: code.into(),
            message: "nope".into(),
            retryable: false,
        }
        .into()
    }

    #[test]
    fn a_missing_facilitator_falls_back_to_self_funding() {
        let err: RequestWithdrawalError = SponsorshipError::NotConfigured.into();
        assert!(err.sponsorship_unavailable());
    }

    #[test]
    fn throttling_falls_back_to_self_funding() {
        assert!(rejected("RATE_LIMITED").sponsorship_unavailable());
        assert!(rejected("RELAYER_BALANCE_TOO_LOW").sponsorship_unavailable());
    }

    /// The user's own transaction would revert for the same reason, so falling back would cost them
    /// gas to learn what the facilitator already told them for free.
    #[test]
    fn a_rejection_naming_the_request_does_not_fall_back() {
        assert!(!rejected("SIMULATION_REVERTED").sponsorship_unavailable());
        assert!(!rejected("SIGNATURE_MISMATCH").sponsorship_unavailable());
        assert!(!rejected("EXPIRED").sponsorship_unavailable());
    }

    /// A code this SDK predates is treated as "the facilitator would not pay", which costs the user
    /// one transaction at worst and keeps a new facilitator rejection from stranding them.
    #[test]
    fn an_unknown_code_falls_back_to_self_funding() {
        assert!(rejected("SOMETHING_NEW").sponsorship_unavailable());
    }

    /// Every step has something to lose from a second transaction it did not need: a request would
    /// overwrite the first and restart the grace period, while a cancel or a finalize would revert
    /// and report failure for a step that worked.
    #[test]
    fn an_unknown_outcome_does_not_fall_back() {
        let unknown = || SponsorshipError::OutcomeUnknown("timed out".into());

        assert!(!RequestWithdrawalError::from(unknown()).sponsorship_unavailable());
        assert!(!CancelWithdrawalError::from(unknown()).sponsorship_unavailable());
        assert!(!FinalizeWithdrawalError::from(unknown()).sponsorship_unavailable());
    }

    /// A request that never reached the facilitator cannot have been submitted.
    #[test]
    fn an_undelivered_request_falls_back_to_self_funding() {
        let undelivered = || SponsorshipError::Transport("connection refused".into());

        assert!(RequestWithdrawalError::from(undelivered()).sponsorship_unavailable());
        assert!(CancelWithdrawalError::from(undelivered()).sponsorship_unavailable());
        assert!(FinalizeWithdrawalError::from(undelivered()).sponsorship_unavailable());
    }

    #[test]
    fn a_local_failure_is_not_a_sponsorship_problem() {
        assert!(!RequestWithdrawalError::AmountZero.sponsorship_unavailable());
    }
}
