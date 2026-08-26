//! Settling a clearing cycle: the debtor pays what they owe, the creditor claims what they are
//! owed. Both sides of a cycle live here because they share a cycle's terms and its proof format.
//!
//! [`SettlementClient::pay`] and [`SettlementClient::claim`] capture the intent, a route pin
//! (`gasless()`, `eip3009()`, `permit2()`, `self_funded()`) narrows how, and a terminal (`send()`,
//! `sign()`, `verify()`, `approve()`, `action()`) does it. A debit authorization signed elsewhere
//! attaches with `authorization(…)`. The claim side addresses someone else's credit with
//! `creditor(…)` — an input, not a different method: the payout goes to the address the committed
//! leaf names either way.

use std::marker::PhantomData;
use std::str::FromStr;

use alloy::{
    network::TxSigner,
    primitives::{Address, B256, U256},
    rpc::types::TransactionReceipt,
    signers::{Signature, Signer},
};
use rpc::ClearingSettlementActionResponse;
use serde::{Deserialize, Serialize};

use crate::{
    client::{
        ClientCtx, await_receipt, confirm_echoed,
        facilitator::FacilitatorFailure,
        model::{ClaimReceipt, PayReceipt, Route, TokenRoute},
        route,
        sig::{self, Eip2612PermitRequest},
    },
    contract::Core4Mica::{Permit2Authorization, ReceiveAuthorization},
    error::{ClientError, SettlementError, SponsorshipError},
    validators::validate_address,
};

pub struct SettlementClient<S> {
    ctx: ClientCtx<S>,
}

impl<S> Clone for SettlementClient<S> {
    fn clone(&self) -> Self {
        Self {
            ctx: self.ctx.clone(),
        }
    }
}

impl<S> SettlementClient<S> {
    pub(super) fn new(ctx: ClientCtx<S>) -> Self {
        Self { ctx }
    }

    /// Whether the gasless route is available at all. Callers that want to decide for themselves
    /// rather than let the auto route fall back can branch on this instead of on an error.
    pub fn is_gasless_available(&self) -> bool {
        self.ctx.facilitator().is_configured()
    }

    /// Starts a net-debit payment for `cycle_id`. Nothing happens until a terminal (`send()`,
    /// `sign()`, `verify()`, `approve()`, `action()`) runs.
    pub fn pay(&self, cycle_id: impl Into<String>) -> PayBuilder<S, route::Auto> {
        PayBuilder {
            ctx: self.ctx.clone(),
            cycle_id: cycle_id.into(),
            route: route::Auto,
        }
    }

    /// Starts a net-credit claim for `cycle_id`, for the signer's own credit unless `creditor(…)`
    /// redirects it.
    pub fn claim(&self, cycle_id: impl Into<String>) -> ClaimBuilder<S, route::Auto> {
        ClaimBuilder {
            ctx: self.ctx.clone(),
            cycle_id: cycle_id.into(),
            creditor: None,
            _route: PhantomData,
        }
    }
}

/// A net-debit payment being built. Terminal signer bounds are per route: gasless pins need only a
/// [`Signer`], the self-funded pin (and the auto route, which may fall back to it) a transaction
/// signer too.
#[must_use = "a builder does nothing until a terminal method (`send`, `sign`, `verify`, `approve`, `action`) runs"]
pub struct PayBuilder<S, R = route::Auto> {
    ctx: ClientCtx<S>,
    cycle_id: String,
    route: R,
}

impl<S, R> PayBuilder<S, R> {
    fn with_route<T>(self, route: T) -> PayBuilder<S, T> {
        PayBuilder {
            ctx: self.ctx,
            cycle_id: self.cycle_id,
            route,
        }
    }
}

impl<S> PayBuilder<S, route::Auto> {
    /// Pins "any gasless scheme": EIP-3009 first, then Permit2 with the approval sponsored, with
    /// no self-funded fallback.
    pub fn gasless(self) -> PayBuilder<S, route::Gasless> {
        self.with_route(route::Gasless)
    }

    /// Pins the EIP-3009 route, failing rather than trying another scheme.
    pub fn eip3009(self) -> PayBuilder<S, route::Eip3009> {
        self.with_route(route::Eip3009)
    }

    /// Pins the Permit2 route, failing rather than trying another scheme.
    pub fn permit2(self) -> PayBuilder<S, route::Permit2> {
        self.with_route(route::Permit2)
    }

    /// Pins the caller's own transaction.
    pub fn self_funded(self) -> PayBuilder<S, route::SelfFunded> {
        self.with_route(route::SelfFunded)
    }

    /// The terms of the caller's net debit: where to pay, how much, and the proof the contract
    /// will check.
    pub async fn action(&self) -> Result<ClearingSettlementActionResponse, SettlementError>
    where
        S: Signer + Sync,
    {
        pay_action(&self.ctx, self.cycle_id.clone()).await
    }

    /// Pays the caller's committed net debit, gaslessly where possible.
    ///
    /// For an ERC-20 cycle with a facilitator configured, the caller signs an authorization for
    /// the exact amount — EIP-3009 where the token supports it, Permit2 otherwise — and the
    /// facilitator submits and pays gas; no native balance needed. Otherwise — a native-asset
    /// cycle, no facilitator, or no gasless scheme left — the caller's own transaction runs
    /// (grant the allowance with `pay(…).self_funded().approve()` first for ERC-20 cycles; a
    /// fallback without it is refused as [`SettlementError::Erc20AllowanceRequired`] rather than
    /// left to revert). A rejection that names the payment itself is returned rather than
    /// retried, and so is an unknown outcome: the facilitator may already have submitted, and a
    /// second payment would revert as `AlreadyPaid` after paying gas.
    ///
    /// Read [`PayReceipt::route`] to see which route ran.
    pub async fn send(self) -> Result<PayReceipt, SettlementError>
    where
        S: Signer + TxSigner<Signature> + Send + Sync + Clone + 'static,
    {
        let action = pay_action(&self.ctx, self.cycle_id.clone()).await?;
        if !self.ctx.facilitator().is_configured() || cycle_asset(&action)? == Address::ZERO {
            return pay_self_funded_with(&self.ctx, &action).await;
        }
        match pay_gasless_with(&self.ctx, self.cycle_id, &action).await {
            // The approval cannot be sponsored, so gaslessness is off the table either way;
            // paying the debit directly is one transaction rather than an approval plus a
            // payment.
            Err(SettlementError::Permit2AllowanceRequired { .. }) => {
                fallback_to_self_funded(&self.ctx, &action).await
            }
            Err(err) if sponsorship_unavailable(&err, names_the_payment) => {
                fallback_to_self_funded(&self.ctx, &action).await
            }
            outcome => outcome,
        }
    }
}

impl<S> PayBuilder<S, route::Gasless> {
    /// Pays gaslessly, over whichever signature scheme the cycle's token supports: EIP-3009
    /// first, then Permit2 with the one-time `approve(PERMIT2, …)` signed rather than transacted
    /// where the token allows it. Fails rather than falling back to the caller's own transaction.
    ///
    /// ERC-20 cycles only: a native-asset debit cannot be pulled by signature.
    pub async fn send(self) -> Result<PayReceipt, SettlementError>
    where
        S: Signer + Send + Sync,
    {
        let action = pay_action(&self.ctx, self.cycle_id.clone()).await?;
        pay_gasless_with(&self.ctx, self.cycle_id, &action).await
    }
}

impl<S> PayBuilder<S, route::Eip3009> {
    /// Signs the debit authorization without submitting it, for callers that redeem it
    /// elsewhere. Fetches the debit's terms from core first: the signature binds the
    /// ClearingHouse, the exact amount, and — as its nonce — the cycle. Redeem by attaching it to
    /// a fresh builder: `settlement.pay(cycle_id).eip3009().authorization(auth).send()`.
    pub async fn sign(self) -> Result<ReceiveAuthorization, SettlementError>
    where
        S: Signer + Send + Sync,
    {
        let action = pay_action(&self.ctx, self.cycle_id).await?;
        let (_, asset, call) = checked_gasless_pay(&self.ctx, &action)?;
        sig::debit_authorization(
            &self.ctx,
            asset,
            call.contract_address,
            call.amount,
            call.cycle_id,
        )
        .await
    }

    /// Attaches a debit authorization signed elsewhere. It is self-contained, so it need not
    /// have been signed here.
    pub fn authorization(
        self,
        authorization: ReceiveAuthorization,
    ) -> PayBuilder<S, route::Authorized<ReceiveAuthorization>> {
        self.with_route(route::Authorized {
            auth: authorization,
        })
    }

    /// Pays gaslessly with an EIP-3009 authorization, failing rather than trying another scheme.
    ///
    /// Requires a token implementing EIP-3009 (USDC and similar); for anything else pin
    /// `permit2()`.
    pub async fn send(self) -> Result<PayReceipt, SettlementError>
    where
        S: Signer + Send + Sync,
    {
        let action = pay_action(&self.ctx, self.cycle_id.clone()).await?;
        pay_eip3009_with(&self.ctx, self.cycle_id, &action).await
    }
}

impl<S> PayBuilder<S, route::Permit2> {
    /// Upgrades the pin to sign the missing Permit2 approval (EIP-2612) rather than fail on it.
    pub fn sponsor_approval(self) -> PayBuilder<S, route::SponsoredPermit2> {
        self.with_route(route::SponsoredPermit2)
    }

    /// Signs the Permit2 debit authorization without submitting it. See the EIP-3009 pin's
    /// `sign()`; redeem with `settlement.pay(cycle_id).permit2().authorization(auth).send()`.
    pub async fn sign(self) -> Result<Permit2Authorization, SettlementError>
    where
        S: Signer + Send + Sync,
    {
        let action = pay_action(&self.ctx, self.cycle_id).await?;
        let (_, asset, call) = checked_gasless_pay(&self.ctx, &action)?;
        sig::debit_permit2_authorization(
            &self.ctx,
            asset,
            call.contract_address,
            call.amount,
            call.cycle_id,
        )
        .await
    }

    /// Attaches a Permit2 debit authorization signed elsewhere.
    pub fn authorization(
        self,
        authorization: Permit2Authorization,
    ) -> PayBuilder<S, route::Authorized<Permit2Authorization>> {
        self.with_route(route::Authorized {
            auth: authorization,
        })
    }

    /// Pays gaslessly through Permit2, failing rather than trying another scheme.
    ///
    /// Works for any ERC-20, but **is not gasless on its own**: Permit2 needs a one-time on-chain
    /// `approve(PERMIT2, …)` from the debtor, without which this fails with
    /// [`SettlementError::Permit2AllowanceRequired`]. `sponsor_approval()` covers that approval
    /// too, where the token allows it.
    pub async fn send(self) -> Result<PayReceipt, SettlementError>
    where
        S: Signer + Send + Sync,
    {
        let action = pay_action(&self.ctx, self.cycle_id.clone()).await?;
        submit_permit2_pay(&self.ctx, self.cycle_id, &action, None).await
    }
}

impl<S> PayBuilder<S, route::SponsoredPermit2> {
    /// Pays through Permit2, signing the missing approval rather than transacting for it.
    ///
    /// Tries the plain Permit2 route first; if the allowance is missing *and* the token supports
    /// EIP-2612, signs a permit for it and retries so both are submitted together. Still costs
    /// the debtor nothing.
    ///
    /// Fails with [`SettlementError::Permit2AllowanceRequired`] for tokens with no EIP-2612
    /// surface — their approval cannot be sponsored, so the debtor must send it themselves.
    pub async fn send(self) -> Result<PayReceipt, SettlementError>
    where
        S: Signer + Send + Sync,
    {
        let action = pay_action(&self.ctx, self.cycle_id.clone()).await?;
        pay_sponsored_permit2_with(&self.ctx, self.cycle_id, &action).await
    }
}

impl<S> PayBuilder<S, route::Authorized<ReceiveAuthorization>> {
    /// Preflight: runs every check a real submission would run, without spending anyone's gas.
    ///
    /// Worth doing before handing an authorization to a user-facing flow, since it tells a
    /// permanently unusable authorization apart from a transient failure.
    pub async fn verify(&self) -> Result<(), SettlementError> {
        let request = FacilitatorPayRequest {
            cycle_id: self.cycle_id.clone(),
            authorization: PayAuthorization::Eip3009 {
                authorization: self.route.auth.clone(),
            },
        };
        verify_pay(&self.ctx, &request).await
    }

    /// Pays the committed net debit with the attached authorization. The submitter needs no
    /// signer of their own: the facilitator resolves the debit's terms from core, and the
    /// signature fixes whose funds move.
    pub async fn send(self) -> Result<PayReceipt, SettlementError> {
        let debtor = self.route.auth.from;
        submit_pay(
            &self.ctx,
            self.cycle_id,
            PayAuthorization::Eip3009 {
                authorization: self.route.auth,
            },
            TokenRoute::Eip3009,
            debtor,
        )
        .await
    }
}

impl<S> PayBuilder<S, route::Authorized<Permit2Authorization>> {
    /// Preflight: runs every check a real submission would run, without spending anyone's gas.
    pub async fn verify(&self) -> Result<(), SettlementError> {
        let request = FacilitatorPayRequest {
            cycle_id: self.cycle_id.clone(),
            authorization: PayAuthorization::Permit2 {
                permit2_authorization: self.route.auth.clone(),
                eip2612_permit: None,
            },
        };
        verify_pay(&self.ctx, &request).await
    }

    /// Pays the committed net debit with the attached authorization. The submitter needs no
    /// signer of their own.
    pub async fn send(self) -> Result<PayReceipt, SettlementError> {
        let debtor = self.route.auth.from;
        submit_pay(
            &self.ctx,
            self.cycle_id,
            PayAuthorization::Permit2 {
                permit2_authorization: self.route.auth,
                eip2612_permit: None,
            },
            TokenRoute::Permit2,
            debtor,
        )
        .await
    }
}

impl<S> PayBuilder<S, route::SelfFunded> {
    /// Approves the settling ClearingHouse to pull exactly the committed debit, which a
    /// self-funded ERC-20 pay needs before `send()`. Token, spender and amount all come from the
    /// cycle's prepared action.
    pub async fn approve(&self) -> Result<TransactionReceipt, SettlementError>
    where
        S: Signer + TxSigner<Signature> + Send + Sync + Clone + 'static,
    {
        let action = pay_action(&self.ctx, self.cycle_id.clone()).await?;
        let call = checked_pay_call(&action, self.ctx.signer_address())?;
        let token = cycle_asset(&action)?;
        if token == Address::ZERO {
            return Err(SettlementError::InvalidParams(
                "a native-asset debit needs no approval; its value rides with the transaction"
                    .into(),
            ));
        }
        let contract = self.ctx.get_erc20_write_contract(token).await?;
        let sent = contract
            .approve(call.contract_address, call.amount)
            .send()
            .await;
        Ok(await_receipt(sent).await?)
    }

    /// Pays the caller's committed net debit with their own transaction.
    ///
    /// For ERC-20 cycles, grant the allowance with [`Self::approve`] first.
    pub async fn send(self) -> Result<PayReceipt, SettlementError>
    where
        S: Signer + TxSigner<Signature> + Send + Sync + Clone + 'static,
    {
        let action = pay_action(&self.ctx, self.cycle_id).await?;
        pay_self_funded_with(&self.ctx, &action).await
    }
}

/// A net-credit claim being built. Takes no signature on any route: the on-chain payout goes to
/// the address the committed leaf names, for the amount that leaf fixes, so a submitter can
/// neither redirect the payout nor inflate it. The only question is who pays the gas.
///
/// `PhantomData` rather than a stored route: with no authorization to carry, no claim state holds
/// data.
#[must_use = "a builder does nothing until a terminal method (`send`, `verify`, `action`) runs"]
pub struct ClaimBuilder<S, R = route::Auto> {
    ctx: ClientCtx<S>,
    cycle_id: String,
    creditor: Option<Address>,
    _route: PhantomData<R>,
}

impl<S, R> ClaimBuilder<S, R> {
    /// Claims `creditor`'s committed net credit rather than the signer's own, paying them rather
    /// than anyone else — they may of course be the same account.
    pub fn creditor(mut self, creditor: Address) -> Self {
        self.creditor = Some(creditor);
        self
    }

    fn with_route<T>(self) -> ClaimBuilder<S, T> {
        ClaimBuilder {
            ctx: self.ctx,
            cycle_id: self.cycle_id,
            creditor: self.creditor,
            _route: PhantomData,
        }
    }

    fn resolved_creditor(&self) -> Address
    where
        S: Signer,
    {
        self.creditor.unwrap_or_else(|| self.ctx.signer_address())
    }
}

impl<S> ClaimBuilder<S, route::Auto> {
    /// Pins the gasless route: the facilitator submits and pays, with no self-funded fallback.
    pub fn gasless(self) -> ClaimBuilder<S, route::Gasless> {
        self.with_route()
    }

    /// Pins the caller's own transaction.
    pub fn self_funded(self) -> ClaimBuilder<S, route::SelfFunded> {
        self.with_route()
    }

    /// The terms of the creditor's net credit for this cycle.
    pub async fn action(&self) -> Result<ClearingSettlementActionResponse, SettlementError>
    where
        S: Signer + Sync,
    {
        claim_action_for(&self.ctx, self.cycle_id.clone(), self.resolved_creditor()).await
    }

    /// Claims the committed net credit, gaslessly where possible.
    ///
    /// Goes through the facilitator when one is configured, so the caller needs no native balance;
    /// falls back to the caller's own transaction when no facilitator is configured or the
    /// facilitator declines to sponsor. A rejection that names the claim itself — an unfunded
    /// cycle, say — is returned rather than retried, since the caller's own transaction would
    /// revert for the same reason after paying for the privilege.
    ///
    /// Read [`ClaimReceipt::route`] to see which route ran.
    pub async fn send(self) -> Result<ClaimReceipt, SettlementError>
    where
        S: Signer + TxSigner<Signature> + Send + Sync + Clone + 'static,
    {
        let creditor = self.resolved_creditor();
        if !self.ctx.facilitator().is_configured() {
            return claim_self_funded_for(&self.ctx, self.cycle_id, creditor).await;
        }
        match claim_gasless_for(&self.ctx, self.cycle_id.clone(), creditor).await {
            Err(err) if sponsorship_unavailable(&err, names_the_claim) => {
                claim_self_funded_for(&self.ctx, self.cycle_id, creditor).await
            }
            outcome => outcome,
        }
    }
}

impl<S> ClaimBuilder<S, route::Gasless> {
    /// Preflight: runs every check a real submission would run, without spending anyone's gas.
    pub async fn verify(&self) -> Result<(), SettlementError>
    where
        S: Signer,
    {
        let request = FacilitatorClaimRequest {
            cycle_id: self.cycle_id.clone(),
            creditor: self.resolved_creditor(),
        };
        verify_claim(&self.ctx, &request).await
    }

    /// Claims the committed net credit gaslessly. The caller needs no native balance and makes no
    /// transaction — the facilitator resolves the claim's terms from core and submits it.
    ///
    /// Nothing is signed and nothing local is trusted: the facilitator asks core for the committed
    /// leaf's terms, so this call can only name *which* claim to submit, not what it pays.
    pub async fn send(self) -> Result<ClaimReceipt, SettlementError>
    where
        S: Signer,
    {
        let creditor = self.resolved_creditor();
        claim_gasless_for(&self.ctx, self.cycle_id, creditor).await
    }
}

impl<S> ClaimBuilder<S, route::SelfFunded> {
    /// Claims the committed net credit with the caller's own transaction.
    pub async fn send(self) -> Result<ClaimReceipt, SettlementError>
    where
        S: Signer + TxSigner<Signature> + Send + Sync + Clone + 'static,
    {
        let creditor = self.resolved_creditor();
        claim_self_funded_for(&self.ctx, self.cycle_id, creditor).await
    }
}

async fn pay_action<S>(
    ctx: &ClientCtx<S>,
    cycle_id: String,
) -> Result<ClearingSettlementActionResponse, SettlementError>
where
    S: Signer + Sync,
{
    let debtor = ctx.signer_address().to_string();
    let proxy = ctx.rpc_proxy().await?;
    Ok(proxy
        .get_clearing_pay_net_debit_action(cycle_id, debtor)
        .await?)
}

async fn claim_action_for<S>(
    ctx: &ClientCtx<S>,
    cycle_id: String,
    creditor: Address,
) -> Result<ClearingSettlementActionResponse, SettlementError>
where
    S: Signer + Sync,
{
    let proxy = ctx.rpc_proxy().await?;
    Ok(proxy
        .get_clearing_claim_net_credit_action(cycle_id, creditor.to_string())
        .await?)
}

async fn pay_gasless_with<S>(
    ctx: &ClientCtx<S>,
    cycle_id: String,
    action: &ClearingSettlementActionResponse,
) -> Result<PayReceipt, SettlementError>
where
    S: Signer + Send + Sync,
{
    // EIP-3009 is the cheaper route, but nothing says up front whether the token implements
    // it — so try it and read the answer off the rejection, which costs no gas.
    let rejection = match pay_eip3009_with(ctx, cycle_id.clone(), action).await {
        Ok(receipt) => return Ok(receipt),
        Err(err) => err,
    };
    if !refuses_the_authorization(&rejection) {
        return Err(rejection);
    }
    pay_sponsored_permit2_with(ctx, cycle_id, action).await
}

async fn pay_eip3009_with<S>(
    ctx: &ClientCtx<S>,
    cycle_id: String,
    action: &ClearingSettlementActionResponse,
) -> Result<PayReceipt, SettlementError>
where
    S: Signer + Send + Sync,
{
    let (debtor, asset, call) = checked_gasless_pay(ctx, action)?;
    let authorization = sig::debit_authorization(
        ctx,
        asset,
        call.contract_address,
        call.amount,
        call.cycle_id,
    )
    .await?;
    submit_pay(
        ctx,
        cycle_id,
        PayAuthorization::Eip3009 { authorization },
        TokenRoute::Eip3009,
        debtor,
    )
    .await
}

async fn pay_sponsored_permit2_with<S>(
    ctx: &ClientCtx<S>,
    cycle_id: String,
    action: &ClearingSettlementActionResponse,
) -> Result<PayReceipt, SettlementError>
where
    S: Signer + Send + Sync,
{
    // Try the plain route first: the debtor may already have approved, in which case a permit
    // is pointless and only costs the submitter a no-op.
    let rejection = match submit_permit2_pay(ctx, cycle_id.clone(), action, None).await {
        Ok(receipt) => return Ok(receipt),
        Err(err) => err,
    };

    let SettlementError::Permit2AllowanceRequired {
        eip2612_nonce: Some(nonce),
        ..
    } = &rejection
    else {
        // Either a different failure, or a token whose approval cannot be sponsored.
        return Err(rejection);
    };

    let (_, asset, _) = checked_gasless_pay(ctx, action)?;
    let permit = match sig::debit_eip2612_permit(ctx, asset, *nonce).await {
        Ok(permit) => permit,
        // The permit digest needs the token's domain separator; without one the approval
        // cannot be sponsored from here — the same dead end as a token with no EIP-2612
        // surface, and reported the same way.
        Err(SettlementError::Client(ClientError::MissingTokenDomainSeparator { .. })) => {
            return Err(unsponsorable(rejection));
        }
        Err(err) => return Err(err),
    };
    submit_permit2_pay(ctx, cycle_id, action, Some(permit.into())).await
}

async fn submit_permit2_pay<S>(
    ctx: &ClientCtx<S>,
    cycle_id: String,
    action: &ClearingSettlementActionResponse,
    eip2612_permit: Option<Eip2612PermitRequest>,
) -> Result<PayReceipt, SettlementError>
where
    S: Signer + Send + Sync,
{
    let (debtor, asset, call) = checked_gasless_pay(ctx, action)?;
    let permit2_authorization = sig::debit_permit2_authorization(
        ctx,
        asset,
        call.contract_address,
        call.amount,
        call.cycle_id,
    )
    .await?;
    let route = if eip2612_permit.is_some() {
        TokenRoute::SponsoredPermit2
    } else {
        TokenRoute::Permit2
    };
    submit_pay(
        ctx,
        cycle_id,
        PayAuthorization::Permit2 {
            permit2_authorization,
            eip2612_permit,
        },
        route,
        debtor,
    )
    .await
}

/// Validations shared by every gasless debit route: the terms must name this signer, and the
/// cycle must settle in an ERC-20 — a native debit cannot be pulled by signature.
fn checked_gasless_pay<S>(
    ctx: &ClientCtx<S>,
    action: &ClearingSettlementActionResponse,
) -> Result<(Address, Address, ClearingActionCall), SettlementError>
where
    S: Signer,
{
    let debtor = ctx.signer_address();
    let call = checked_pay_call(action, debtor)?;
    let asset = cycle_asset(action)?;
    if asset == Address::ZERO {
        return Err(SettlementError::InvalidParams(
            "native-asset debits cannot be paid gaslessly; use the self-funded route".into(),
        ));
    }
    Ok((debtor, asset, call))
}

async fn submit_pay<S>(
    ctx: &ClientCtx<S>,
    cycle_id: String,
    authorization: PayAuthorization,
    route: TokenRoute,
    debtor: Address,
) -> Result<PayReceipt, SettlementError> {
    let request = FacilitatorPayRequest {
        cycle_id,
        authorization,
    };
    let response: FacilitatorPayResponse = ctx
        .facilitator()
        .post("clearing/pay", &request)
        .await
        .map_err(SettlementError::Sponsorship)?;
    response.into_receipt(route, debtor)
}

async fn verify_pay<S>(
    ctx: &ClientCtx<S>,
    request: &FacilitatorPayRequest,
) -> Result<(), SettlementError> {
    let response: ClearingVerifyResponse = ctx
        .facilitator()
        .post("clearing/pay/verify", request)
        .await
        .map_err(SettlementError::Sponsorship)?;
    if response.is_valid {
        return Ok(());
    }
    Err(pay_rejection(response.failure, response.invalid_reason))
}

async fn verify_claim<S>(
    ctx: &ClientCtx<S>,
    request: &FacilitatorClaimRequest,
) -> Result<(), SettlementError> {
    let response: ClearingVerifyResponse = ctx
        .facilitator()
        .post("clearing/claim/verify", request)
        .await
        .map_err(SettlementError::Sponsorship)?;
    if response.is_valid {
        return Ok(());
    }
    Err(response
        .failure
        .into_sponsorship_error(response.invalid_reason)
        .into())
}

/// The one rejection with detail to unpack: the missing-allowance nonce is what lets the
/// sponsored-Permit2 route sign the approval instead of surrendering.
fn pay_rejection(failure: FacilitatorFailure, message: Option<String>) -> SettlementError {
    let eip2612_nonce = failure.eip2612_nonce();
    match failure.into_sponsorship_error(message) {
        SponsorshipError::Rejected { code, message, .. }
            if code == "PERMIT2_ALLOWANCE_REQUIRED" =>
        {
            SettlementError::Permit2AllowanceRequired {
                message,
                eip2612_nonce,
            }
        }
        other => other.into(),
    }
}

/// The self-funded fallback, taken only after a gasless attempt was refused. Pre-checks the
/// ERC-20 allowance the fallback needs and the gasless routes never did, so a debtor who has
/// not approved the ClearingHouse is told exactly that instead of getting an opaque revert
/// from inside the token.
async fn fallback_to_self_funded<S>(
    ctx: &ClientCtx<S>,
    action: &ClearingSettlementActionResponse,
) -> Result<PayReceipt, SettlementError>
where
    S: Signer + TxSigner<Signature> + Send + Sync + Clone + 'static,
{
    let call = ClearingActionCall::parse(action)?;
    let token = cycle_asset(action)?;
    let allowance = ctx
        .get_erc20_contract(token)
        .await?
        .allowance(ctx.signer_address(), call.contract_address)
        .call()
        .await?;
    if allowance < call.amount {
        return Err(SettlementError::Erc20AllowanceRequired {
            token,
            spender: call.contract_address,
            allowance,
            needed: call.amount,
        });
    }
    pay_self_funded_with(ctx, action).await
}

async fn pay_self_funded_with<S>(
    ctx: &ClientCtx<S>,
    action: &ClearingSettlementActionResponse,
) -> Result<PayReceipt, SettlementError>
where
    S: Signer + TxSigner<Signature> + Send + Sync + Clone + 'static,
{
    let debtor = ctx.signer_address();
    let call = checked_pay_call(action, debtor)?;
    let contract = ctx
        .get_clearing_house_write_contract(call.contract_address)
        .await?;

    let sent = contract
        .payNetDebit(call.cycle_id, call.amount, call.proof)
        .value(call.payable_value)
        .send()
        .await;
    let receipt = await_receipt(sent).await?;
    if !receipt.status() {
        return Err(SettlementError::RevertedOnChain {
            tx_hash: receipt.transaction_hash,
        });
    }
    Ok(PayReceipt {
        tx_hash: receipt.transaction_hash,
        route: TokenRoute::SelfFunded,
        account: debtor,
        network: None,
    })
}

async fn claim_gasless_for<S>(
    ctx: &ClientCtx<S>,
    cycle_id: String,
    creditor: Address,
) -> Result<ClaimReceipt, SettlementError> {
    let request = FacilitatorClaimRequest { cycle_id, creditor };
    let response: FacilitatorClaimResponse = ctx
        .facilitator()
        .post("clearing/claim", &request)
        .await
        .map_err(SettlementError::Sponsorship)?;
    Ok(response.into_receipt(creditor)?)
}

async fn claim_self_funded_for<S>(
    ctx: &ClientCtx<S>,
    cycle_id: String,
    creditor: Address,
) -> Result<ClaimReceipt, SettlementError>
where
    S: Signer + TxSigner<Signature> + Send + Sync + Clone + 'static,
{
    let action = claim_action_for(ctx, cycle_id, creditor).await?;
    confirm_echoed(
        "participant",
        Some(&action.participant),
        creditor,
        SettlementError::InvalidParams,
    )?;
    if action.function_name != "claimNetCreditFor" {
        return Err(SettlementError::InvalidParams(format!(
            "core prepared {}, expected claimNetCreditFor",
            action.function_name
        )));
    }
    let call = ClearingActionCall::parse(&action)?;
    let contract = ctx
        .get_clearing_house_write_contract(call.contract_address)
        .await?;

    let sent = contract
        .claimNetCreditFor(creditor, call.cycle_id, call.amount, call.proof)
        .send()
        .await;
    let receipt = await_receipt(sent).await?;
    if !receipt.status() {
        return Err(SettlementError::RevertedOnChain {
            tx_hash: receipt.transaction_hash,
        });
    }
    Ok(ClaimReceipt {
        tx_hash: receipt.transaction_hash,
        route: Route::SelfFunded,
        account: creditor,
        network: None,
    })
}

/// Whether an error means "nobody sponsored this", as opposed to "this request is bad" or "we do
/// not know what happened". Only the first is worth falling back on: a rejection that names the
/// request (per `names_the_request`) would revert the caller's own transaction too, after they had
/// paid for it, and an unknown outcome may mean the facilitator already submitted — a second
/// attempt then reverts as `AlreadyClaimed`/`AlreadyPaid` after paying gas.
fn sponsorship_unavailable(err: &SettlementError, names_the_request: fn(&str) -> bool) -> bool {
    match err {
        SettlementError::Sponsorship(SponsorshipError::Rejected { code, .. }) => {
            !names_the_request(code)
        }
        SettlementError::Sponsorship(SponsorshipError::OutcomeUnknown(_)) => false,
        SettlementError::Sponsorship(_) => true,
        _ => false,
    }
}

/// Rejections that describe the claim rather than the facilitator's willingness to pay. The
/// self-funded path resolves the same terms from the same core and submits to the same contract,
/// so it would fail for the same reason.
fn names_the_claim(code: &str) -> bool {
    matches!(
        code,
        "INVALID_REQUEST"
            | "ACTION_UNAVAILABLE"
            | "ACTION_MISMATCH"
            | "SIMULATION_REVERTED"
            | "REVERTED_ON_CHAIN"
            | "RECEIPT_UNAVAILABLE"
    )
}

/// Rejections that describe the payment rather than the facilitator's willingness to sponsor it.
/// Beyond the claim codes, this covers the debtor's side of the bargain: a refused signature means
/// the SDK signed over the wrong terms (falling back would mask the bug at the caller's expense),
/// and an insufficient balance fails the self-funded route just the same.
fn names_the_payment(code: &str) -> bool {
    names_the_claim(code)
        || matches!(
            code,
            "MALFORMED_SIGNATURE"
                | "SIGNATURE_MISMATCH"
                | "EXPIRED"
                | "NOT_YET_VALID"
                | "NONCE_ALREADY_USED"
                | "INSUFFICIENT_BALANCE"
        )
}

/// Strips the EIP-2612 nonce from an allowance rejection: the nonce advertises that the approval
/// *could* be sponsored, which has just been disproven.
fn unsponsorable(err: SettlementError) -> SettlementError {
    match err {
        SettlementError::Permit2AllowanceRequired { message, .. } => {
            SettlementError::Permit2AllowanceRequired {
                message,
                eip2612_nonce: None,
            }
        }
        other => other,
    }
}

/// Whether a rejection means "this token cannot take an EIP-3009 authorization" rather than
/// "this payment is bad". A token without `receiveWithAuthorization` reverts opaquely, which the
/// facilitator reports as a failed simulation — indistinguishable, from here, from any other
/// revert. Retrying over Permit2 is therefore a guess, but a cheap one: the simulation spent no
/// gas, and a genuinely bad payment fails the second route with its own error.
///
/// A token with no published domain separator refuses earlier still — the EIP-3009 digest cannot
/// even be built — and that is no reason to give up: Permit2's domain derives from the chain id,
/// so its route stays open.
fn refuses_the_authorization(err: &SettlementError) -> bool {
    matches!(
        err,
        SettlementError::Sponsorship(SponsorshipError::Rejected { code, .. })
            if code == "SIMULATION_REVERTED" || code == "UNSUPPORTED_TRANSFER_METHOD"
    ) || matches!(
        err,
        SettlementError::Client(ClientError::MissingTokenDomainSeparator { .. })
    )
}

/// The action's cycle asset, `Address::ZERO` for a native-asset cycle.
fn cycle_asset(action: &ClearingSettlementActionResponse) -> Result<Address, SettlementError> {
    validate_address(&action.asset_address)
        .map_err(|err| SettlementError::InvalidParams(format!("invalid cycle asset: {err}")))
}

/// Validates a pay action against the caller before any money moves: core must have prepared a
/// debit for this debtor, not some other action or participant.
fn checked_pay_call(
    action: &ClearingSettlementActionResponse,
    debtor: Address,
) -> Result<ClearingActionCall, SettlementError> {
    confirm_echoed(
        "participant",
        Some(&action.participant),
        debtor,
        SettlementError::InvalidParams,
    )?;
    if action.function_name != "payNetDebit" {
        return Err(SettlementError::InvalidParams(format!(
            "core prepared {}, expected payNetDebit",
            action.function_name
        )));
    }
    ClearingActionCall::parse(action)
}

/// Wire format for `POST /clearing/claim` and `POST /clearing/claim/verify`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct FacilitatorClaimRequest {
    cycle_id: String,
    creditor: Address,
}

/// Wire format for `POST /clearing/pay/verify` and `POST /clearing/claim/verify` responses.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ClearingVerifyResponse {
    is_valid: bool,
    invalid_reason: Option<String>,
    #[serde(flatten)]
    failure: FacilitatorFailure,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FacilitatorClaimResponse {
    success: bool,
    tx_hash: Option<String>,
    network: Option<String>,
    creditor: Option<String>,
    error: Option<String>,
    #[serde(flatten)]
    failure: FacilitatorFailure,
}

impl FacilitatorClaimResponse {
    /// `creditor` falls back to what was asked for: it is echoed for reconciliation, and a
    /// facilitator that omits it has not changed who the contract paid. One that echoes something
    /// else has, and the receipt is refused rather than made to describe it.
    fn into_receipt(self, creditor: Address) -> Result<ClaimReceipt, SponsorshipError> {
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

        Ok(ClaimReceipt {
            tx_hash,
            route: Route::Gasless,
            account: confirm_echoed(
                "creditor",
                self.creditor.as_deref(),
                creditor,
                SponsorshipError::OutcomeUnknown,
            )?,
            network: self.network,
        })
    }
}

/// Wire format for `POST /clearing/pay` and `POST /clearing/pay/verify`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct FacilitatorPayRequest {
    cycle_id: String,
    #[serde(flatten)]
    authorization: PayAuthorization,
}

/// The authorization and its `assetTransferMethod` tag, flattened into the request as siblings —
/// the same envelope a deposit's authorization travels in.
#[derive(Debug, Serialize)]
#[serde(
    tag = "assetTransferMethod",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
enum PayAuthorization {
    Eip3009 {
        authorization: ReceiveAuthorization,
    },
    Permit2 {
        permit2_authorization: Permit2Authorization,
        /// Sponsored approval, so the debtor never transacts.
        #[serde(skip_serializing_if = "Option::is_none")]
        eip2612_permit: Option<Eip2612PermitRequest>,
    },
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FacilitatorPayResponse {
    success: bool,
    tx_hash: Option<String>,
    network: Option<String>,
    debtor: Option<String>,
    error: Option<String>,
    #[serde(flatten)]
    failure: FacilitatorFailure,
}

impl FacilitatorPayResponse {
    /// `debtor` falls back to what was asked for: it is echoed for reconciliation, and a
    /// facilitator that omits it has not changed whose funds the contract pulled. One that echoes
    /// something else has, and the receipt is refused rather than made to describe it.
    fn into_receipt(
        self,
        route: TokenRoute,
        debtor: Address,
    ) -> Result<PayReceipt, SettlementError> {
        if !self.success {
            return Err(pay_rejection(self.failure, self.error));
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

        Ok(PayReceipt {
            tx_hash,
            route,
            account: confirm_echoed(
                "debtor",
                self.debtor.as_deref(),
                debtor,
                SponsorshipError::OutcomeUnknown,
            )?,
            network: self.network,
        })
    }
}

struct ClearingActionCall {
    contract_address: Address,
    cycle_id: B256,
    amount: U256,
    payable_value: U256,
    proof: Vec<B256>,
}

impl ClearingActionCall {
    fn parse(action: &ClearingSettlementActionResponse) -> Result<Self, SettlementError> {
        let contract_address = validate_address(&action.contract_address)
            .map_err(|err| SettlementError::InvalidParams(err.to_string()))?;
        let cycle_id = B256::from_str(&action.cycle_id).map_err(|err| {
            SettlementError::InvalidParams(format!("invalid clearing cycle id: {err}"))
        })?;
        let amount = U256::from_str(&action.amount).map_err(|err| {
            SettlementError::InvalidParams(format!("invalid clearing amount: {err}"))
        })?;
        let payable_value = U256::from_str(&action.payable_value).map_err(|err| {
            SettlementError::InvalidParams(format!("invalid payable value: {err}"))
        })?;
        let proof = action
            .proof
            .iter()
            .map(|item| {
                B256::from_str(item).map_err(|err| {
                    SettlementError::InvalidParams(format!("invalid clearing proof element: {err}"))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            contract_address,
            cycle_id,
            amount,
            payable_value,
            proof,
        })
    }
}
