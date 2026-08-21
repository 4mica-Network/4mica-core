//! Settling a clearing cycle: the debtor pays what they owe, the creditor claims what they are
//! owed. Both sides of a cycle live here because they share a cycle's terms and its proof format.

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
        model::{ClaimPath, ClaimReceipt, PayPath, PayReceipt},
        sig::{self, Eip2612PermitRequest},
    },
    contract::Core4Mica::{Permit2Authorization, ReceiveAuthorization},
    error::{ApproveErc20Error, ClearingSettlementError, ClientError, SponsorshipError},
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

    /// Whether the sponsored route is available at all. Callers that want to decide for themselves
    /// rather than let the gasless methods fall back can branch on this instead of on an error.
    pub fn is_gasless_available(&self) -> bool {
        self.ctx.facilitator().is_configured()
    }
}

impl<S> SettlementClient<S>
where
    S: Signer + Sync,
{
    /// The terms of the caller's net debit for `cycle_id`: where to pay, how much, and the proof
    /// the contract will check.
    pub async fn pay_net_debit_action(
        &self,
        cycle_id: String,
    ) -> Result<ClearingSettlementActionResponse, ClearingSettlementError> {
        let debtor = self.ctx.signer_address().to_string();
        let proxy = self.ctx.rpc_proxy().await?;
        Ok(proxy
            .get_clearing_pay_net_debit_action(cycle_id, debtor)
            .await?)
    }

    /// The terms of the caller's net credit for `cycle_id`.
    pub async fn claim_net_credit_action(
        &self,
        cycle_id: String,
    ) -> Result<ClearingSettlementActionResponse, ClearingSettlementError> {
        self.claim_net_credit_action_for(cycle_id, self.ctx.signer_address())
            .await
    }

    pub async fn claim_net_credit_action_for(
        &self,
        cycle_id: String,
        creditor: Address,
    ) -> Result<ClearingSettlementActionResponse, ClearingSettlementError> {
        let proxy = self.ctx.rpc_proxy().await?;
        Ok(proxy
            .get_clearing_claim_net_credit_action(cycle_id, creditor.to_string())
            .await?)
    }

    /// Claims the caller's committed net credit gaslessly. The caller needs no native balance and
    /// makes no transaction — the facilitator resolves the claim's terms from core and submits it.
    pub async fn claim_net_credit_gasless(
        &self,
        cycle_id: String,
    ) -> Result<ClaimReceipt, ClearingSettlementError> {
        self.claim_net_credit_gasless_for(cycle_id, self.ctx.signer_address())
            .await
    }

    /// Claims `creditor`'s committed net credit gaslessly, paying them rather than anyone else.
    ///
    /// Nothing is signed and nothing local is trusted: the facilitator asks core for the committed
    /// leaf's terms, so this call can only name *which* claim to submit, not what it pays.
    pub async fn claim_net_credit_gasless_for(
        &self,
        cycle_id: String,
        creditor: Address,
    ) -> Result<ClaimReceipt, ClearingSettlementError> {
        let request = FacilitatorClaimRequest { cycle_id, creditor };
        let response: FacilitatorClaimResponse = self
            .ctx
            .facilitator()
            .post("clearing/claim", &request)
            .await
            .map_err(ClearingSettlementError::Sponsorship)?;
        Ok(response.into_receipt(creditor)?)
    }
}

impl<S> SettlementClient<S>
where
    S: Signer + Send + Sync,
{
    /// Pays the caller's committed net debit gaslessly, over whichever signature scheme the
    /// cycle's token supports. The caller signs an authorization for the exact amount and the
    /// facilitator submits it — no native balance, no allowance, and no transaction of the
    /// caller's own.
    ///
    /// Tries EIP-3009 first; where the token cannot redeem it, retries over Permit2 with the
    /// one-time `approve(PERMIT2, …)` signed rather than transacted where the token allows it.
    /// Call [`Self::pay_net_debit_eip3009`], [`Self::pay_net_debit_permit2`] or
    /// [`Self::pay_net_debit_sponsored_permit2`] to pin one scheme instead.
    ///
    /// ERC-20 cycles only: a native-asset debit cannot be pulled by signature.
    pub async fn pay_net_debit_gasless(
        &self,
        cycle_id: String,
    ) -> Result<PayReceipt, ClearingSettlementError> {
        let action = self.pay_net_debit_action(cycle_id.clone()).await?;
        self.pay_net_debit_gasless_with(cycle_id, &action).await
    }

    /// Pays the caller's committed net debit gaslessly with an EIP-3009 authorization, failing
    /// rather than trying another scheme.
    ///
    /// Requires a token implementing EIP-3009 (USDC and similar); for anything else see
    /// [`Self::pay_net_debit_permit2`].
    pub async fn pay_net_debit_eip3009(
        &self,
        cycle_id: String,
    ) -> Result<PayReceipt, ClearingSettlementError> {
        let action = self.pay_net_debit_action(cycle_id.clone()).await?;
        self.pay_net_debit_eip3009_with(cycle_id, &action).await
    }

    /// Pays the caller's committed net debit gaslessly through Permit2, failing rather than
    /// trying another scheme.
    ///
    /// Works for any ERC-20, but **is not gasless on its own**: Permit2 needs a one-time on-chain
    /// `approve(PERMIT2, …)` from the debtor, without which this fails with
    /// [`ClearingSettlementError::Permit2AllowanceRequired`].
    /// [`Self::pay_net_debit_sponsored_permit2`] covers that approval too, where the token
    /// allows it.
    pub async fn pay_net_debit_permit2(
        &self,
        cycle_id: String,
    ) -> Result<PayReceipt, ClearingSettlementError> {
        let action = self.pay_net_debit_action(cycle_id.clone()).await?;
        self.pay_net_debit_permit2_with(cycle_id, &action).await
    }

    /// Pays through Permit2, signing the missing approval rather than transacting for it.
    ///
    /// Tries the plain Permit2 route first; if the allowance is missing *and* the token supports
    /// EIP-2612, signs a permit for it and retries so both are submitted together. Still costs
    /// the debtor nothing.
    ///
    /// Fails with [`ClearingSettlementError::Permit2AllowanceRequired`] for tokens with no
    /// EIP-2612 surface — their approval cannot be sponsored, so the debtor must send it
    /// themselves.
    pub async fn pay_net_debit_sponsored_permit2(
        &self,
        cycle_id: String,
    ) -> Result<PayReceipt, ClearingSettlementError> {
        let action = self.pay_net_debit_action(cycle_id.clone()).await?;
        self.pay_net_debit_sponsored_permit2_with(cycle_id, &action)
            .await
    }

    async fn pay_net_debit_gasless_with(
        &self,
        cycle_id: String,
        action: &ClearingSettlementActionResponse,
    ) -> Result<PayReceipt, ClearingSettlementError> {
        // EIP-3009 is the cheaper route, but nothing says up front whether the token implements
        // it — so try it and read the answer off the rejection, which costs no gas.
        let rejection = match self
            .pay_net_debit_eip3009_with(cycle_id.clone(), action)
            .await
        {
            Ok(receipt) => return Ok(receipt),
            Err(err) => err,
        };
        if !refuses_the_authorization(&rejection) {
            return Err(rejection);
        }
        self.pay_net_debit_sponsored_permit2_with(cycle_id, action)
            .await
    }

    async fn pay_net_debit_eip3009_with(
        &self,
        cycle_id: String,
        action: &ClearingSettlementActionResponse,
    ) -> Result<PayReceipt, ClearingSettlementError> {
        let (debtor, asset, call) = self.checked_gasless_pay(action)?;
        let authorization = sig::debit_authorization(
            &self.ctx,
            asset,
            call.contract_address,
            call.amount,
            call.cycle_id,
        )
        .await?;
        self.submit_pay(
            cycle_id,
            PayAuthorization::Eip3009 { authorization },
            debtor,
        )
        .await
    }

    async fn pay_net_debit_permit2_with(
        &self,
        cycle_id: String,
        action: &ClearingSettlementActionResponse,
    ) -> Result<PayReceipt, ClearingSettlementError> {
        self.submit_permit2_pay(cycle_id, action, None).await
    }

    async fn pay_net_debit_sponsored_permit2_with(
        &self,
        cycle_id: String,
        action: &ClearingSettlementActionResponse,
    ) -> Result<PayReceipt, ClearingSettlementError> {
        // Try the plain route first: the debtor may already have approved, in which case a permit
        // is pointless and only costs the submitter a no-op.
        let rejection = match self
            .submit_permit2_pay(cycle_id.clone(), action, None)
            .await
        {
            Ok(receipt) => return Ok(receipt),
            Err(err) => err,
        };

        let ClearingSettlementError::Permit2AllowanceRequired {
            eip2612_nonce: Some(nonce),
            ..
        } = &rejection
        else {
            // Either a different failure, or a token whose approval cannot be sponsored.
            return Err(rejection);
        };

        let (_, asset, _) = self.checked_gasless_pay(action)?;
        let permit = match sig::debit_eip2612_permit(&self.ctx, asset, *nonce).await {
            Ok(permit) => permit,
            // The permit digest needs the token's domain separator; without one the approval
            // cannot be sponsored from here — the same dead end as a token with no EIP-2612
            // surface, and reported the same way.
            Err(ClearingSettlementError::Client(ClientError::MissingTokenDomainSeparator {
                ..
            })) => {
                return Err(unsponsorable(rejection));
            }
            Err(err) => return Err(err),
        };
        self.submit_permit2_pay(cycle_id, action, Some(permit.into()))
            .await
    }

    async fn submit_permit2_pay(
        &self,
        cycle_id: String,
        action: &ClearingSettlementActionResponse,
        eip2612_permit: Option<Eip2612PermitRequest>,
    ) -> Result<PayReceipt, ClearingSettlementError> {
        let (debtor, asset, call) = self.checked_gasless_pay(action)?;
        let permit2_authorization = sig::debit_permit2_authorization(
            &self.ctx,
            asset,
            call.contract_address,
            call.amount,
            call.cycle_id,
        )
        .await?;
        self.submit_pay(
            cycle_id,
            PayAuthorization::Permit2 {
                permit2_authorization,
                eip2612_permit,
            },
            debtor,
        )
        .await
    }

    /// Validations shared by every gasless debit route: the terms must name this signer, and the
    /// cycle must settle in an ERC-20 — a native debit cannot be pulled by signature.
    fn checked_gasless_pay(
        &self,
        action: &ClearingSettlementActionResponse,
    ) -> Result<(Address, Address, ClearingActionCall), ClearingSettlementError> {
        let debtor = self.ctx.signer_address();
        let call = checked_pay_call(action, debtor)?;
        let asset = cycle_asset(action)?;
        if asset == Address::ZERO {
            return Err(ClearingSettlementError::InvalidParams(
                "native-asset debits cannot be paid gaslessly; use the self-funded route".into(),
            ));
        }
        Ok((debtor, asset, call))
    }

    async fn submit_pay(
        &self,
        cycle_id: String,
        authorization: PayAuthorization,
        debtor: Address,
    ) -> Result<PayReceipt, ClearingSettlementError> {
        let request = FacilitatorPayRequest {
            cycle_id,
            authorization,
        };
        let response: FacilitatorPayResponse = self
            .ctx
            .facilitator()
            .post("clearing/pay", &request)
            .await
            .map_err(ClearingSettlementError::Sponsorship)?;
        response.into_receipt(debtor)
    }
}

impl<S> SettlementClient<S>
where
    S: Signer + TxSigner<Signature> + Send + Sync + Clone + 'static,
{
    /// Pays the caller's committed net debit for a clearing cycle, sponsored where possible.
    ///
    /// For an ERC-20 cycle with a facilitator configured, the caller signs an authorization for
    /// the exact amount — EIP-3009 where the token supports it, Permit2 otherwise — and the
    /// facilitator submits and pays gas; no native balance needed. Otherwise — a native-asset
    /// cycle, no facilitator, or no sponsored scheme left — the caller's own transaction runs
    /// (grant the allowance with [`Self::approve_erc20`] first for ERC-20 cycles; a fallback
    /// without it is refused as [`ClearingSettlementError::Erc20AllowanceRequired`] rather than
    /// left to revert). A rejection that names the payment itself is returned rather than
    /// retried, and so is an unknown outcome: the facilitator may already have submitted, and a
    /// second payment would revert as `AlreadyPaid` after paying gas.
    ///
    /// Read [`PayReceipt::path`] to see which route ran.
    pub async fn pay_net_debit(
        &self,
        cycle_id: String,
    ) -> Result<PayReceipt, ClearingSettlementError> {
        let action = self.pay_net_debit_action(cycle_id.clone()).await?;
        if !self.is_gasless_available() || cycle_asset(&action)? == Address::ZERO {
            return self.pay_net_debit_self_funded_with(&action).await;
        }
        match self.pay_net_debit_gasless_with(cycle_id, &action).await {
            // The approval cannot be sponsored, so gaslessness is off the table either way;
            // paying the debit directly is one transaction rather than an approval plus a
            // payment.
            Err(ClearingSettlementError::Permit2AllowanceRequired { .. }) => {
                self.fallback_to_self_funded(&action).await
            }
            Err(err) if sponsorship_unavailable(&err, names_the_payment) => {
                self.fallback_to_self_funded(&action).await
            }
            outcome => outcome,
        }
    }

    /// The self-funded fallback, taken only after a gasless attempt was refused. Pre-checks the
    /// ERC-20 allowance the fallback needs and the gasless routes never did, so a debtor who has
    /// not approved the ClearingHouse is told exactly that instead of getting an opaque revert
    /// from inside the token.
    async fn fallback_to_self_funded(
        &self,
        action: &ClearingSettlementActionResponse,
    ) -> Result<PayReceipt, ClearingSettlementError> {
        let call = ClearingActionCall::parse(action)?;
        let token = cycle_asset(action)?;
        let allowance = self
            .ctx
            .get_erc20_contract(token)
            .await?
            .allowance(self.ctx.signer_address(), call.contract_address)
            .call()
            .await?;
        if allowance < call.amount {
            return Err(ClearingSettlementError::Erc20AllowanceRequired {
                token,
                spender: call.contract_address,
                allowance,
                needed: call.amount,
            });
        }
        self.pay_net_debit_self_funded_with(action).await
    }

    /// Pays the caller's committed net debit with their own transaction.
    ///
    /// For ERC-20 cycles, grant the allowance with [`Self::approve_erc20`] first.
    pub async fn pay_net_debit_self_funded(
        &self,
        cycle_id: String,
    ) -> Result<PayReceipt, ClearingSettlementError> {
        let action = self.pay_net_debit_action(cycle_id).await?;
        self.pay_net_debit_self_funded_with(&action).await
    }

    async fn pay_net_debit_self_funded_with(
        &self,
        action: &ClearingSettlementActionResponse,
    ) -> Result<PayReceipt, ClearingSettlementError> {
        let debtor = self.ctx.signer_address();
        let call = checked_pay_call(action, debtor)?;
        let contract = self
            .ctx
            .get_clearing_house_write_contract(call.contract_address)
            .await?;

        let sent = contract
            .payNetDebit(call.cycle_id, call.amount, call.proof)
            .value(call.payable_value)
            .send()
            .await;
        let receipt = await_receipt(sent).await?;
        if !receipt.status() {
            return Err(ClearingSettlementError::RevertedOnChain {
                tx_hash: receipt.transaction_hash,
            });
        }
        Ok(PayReceipt {
            tx_hash: receipt.transaction_hash,
            path: PayPath::SelfFunded,
            debtor,
            network: None,
        })
    }

    /// Claims the caller's committed net credit for a clearing cycle, sponsored where possible.
    ///
    /// Goes through the facilitator when one is configured, so the caller needs no native balance;
    /// falls back to the caller's own transaction when no facilitator is configured or the
    /// facilitator declines to sponsor. A rejection that names the claim itself — an unfunded
    /// cycle, say — is returned rather than retried, since the caller's own transaction would
    /// revert for the same reason after paying for the privilege.
    ///
    /// Read [`ClaimReceipt::path`] to see which route ran.
    pub async fn claim_net_credit(
        &self,
        cycle_id: String,
    ) -> Result<ClaimReceipt, ClearingSettlementError> {
        self.claim_net_credit_for(cycle_id, self.ctx.signer_address())
            .await
    }

    /// Claims `creditor`'s committed net credit, sponsored where possible.
    ///
    /// Takes no signature either way: the on-chain payout goes to the address the committed leaf
    /// names, for the amount that leaf fixes, so a submitter can neither redirect the payout nor
    /// inflate it. The only question is who pays the gas — the facilitator's relayer, or this
    /// caller as the fallback.
    pub async fn claim_net_credit_for(
        &self,
        cycle_id: String,
        creditor: Address,
    ) -> Result<ClaimReceipt, ClearingSettlementError> {
        if !self.is_gasless_available() {
            return self
                .claim_net_credit_self_funded_for(cycle_id, creditor)
                .await;
        }
        match self
            .claim_net_credit_gasless_for(cycle_id.clone(), creditor)
            .await
        {
            Err(err) if sponsorship_unavailable(&err, names_the_claim) => {
                self.claim_net_credit_self_funded_for(cycle_id, creditor)
                    .await
            }
            outcome => outcome,
        }
    }

    /// Claims the caller's committed net credit with their own transaction.
    pub async fn claim_net_credit_self_funded(
        &self,
        cycle_id: String,
    ) -> Result<ClaimReceipt, ClearingSettlementError> {
        self.claim_net_credit_self_funded_for(cycle_id, self.ctx.signer_address())
            .await
    }

    /// Claims `creditor`'s committed net credit with the caller's own transaction, paying the
    /// creditor rather than the caller — who may of course be the same account.
    pub async fn claim_net_credit_self_funded_for(
        &self,
        cycle_id: String,
        creditor: Address,
    ) -> Result<ClaimReceipt, ClearingSettlementError> {
        let action = self.claim_net_credit_action_for(cycle_id, creditor).await?;
        confirm_echoed(
            "participant",
            Some(&action.participant),
            creditor,
            ClearingSettlementError::InvalidParams,
        )?;
        if action.function_name != "claimNetCreditFor" {
            return Err(ClearingSettlementError::InvalidParams(format!(
                "core prepared {}, expected claimNetCreditFor",
                action.function_name
            )));
        }
        let call = ClearingActionCall::parse(&action)?;
        let contract = self
            .ctx
            .get_clearing_house_write_contract(call.contract_address)
            .await?;

        let sent = contract
            .claimNetCreditFor(creditor, call.cycle_id, call.amount, call.proof)
            .send()
            .await;
        let receipt = await_receipt(sent).await?;
        if !receipt.status() {
            return Err(ClearingSettlementError::RevertedOnChain {
                tx_hash: receipt.transaction_hash,
            });
        }
        Ok(ClaimReceipt {
            tx_hash: receipt.transaction_hash,
            path: ClaimPath::SelfFunded,
            creditor,
            network: None,
        })
    }

    /// Approves the contract that settles `cycle_id` to spend `amount` of `token`.
    pub async fn approve_erc20(
        &self,
        cycle_id: String,
        token: String,
        amount: U256,
    ) -> Result<TransactionReceipt, ApproveErc20Error> {
        let action = self
            .pay_net_debit_action(cycle_id)
            .await
            .map_err(|err| ApproveErc20Error::InvalidParams(err.to_string()))?;
        let spender = validate_address(&action.contract_address).map_err(|_| {
            ApproveErc20Error::InvalidParams(format!(
                "invalid ClearingHouse address: {}",
                action.contract_address
            ))
        })?;
        let token = validate_address(&token).map_err(|_| {
            ApproveErc20Error::InvalidParams(format!("invalid ERC20 token address: {token}"))
        })?;
        let contract = self.ctx.get_erc20_write_contract(token).await?;

        Ok(await_receipt(contract.approve(spender, amount).send().await).await?)
    }
}

/// Whether an error means "nobody sponsored this", as opposed to "this request is bad" or "we do
/// not know what happened". Only the first is worth falling back on: a rejection that names the
/// request (per `names_the_request`) would revert the caller's own transaction too, after they had
/// paid for it, and an unknown outcome may mean the facilitator already submitted — a second
/// attempt then reverts as `AlreadyClaimed`/`AlreadyPaid` after paying gas.
fn sponsorship_unavailable(
    err: &ClearingSettlementError,
    names_the_request: fn(&str) -> bool,
) -> bool {
    match err {
        ClearingSettlementError::Sponsorship(SponsorshipError::Rejected { code, .. }) => {
            !names_the_request(code)
        }
        ClearingSettlementError::Sponsorship(SponsorshipError::OutcomeUnknown(_)) => false,
        ClearingSettlementError::Sponsorship(_) => true,
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
fn unsponsorable(err: ClearingSettlementError) -> ClearingSettlementError {
    match err {
        ClearingSettlementError::Permit2AllowanceRequired { message, .. } => {
            ClearingSettlementError::Permit2AllowanceRequired {
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
fn refuses_the_authorization(err: &ClearingSettlementError) -> bool {
    matches!(
        err,
        ClearingSettlementError::Sponsorship(SponsorshipError::Rejected { code, .. })
            if code == "SIMULATION_REVERTED" || code == "UNSUPPORTED_TRANSFER_METHOD"
    ) || matches!(
        err,
        ClearingSettlementError::Client(ClientError::MissingTokenDomainSeparator { .. })
    )
}

/// The action's cycle asset, `Address::ZERO` for a native-asset cycle.
fn cycle_asset(
    action: &ClearingSettlementActionResponse,
) -> Result<Address, ClearingSettlementError> {
    validate_address(&action.asset_address).map_err(|err| {
        ClearingSettlementError::InvalidParams(format!("invalid cycle asset: {err}"))
    })
}

/// Validates a pay action against the caller before any money moves: core must have prepared a
/// debit for this debtor, not some other action or participant.
fn checked_pay_call(
    action: &ClearingSettlementActionResponse,
    debtor: Address,
) -> Result<ClearingActionCall, ClearingSettlementError> {
    confirm_echoed(
        "participant",
        Some(&action.participant),
        debtor,
        ClearingSettlementError::InvalidParams,
    )?;
    if action.function_name != "payNetDebit" {
        return Err(ClearingSettlementError::InvalidParams(format!(
            "core prepared {}, expected payNetDebit",
            action.function_name
        )));
    }
    ClearingActionCall::parse(action)
}

/// Wire format for `POST /clearing/claim`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct FacilitatorClaimRequest {
    cycle_id: String,
    creditor: Address,
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
            path: ClaimPath::Sponsored,
            creditor: confirm_echoed(
                "creditor",
                self.creditor.as_deref(),
                creditor,
                SponsorshipError::OutcomeUnknown,
            )?,
            network: self.network,
        })
    }
}

/// Wire format for `POST /clearing/pay`.
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
    fn into_receipt(self, debtor: Address) -> Result<PayReceipt, ClearingSettlementError> {
        if !self.success {
            // The one rejection with detail to unpack: the missing-allowance nonce is what lets
            // the sponsored-Permit2 route sign the approval instead of surrendering.
            let eip2612_nonce = self.failure.eip2612_nonce();
            return Err(match self.failure.into_sponsorship_error(self.error) {
                SponsorshipError::Rejected { code, message, .. }
                    if code == "PERMIT2_ALLOWANCE_REQUIRED" =>
                {
                    ClearingSettlementError::Permit2AllowanceRequired {
                        message,
                        eip2612_nonce,
                    }
                }
                other => other.into(),
            });
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
            path: PayPath::Sponsored,
            debtor: confirm_echoed(
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
    fn parse(action: &ClearingSettlementActionResponse) -> Result<Self, ClearingSettlementError> {
        let contract_address = validate_address(&action.contract_address)
            .map_err(|err| ClearingSettlementError::InvalidParams(err.to_string()))?;
        let cycle_id = B256::from_str(&action.cycle_id).map_err(|err| {
            ClearingSettlementError::InvalidParams(format!("invalid clearing cycle id: {err}"))
        })?;
        let amount = U256::from_str(&action.amount).map_err(|err| {
            ClearingSettlementError::InvalidParams(format!("invalid clearing amount: {err}"))
        })?;
        let payable_value = U256::from_str(&action.payable_value).map_err(|err| {
            ClearingSettlementError::InvalidParams(format!("invalid payable value: {err}"))
        })?;
        let proof = action
            .proof
            .iter()
            .map(|item| {
                B256::from_str(item).map_err(|err| {
                    ClearingSettlementError::InvalidParams(format!(
                        "invalid clearing proof element: {err}"
                    ))
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
