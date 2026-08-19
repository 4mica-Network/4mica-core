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
        model::{ClaimPath, ClaimReceipt},
    },
    error::{ApproveErc20Error, ClearingSettlementError, SponsorshipError},
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
    S: Signer + TxSigner<Signature> + Send + Sync + Clone + 'static,
{
    /// Pays the caller's committed net debit for a clearing cycle.
    ///
    /// For ERC-20 cycles, grant the allowance with [`Self::approve_erc20`] first.
    pub async fn pay_net_debit(
        &self,
        cycle_id: String,
    ) -> Result<TransactionReceipt, ClearingSettlementError> {
        let action = self.pay_net_debit_action(cycle_id).await?;
        let call = ClearingActionCall::parse(&action)?;
        let contract = self
            .ctx
            .get_clearing_house_write_contract(call.contract_address)
            .await?;

        Ok(await_receipt(
            contract
                .payNetDebit(call.cycle_id, call.amount, call.proof)
                .value(call.payable_value)
                .send()
                .await,
        )
        .await?)
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
            Err(err) if sponsorship_unavailable(&err) => {
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

/// Whether an error means "nobody sponsored this", as opposed to "this claim is bad" or "we do not
/// know what happened". Only the first is worth falling back on: a rejection that names the claim
/// would revert the caller's own transaction too, after they had paid for it, and an unknown
/// outcome may mean the facilitator already submitted — a second claim then reverts as
/// `AlreadyClaimed` after paying gas.
fn sponsorship_unavailable(err: &ClearingSettlementError) -> bool {
    match err {
        ClearingSettlementError::Sponsorship(SponsorshipError::Rejected { code, .. }) => {
            !names_the_claim(code)
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
