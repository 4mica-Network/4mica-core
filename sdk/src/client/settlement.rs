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

use crate::{
    client::{ClientCtx, await_receipt},
    error::{ApproveErc20Error, ClearingSettlementError},
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

    /// Claims the caller's committed net credit for a clearing cycle.
    pub async fn claim_net_credit(
        &self,
        cycle_id: String,
    ) -> Result<TransactionReceipt, ClearingSettlementError> {
        self.claim_net_credit_for(cycle_id, self.ctx.signer_address())
            .await
    }

    /// Claims `creditor`'s committed net credit, paying them rather than the caller.
    ///
    /// Takes no signature: `claimNetCreditFor` pays the address the committed leaf names, for the
    /// amount that leaf fixes, so a submitter can neither redirect the payout nor inflate it. That
    /// makes it sponsorable — a creditor with no native balance still gets paid.
    pub async fn claim_net_credit_for(
        &self,
        cycle_id: String,
        creditor: Address,
    ) -> Result<TransactionReceipt, ClearingSettlementError> {
        let action = self.claim_net_credit_action_for(cycle_id, creditor).await?;
        let call = ClearingActionCall::parse(&action)?;
        let contract = self
            .ctx
            .get_clearing_house_write_contract(call.contract_address)
            .await?;

        Ok(await_receipt(
            contract
                .claimNetCreditFor(creditor, call.cycle_id, call.amount, call.proof)
                .send()
                .await,
        )
        .await?)
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
