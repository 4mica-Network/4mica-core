use alloy::{
    network::TransactionBuilder,
    primitives::{Address, U256},
    providers::Provider,
    rpc::types::{TransactionReceipt, TransactionRequest},
};
use rpc::common::{PaymentGuaranteeClaims, SigningScheme};

use crate::{
    PaymentSignature,
    client::{
        ClientCtx,
        model::{TabPaymentStatus, UserInfo},
    },
    error::{
        ApproveErc20Error, CancelWithdrawalError, DepositError, FinalizeWithdrawalError,
        GetUserError, PayTabError, RequestWithdrawalError, SignPaymentError, TabPaymentStatusError,
    },
    sig::PaymentSigner,
    validators::validate_address,
};

#[derive(Clone)]
pub struct UserClient {
    ctx: ClientCtx,
}

impl UserClient {
    pub(super) fn new(ctx: ClientCtx) -> Self {
        Self { ctx }
    }

    /// Allows the 4mica contract to spend ERC20 tokens on behalf of the user
    ///
    /// ### Arguments
    ///
    /// * `token` - The address of the ERC20 token
    /// * `amount` - The amount of tokens the 4Mica contract is allowed to spend
    pub async fn approve_erc20(
        &self,
        token: String,
        amount: U256,
    ) -> Result<TransactionReceipt, ApproveErc20Error> {
        let token = validate_address(&token).map_err(|_| {
            ApproveErc20Error::InvalidParams(format!("invalid ERC20 token address: {token}"))
        })?;

        let spender = self.ctx.contract_address();
        let contract = self.ctx.get_erc20_contract(token);

        let send_result = contract
            .approve(spender, amount)
            .send()
            .await
            .map_err(ApproveErc20Error::from)?;

        let receipt = send_result
            .get_receipt()
            .await
            .map_err(alloy::contract::Error::from)
            .map_err(ApproveErc20Error::from)?;

        Ok(receipt)
    }

    /// Deposits collateral into the user's account
    ///
    /// ### Arguments
    ///
    /// * `amount` - The amount of collateral to deposit
    /// * `erc20_token` - The address of the ERC20 token to use for the payment, leave as `None` for ETH
    ///
    /// IMPORTANT: If depositing with an ERC20 token, you MUST first approve the 4Mica contract to spend the ERC20 token using the `approve_erc20` method.
    pub async fn deposit(
        &self,
        amount: U256,
        erc20_token: Option<String>,
    ) -> Result<TransactionReceipt, DepositError> {
        let send_result = if let Some(token) = erc20_token {
            let token = validate_address(&token).map_err(|_| {
                DepositError::InvalidParams(format!("invalid ERC20 token address: {token}"))
            })?;
            self.ctx
                .get_contract()
                .depositStablecoin(token, amount)
                .send()
                .await
        } else {
            self.ctx.get_contract().deposit().value(amount).send().await
        };

        let receipt = send_result
            .map_err(DepositError::from)?
            .get_receipt()
            .await
            .map_err(alloy::contract::Error::from)
            .map_err(DepositError::from)?;

        Ok(receipt)
    }

    /// Returns information about user's assets and withdrawal requests
    pub async fn get_user(&self) -> Result<Vec<UserInfo>, GetUserError> {
        let signer_address = self.ctx.signer().address();
        let assets = self
            .ctx
            .get_contract()
            .getUserAllAssets(signer_address)
            .call()
            .await
            .map_err(GetUserError::from)?;

        Ok(assets.into_iter().map(|asset| asset.into()).collect())
    }

    pub async fn get_tab_payment_status(
        &self,
        tab_id: U256,
    ) -> Result<TabPaymentStatus, TabPaymentStatusError> {
        let status = self
            .ctx
            .get_contract()
            .getPaymentStatus(tab_id)
            .call()
            .await
            .map_err(TabPaymentStatusError::from)?;

        Ok(TabPaymentStatus {
            paid: status.paid,
            remunerated: status.remunerated,
            asset: status.asset.to_string(),
        })
    }

    pub async fn sign_payment(
        &self,
        claims: PaymentGuaranteeClaims,
        scheme: SigningScheme,
    ) -> Result<PaymentSignature, SignPaymentError> {
        // TODO: Cache public parameters for a while
        let pub_params = self.ctx.rpc_proxy().get_public_params().await?;

        let sig = self
            .ctx
            .signer()
            .sign_request(&pub_params, claims, scheme)
            .await?;

        Ok(sig)
    }

    async fn pay_tab_in_erc20_token(
        &self,
        tab_id: U256,
        amount: U256,
        erc20_token: String,
        recipient: Address,
    ) -> Result<TransactionReceipt, PayTabError> {
        let token = validate_address(&erc20_token).map_err(|_| {
            PayTabError::InvalidParams(format!("invalid ERC20 token address: {erc20_token}"))
        })?;

        let send_result = self
            .ctx
            .get_contract()
            .payTabInERC20Token(tab_id, token, amount, recipient)
            .send()
            .await
            .map_err(PayTabError::from)?;

        let receipt = send_result
            .get_receipt()
            .await
            .map_err(alloy::contract::Error::from)
            .map_err(PayTabError::from)?;

        Ok(receipt)
    }

    /// Pay a tab in ETH or an ERC20 token
    ///
    /// If `erc20_token` is provided, the tab will be paid in the specified ERC20 token.
    /// Otherwise, the tab will be paid in ETH.
    ///
    /// NOTE: You can only pay with the same asset as the one that the tab was created with.
    ///
    /// IMPORTANT: If paying with an ERC20 token, you MUST first approve the 4Mica contract to spend the ERC20 token using the `approve_erc20` method.
    pub async fn pay_tab(
        &self,
        tab_id: U256,
        req_id: U256,
        amount: U256,
        recipient_address: String,
        erc20_token: Option<String>,
    ) -> Result<TransactionReceipt, PayTabError> {
        let recipient = validate_address(&recipient_address)
            .map_err(|e| PayTabError::InvalidParams(e.to_string()))?;

        if let Some(token) = erc20_token {
            return self
                .pay_tab_in_erc20_token(tab_id, amount, token, recipient)
                .await;
        }

        let input = format!("tab_id:{:#x};req_id:{:#x}", tab_id, req_id);
        let tx = TransactionRequest::default()
            .with_to(recipient)
            .with_value(amount)
            .with_input(input.into_bytes())
            .with_gas_limit(120_000u64);

        let pending_tx = self
            .ctx
            .provider()
            .send_transaction(tx)
            .await
            .map_err(|e| PayTabError::Transport(e.to_string()))?;
        let receipt = pending_tx
            .get_receipt()
            .await
            .map_err(|e| PayTabError::Transport(e.to_string()))?;

        Ok(receipt)
    }

    /// Requests a withdrawal of collateral from the user's account
    ///
    /// ### Arguments
    ///
    /// * `amount` - The amount of collateral to withdraw
    /// * `erc20_token` - The address of the ERC20 token to use for the withdrawal, leave as `None` for ETH
    pub async fn request_withdrawal(
        &self,
        amount: U256,
        erc20_token: Option<String>,
    ) -> Result<TransactionReceipt, RequestWithdrawalError> {
        let send_result = if let Some(token) = erc20_token {
            let token = validate_address(&token).map_err(|_| {
                RequestWithdrawalError::InvalidParams(format!(
                    "invalid ERC20 token address: {token}"
                ))
            })?;
            self.ctx
                .get_contract()
                .requestWithdrawal_1(token, amount)
                .send()
                .await
        } else {
            self.ctx
                .get_contract()
                .requestWithdrawal_0(amount)
                .send()
                .await
        };

        let receipt = send_result
            .map_err(RequestWithdrawalError::from)?
            .get_receipt()
            .await
            .map_err(alloy::contract::Error::from)
            .map_err(RequestWithdrawalError::from)?;

        Ok(receipt)
    }

    /// Cancels a pending withdrawal request
    ///
    /// ### Arguments
    ///
    /// * `erc20_token` - The address of the ERC20 token to use for the withdrawal, leave as `None` for ETH
    pub async fn cancel_withdrawal(
        &self,
        erc20_token: Option<String>,
    ) -> Result<TransactionReceipt, CancelWithdrawalError> {
        let send_result = if let Some(token) = erc20_token {
            let token = validate_address(&token).map_err(|_| {
                CancelWithdrawalError::InvalidParams(format!(
                    "invalid ERC20 token address: {token}"
                ))
            })?;
            self.ctx
                .get_contract()
                .cancelWithdrawal_1(token)
                .send()
                .await
        } else {
            self.ctx.get_contract().cancelWithdrawal_0().send().await
        };

        let receipt = send_result
            .map_err(CancelWithdrawalError::from)?
            .get_receipt()
            .await
            .map_err(alloy::contract::Error::from)
            .map_err(CancelWithdrawalError::from)?;

        Ok(receipt)
    }

    /// Finalizes a withdrawal request after the waiting period
    ///
    /// ### Arguments
    ///
    /// * `erc20_token` - The address of the ERC20 token to use for the withdrawal, leave as `None` for ETH
    pub async fn finalize_withdrawal(
        &self,
        erc20_token: Option<String>,
    ) -> Result<TransactionReceipt, FinalizeWithdrawalError> {
        let send_result = if let Some(token) = erc20_token {
            let token = validate_address(&token).map_err(|_| {
                FinalizeWithdrawalError::InvalidParams(format!(
                    "invalid ERC20 token address: {token}"
                ))
            })?;
            self.ctx
                .get_contract()
                .finalizeWithdrawal_1(token)
                .send()
                .await
        } else {
            self.ctx.get_contract().finalizeWithdrawal_0().send().await
        };

        let receipt = send_result
            .map_err(FinalizeWithdrawalError::from)?
            .get_receipt()
            .await
            .map_err(alloy::contract::Error::from)
            .map_err(FinalizeWithdrawalError::from)?;

        Ok(receipt)
    }
}
