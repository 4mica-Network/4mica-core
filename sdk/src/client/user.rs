use alloy::{
    network::{TransactionBuilder, TxSigner},
    primitives::{Address, U256},
    providers::Provider,
    rpc::types::{TransactionReceipt, TransactionRequest},
    signers::{Signature, Signer},
};
use rpc::{PaymentGuaranteeRequestClaimsV1, PaymentGuaranteeRequestClaimsV2, SigningScheme};

use crate::{
    PaymentSignature,
    client::{
        ClientCtx,
        model::{StablecoinPosition, TabPaymentStatus, UserInfo},
    },
    error::{
        ApproveErc20Error, CancelWithdrawalError, DepositError, FinalizeWithdrawalError,
        GetUserError, PayTabError, RequestWithdrawalError, SignPaymentError, TabPaymentStatusError,
    },
    guarantee::{
        PaymentGuaranteeIntent, PaymentGuaranteeValidationInput, PreparedPaymentGuaranteeClaims,
        PreparedPaymentGuaranteeRequest, prepare_payment_guarantee_claims,
    },
    sig::PaymentSigner,
    validators::validate_address,
};

#[derive(Clone)]
pub struct UserClient<S> {
    ctx: ClientCtx<S>,
}

impl<S> UserClient<S> {
    pub(super) fn new(ctx: ClientCtx<S>) -> Self {
        Self { ctx }
    }

    pub fn guarantee_domain(&self) -> &[u8; 32] {
        self.ctx.active_guarantee_domain()
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
    ) -> Result<TransactionReceipt, ApproveErc20Error>
    where
        S: TxSigner<Signature> + Send + Sync + Clone + 'static,
    {
        let token = validate_address(&token).map_err(|_| {
            ApproveErc20Error::InvalidParams(format!("invalid ERC20 token address: {token}"))
        })?;

        let spender = self.ctx.contract_address();
        let contract = self.ctx.get_erc20_write_contract(token).await?;

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
    ) -> Result<TransactionReceipt, DepositError>
    where
        S: TxSigner<Signature> + Send + Sync + Clone + 'static,
    {
        let send_result = if let Some(token) = erc20_token {
            let token = validate_address(&token).map_err(|_| {
                DepositError::InvalidParams(format!("invalid ERC20 token address: {token}"))
            })?;
            self.ctx
                .get_write_contract()
                .await?
                .depositStablecoin(token, amount)
                .send()
                .await
        } else {
            self.ctx
                .get_write_contract()
                .await?
                .deposit()
                .value(amount)
                .send()
                .await
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
    pub async fn get_user(&self) -> Result<Vec<UserInfo>, GetUserError>
    where
        S: Signer,
    {
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

    pub async fn get_principal_balance(&self, asset: String) -> Result<U256, GetUserError>
    where
        S: Signer,
    {
        let asset = validate_address(&asset).map_err(|_| {
            GetUserError::Transport(format!("invalid ERC20 token address: {asset}"))
        })?;
        let signer_address = self.ctx.signer_address();

        self.ctx
            .get_contract()
            .principalBalance(signer_address, asset)
            .call()
            .await
            .map_err(GetUserError::from)
    }

    pub async fn get_withdrawable_balance(&self, asset: String) -> Result<U256, GetUserError>
    where
        S: Signer,
    {
        let asset = validate_address(&asset).map_err(|_| {
            GetUserError::Transport(format!("invalid ERC20 token address: {asset}"))
        })?;
        let signer_address = self.ctx.signer_address();

        self.ctx
            .get_contract()
            .withdrawableBalance(signer_address, asset)
            .call()
            .await
            .map_err(GetUserError::from)
    }

    pub async fn get_stablecoin_position(
        &self,
        asset: String,
    ) -> Result<StablecoinPosition, GetUserError>
    where
        S: Signer,
    {
        let asset_address = validate_address(&asset).map_err(|_| {
            GetUserError::Transport(format!("invalid ERC20 token address: {asset}"))
        })?;
        let signer_address = self.ctx.signer_address();
        let contract = self.ctx.get_contract();

        let principal = contract
            .principalBalance(signer_address, asset_address)
            .call()
            .await
            .map_err(GetUserError::from)?;
        let guarantee_capacity = contract
            .guaranteeCapacity(signer_address, asset_address)
            .call()
            .await
            .map_err(GetUserError::from)?;
        let gross_yield = contract
            .grossYield(signer_address, asset_address)
            .call()
            .await
            .map_err(GetUserError::from)?;
        let protocol_yield_share = contract
            .protocolYieldShare(signer_address, asset_address)
            .call()
            .await
            .map_err(GetUserError::from)?;
        let user_net_yield = contract
            .userNetYield(signer_address, asset_address)
            .call()
            .await
            .map_err(GetUserError::from)?;
        let withdrawable_balance = contract
            .withdrawableBalance(signer_address, asset_address)
            .call()
            .await
            .map_err(GetUserError::from)?;
        let total_user_scaled_balance = contract
            .totalUserScaledBalance(asset_address)
            .call()
            .await
            .map_err(GetUserError::from)?;
        let protocol_scaled_balance = contract
            .protocolScaledBalance(asset_address)
            .call()
            .await
            .map_err(GetUserError::from)?;
        let surplus_scaled_balance = contract
            .surplusScaledBalance(asset_address)
            .call()
            .await
            .map_err(GetUserError::from)?;
        let contract_scaled_a_token_balance = contract
            .contractScaledATokenBalance(asset_address)
            .call()
            .await
            .map_err(GetUserError::from)?;
        let stablecoin_a_token = contract
            .stablecoinAToken(asset_address)
            .call()
            .await
            .map_err(GetUserError::from)?;
        let stablecoin_deposits_enabled = contract
            .stablecoinDepositsEnabled(asset_address)
            .call()
            .await
            .map_err(GetUserError::from)?;

        Ok(StablecoinPosition {
            asset,
            principal,
            guarantee_capacity,
            gross_yield,
            protocol_yield_share,
            user_net_yield,
            withdrawable_balance,
            total_user_scaled_balance,
            protocol_scaled_balance,
            surplus_scaled_balance,
            contract_scaled_a_token_balance,
            stablecoin_a_token: stablecoin_a_token.to_string(),
            stablecoin_deposits_enabled,
        })
    }

    pub async fn sign_payment(
        &self,
        claims: PaymentGuaranteeRequestClaimsV1,
        scheme: SigningScheme,
    ) -> Result<PaymentSignature, SignPaymentError>
    where
        S: Signer + Send + Sync,
    {
        // TODO: Cache public parameters for a while
        let pub_params = self.ctx.rpc_proxy().await?.get_public_params().await?;

        let sig = self
            .ctx
            .signer()
            .sign_request(&pub_params, claims, scheme)
            .await?;

        Ok(sig)
    }

    pub async fn sign_payment_v2(
        &self,
        claims: PaymentGuaranteeRequestClaimsV2,
        scheme: SigningScheme,
    ) -> Result<PaymentSignature, SignPaymentError>
    where
        S: Signer + Send + Sync,
    {
        // TODO: Cache public parameters for a while
        let pub_params = self.ctx.rpc_proxy().await?.get_public_params().await?;

        let sig = self
            .ctx
            .signer()
            .sign_request_v2(&pub_params, claims, scheme)
            .await?;

        Ok(sig)
    }

    pub async fn sign_payment_auto(
        &self,
        intent: PaymentGuaranteeIntent,
        validation: Option<PaymentGuaranteeValidationInput>,
        scheme: SigningScheme,
    ) -> Result<PreparedPaymentGuaranteeRequest, SignPaymentError>
    where
        S: Signer + Send + Sync,
    {
        let public_params = self.ctx.rpc_proxy().await?.get_public_params().await?;
        let claims = prepare_payment_guarantee_claims(&public_params, intent, validation)
            .map_err(|err| SignPaymentError::InvalidParams(err.to_string()))?;

        let signature = match &claims {
            PreparedPaymentGuaranteeClaims::V1(claims) => {
                self.ctx
                    .signer()
                    .sign_request(&public_params, claims.clone(), scheme)
                    .await?
            }
            PreparedPaymentGuaranteeClaims::V2(claims) => {
                self.ctx
                    .signer()
                    .sign_request_v2(&public_params, claims.as_ref().clone(), scheme)
                    .await?
            }
        };

        Ok(PreparedPaymentGuaranteeRequest {
            claims,
            signature: signature.signature,
            scheme: signature.scheme,
        })
    }

    async fn pay_tab_in_erc20_token(
        &self,
        tab_id: U256,
        amount: U256,
        erc20_token: String,
        recipient: Address,
    ) -> Result<TransactionReceipt, PayTabError>
    where
        S: TxSigner<Signature> + Send + Sync + Clone + 'static,
    {
        let token = validate_address(&erc20_token).map_err(|_| {
            PayTabError::InvalidParams(format!("invalid ERC20 token address: {erc20_token}"))
        })?;

        let send_result = self
            .ctx
            .get_write_contract()
            .await?
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
    ) -> Result<TransactionReceipt, PayTabError>
    where
        S: TxSigner<Signature> + Send + Sync + Clone + 'static,
    {
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
            .get_wallet_provider()
            .await?
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
    ) -> Result<TransactionReceipt, RequestWithdrawalError>
    where
        S: TxSigner<Signature> + Send + Sync + Clone + 'static,
    {
        let contract = self.ctx.get_write_contract().await?;
        let send_result =
            match parse_erc20_token(erc20_token, RequestWithdrawalError::InvalidParams)? {
                Some(token) => contract.requestWithdrawal_1(token, amount).send().await,
                None => contract.requestWithdrawal_0(amount).send().await,
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
    ) -> Result<TransactionReceipt, CancelWithdrawalError>
    where
        S: TxSigner<Signature> + Send + Sync + Clone + 'static,
    {
        let contract = self.ctx.get_write_contract().await?;
        let send_result =
            match parse_erc20_token(erc20_token, CancelWithdrawalError::InvalidParams)? {
                Some(token) => contract.cancelWithdrawal_1(token).send().await,
                None => contract.cancelWithdrawal_0().send().await,
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
    ) -> Result<TransactionReceipt, FinalizeWithdrawalError>
    where
        S: TxSigner<Signature> + Send + Sync + Clone + 'static,
    {
        let contract = self.ctx.get_write_contract().await?;
        let send_result =
            match parse_erc20_token(erc20_token, FinalizeWithdrawalError::InvalidParams)? {
                Some(token) => contract.finalizeWithdrawal_1(token).send().await,
                None => contract.finalizeWithdrawal_0().send().await,
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

/// Parses an optional ERC-20 token string into an `Option<Address>`.
/// Returns an error produced by `make_err` if the address string is present but invalid.
fn parse_erc20_token<E>(
    token: Option<String>,
    make_err: impl FnOnce(String) -> E,
) -> Result<Option<Address>, E> {
    match token {
        Some(t) => validate_address(&t)
            .map(Some)
            .map_err(|_| make_err(format!("invalid ERC20 token address: {t}"))),
        None => Ok(None),
    }
}
