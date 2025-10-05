use alloy::{
    network::TransactionBuilder,
    primitives::U256,
    providers::Provider,
    rpc::types::{TransactionReceipt, TransactionRequest},
};
use rpc::{
    common::{PaymentGuaranteeClaims, SigningScheme},
    core::CoreApiClient,
};

use crate::{
    PaymentSignature,
    client::{
        ClientCtx,
        model::{TabPaymentStatus, UserInfo},
    },
    error::{
        CancelWithdrawalError, DepositError, FinalizeWithdrawalError, GetUserError, PayTabError,
        RequestWithdrawalError, SignPaymentError, TabPaymentStatusError,
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

    pub async fn deposit(&self, amount: U256) -> Result<TransactionReceipt, DepositError> {
        let send_result = self
            .ctx
            .get_contract()
            .deposit()
            .value(amount)
            .send()
            .await
            .map_err(DepositError::from)?;
        let receipt = send_result
            .get_receipt()
            .await
            .map_err(|e| DepositError::from(alloy::contract::Error::from(e)))?;

        Ok(receipt)
    }

    pub async fn get_user(&self) -> Result<UserInfo, GetUserError> {
        let signer_address = self.ctx.signer().address();
        let user = self
            .ctx
            .get_contract()
            .getUser(signer_address)
            .call()
            .await
            .map_err(|e| GetUserError::from(alloy::contract::Error::from(e)))?;
        Ok(user.into())
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
            .map_err(|e| TabPaymentStatusError::from(alloy::contract::Error::from(e)))?;

        Ok(TabPaymentStatus {
            paid: status.paid,
            remunerated: status.remunerated,
        })
    }

    pub async fn sign_payment(
        &self,
        claims: PaymentGuaranteeClaims,
        scheme: SigningScheme,
    ) -> Result<PaymentSignature, SignPaymentError> {
        // TODO: Cache public parameters for a while
        let pub_params = self
            .ctx
            .rpc_proxy()
            .get_public_params()
            .await
            .map_err(|e| SignPaymentError::Rpc(e.to_string()))?;

        let sig = self
            .ctx
            .signer()
            .sign_request(&pub_params, claims, scheme)
            .await?;

        Ok(sig)
    }

    pub async fn pay_tab(
        &self,
        tab_id: U256,
        req_id: U256,
        amount: U256,
        recipient_address: String,
    ) -> Result<TransactionReceipt, PayTabError> {
        let recipient = validate_address(&recipient_address)
            .map_err(|e| PayTabError::InvalidParams(e.to_string()))?;

        let input = format!("tab_id:{:#x};req_id:{:#x}", tab_id, req_id);
        let tx = TransactionRequest::default()
            .with_to(recipient)
            .with_value(amount)
            .with_input(input.into_bytes());

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

    pub async fn request_withdrawal(
        &self,
        amount: U256,
    ) -> Result<TransactionReceipt, RequestWithdrawalError> {
        let send_result = self
            .ctx
            .get_contract()
            .requestWithdrawal(amount)
            .send()
            .await
            .map_err(RequestWithdrawalError::from)?;
        let receipt = send_result
            .get_receipt()
            .await
            .map_err(|e| RequestWithdrawalError::from(alloy::contract::Error::from(e)))?;

        Ok(receipt)
    }

    pub async fn cancel_withdrawal(&self) -> Result<TransactionReceipt, CancelWithdrawalError> {
        let send_result = self
            .ctx
            .get_contract()
            .cancelWithdrawal()
            .send()
            .await
            .map_err(CancelWithdrawalError::from)?;
        let receipt = send_result
            .get_receipt()
            .await
            .map_err(|e| CancelWithdrawalError::from(alloy::contract::Error::from(e)))?;

        Ok(receipt)
    }

    pub async fn finalize_withdrawal(&self) -> Result<TransactionReceipt, FinalizeWithdrawalError> {
        let send_result = self
            .ctx
            .get_contract()
            .finalizeWithdrawal()
            .send()
            .await
            .map_err(FinalizeWithdrawalError::from)?;
        let receipt = send_result
            .get_receipt()
            .await
            .map_err(|e| FinalizeWithdrawalError::from(alloy::contract::Error::from(e)))?;

        Ok(receipt)
    }
}
