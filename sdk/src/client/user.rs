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
    Error4Mica, PaymentSignature,
    client::{
        ClientCtx,
        model::{TabPaymentStatus, UserInfo},
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

    pub async fn deposit(&self, amount: U256) -> Result<TransactionReceipt, Error4Mica> {
        let send_result = self
            .ctx
            .get_contract()
            .deposit()
            .value(amount)
            .send()
            .await?;
        let receipt = send_result
            .get_receipt()
            .await
            .map_err(|e| alloy::contract::Error::from(e))?;

        Ok(receipt)
    }

    pub async fn get_user(&self) -> Result<UserInfo, Error4Mica> {
        let signer_address = self.ctx.signer().address();
        let user = self
            .ctx
            .get_contract()
            .getUser(signer_address)
            .call()
            .await?;
        Ok(user.into())
    }

    pub async fn get_tab_payment_status(
        &self,
        tab_id: U256,
    ) -> Result<TabPaymentStatus, Error4Mica> {
        let status = self
            .ctx
            .get_contract()
            .getPaymentStatus(tab_id)
            .call()
            .await?;

        Ok(TabPaymentStatus {
            paid: status.paid,
            remunerated: status.remunerated,
        })
    }

    pub async fn sign_payment(
        &self,
        claims: PaymentGuaranteeClaims,
        scheme: SigningScheme,
    ) -> Result<PaymentSignature, Error4Mica> {
        // TODO: Cache public parameters for a while
        let pub_params = self.ctx.rpc_proxy().get_public_params().await?;

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
    ) -> Result<TransactionReceipt, Error4Mica> {
        let recipient = validate_address(&recipient_address)?;

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
            .map_err(|e| Error4Mica::Other(e.into()))?;
        let receipt = pending_tx
            .get_receipt()
            .await
            .map_err(|e| alloy::contract::Error::from(e))?;

        Ok(receipt)
    }

    pub async fn request_withdrawal(&self, amount: U256) -> Result<TransactionReceipt, Error4Mica> {
        let send_result = self
            .ctx
            .get_contract()
            .requestWithdrawal(amount)
            .send()
            .await?;
        let receipt = send_result
            .get_receipt()
            .await
            .map_err(|e| alloy::contract::Error::from(e))?;

        Ok(receipt)
    }

    pub async fn cancel_withdrawal(&self) -> Result<TransactionReceipt, Error4Mica> {
        let send_result = self.ctx.get_contract().cancelWithdrawal().send().await?;
        let receipt = send_result
            .get_receipt()
            .await
            .map_err(|e| alloy::contract::Error::from(e))?;

        Ok(receipt)
    }

    pub async fn finalize_withdrawal(&self) -> Result<TransactionReceipt, Error4Mica> {
        let send_result = self.ctx.get_contract().finalizeWithdrawal().send().await?;
        let receipt = send_result
            .get_receipt()
            .await
            .map_err(|e| alloy::contract::Error::from(e))?;

        Ok(receipt)
    }
}
