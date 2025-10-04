use alloy::primitives::U256;
use rpc::{
    common::{PaymentGuaranteeClaims, SigningScheme},
    core::CoreApiClient,
};

use crate::{Error4Mica, PaymentSignature, client::ClientCtx, sig::PaymentSigner};

#[derive(Clone)]
pub struct UserClient {
    ctx: ClientCtx,
}

impl UserClient {
    pub(super) fn new(ctx: ClientCtx) -> Self {
        Self { ctx }
    }

    pub async fn sign_payment(
        &self,
        claims: PaymentGuaranteeClaims,
        scheme: SigningScheme,
    ) -> Result<PaymentSignature, Error4Mica> {
        // TODO: Cache public parameters for a limited time
        let pub_params = self.ctx.rpc_proxy().get_public_params().await?;

        let sig = self
            .ctx
            .signer()
            .sign_request(&pub_params, claims, scheme)
            .await?;

        Ok(sig)
    }

    pub async fn deposit(&self, amount: U256) -> Result<(), Error4Mica> {
        let send_result = self
            .ctx
            .get_contract()
            .deposit()
            .value(amount)
            .send()
            .await?;
        let _receipt = send_result
            .watch()
            .await
            .map_err(|e| alloy::contract::Error::from(e))?;

        Ok(())
    }

    pub async fn request_withdrawal(&self, amount: U256) -> Result<(), Error4Mica> {
        let send_result = self
            .ctx
            .get_contract()
            .requestWithdrawal(amount)
            .send()
            .await?;
        let _receipt = send_result
            .watch()
            .await
            .map_err(|e| alloy::contract::Error::from(e))?;

        Ok(())
    }

    pub async fn cancel_withdrawal(&self) -> Result<(), Error4Mica> {
        let send_result = self.ctx.get_contract().cancelWithdrawal().send().await?;
        let _receipt = send_result
            .watch()
            .await
            .map_err(|e| alloy::contract::Error::from(e))?;

        Ok(())
    }

    pub async fn finalize_withdrawal(&self) -> Result<(), Error4Mica> {
        let send_result = self.ctx.get_contract().finalizeWithdrawal().send().await?;
        let _receipt = send_result
            .watch()
            .await
            .map_err(|e| alloy::contract::Error::from(e))?;

        Ok(())
    }
}
