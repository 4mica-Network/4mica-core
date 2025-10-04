use std::str::FromStr;

use crypto::{bls::BLSCert, hex::HexBytes};
use rpc::{
    common::{PaymentGuaranteeClaims, PaymentGuaranteeRequest},
    core::CoreApiClient,
};

use crate::{client::ClientCtx, contract::Core4Mica::Guarantee, error::Error4Mica};

#[derive(Clone)]
pub struct RecipientClient {
    ctx: ClientCtx,
}

impl RecipientClient {
    pub(super) fn new(ctx: ClientCtx) -> Self {
        Self { ctx }
    }

    pub async fn issue_payment_guarantee(
        &self,
        req: PaymentGuaranteeRequest,
    ) -> Result<BLSCert, Error4Mica> {
        let cert = self.ctx.rpc_proxy().issue_guarantee(req).await?;
        Ok(cert)
    }

    pub async fn remunerate(&self, cert: BLSCert) -> Result<(), Error4Mica> {
        let claims = HexBytes::from_str(&cert.claims)
            .map_err(|e| Error4Mica::InvalidParams(format!("failed to parse claims: {}", e)))?;
        let claims = PaymentGuaranteeClaims::try_from(claims.bytes())
            .map_err(|e| Error4Mica::InvalidParams(format!("failed to decode claims: {}", e)))?;

        let guarantee: Guarantee = claims.try_into()?;

        let sig = HexBytes::from_str(&cert.signature)
            .map_err(|e| Error4Mica::InvalidParams(format!("Invalid signature: {}", e)))?;

        let sig_words = crypto::bls::g2_words_from_signature(&sig.bytes())
            .map_err(|e| Error4Mica::InvalidParams(format!("Invalid signature: {}", e)))?;

        let send_result = self
            .ctx
            .get_contract()
            .remunerate(guarantee, sig_words.into())
            .send()
            .await?;

        let _receipt = send_result
            .watch()
            .await
            .map_err(|e| alloy::contract::Error::from(e))?;

        Ok(())
    }
}
