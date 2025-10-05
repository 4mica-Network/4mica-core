use alloy::{primitives::U256, rpc::types::TransactionReceipt};
use crypto::bls::BLSCert;
use rpc::{
    common::{
        CreatePaymentTabRequest, PaymentGuaranteeClaims, PaymentGuaranteeRequest, SigningScheme,
    },
    core::CoreApiClient,
};

use crate::{
    client::{ClientCtx, model::TabPaymentStatus},
    contract::Core4Mica::Guarantee,
    error::Error4Mica,
};

#[derive(Clone)]
pub struct RecipientClient {
    ctx: ClientCtx,
}

impl RecipientClient {
    pub(super) fn new(ctx: ClientCtx) -> Self {
        Self { ctx }
    }

    fn check_signer_address(&self, expected: &str) -> Result<(), Error4Mica> {
        let signer_address = self.ctx.signer().address();
        if signer_address.to_string() != expected {
            return Err(Error4Mica::InvalidParams(
                "signer address does not match recipient address".into(),
            ));
        }

        Ok(())
    }

    /// Creates a new payment tab and returns the tab id
    pub async fn create_tab(
        &self,
        user_address: String,
        recipient_address: String,
        ttl: Option<u64>,
    ) -> Result<U256, Error4Mica> {
        self.check_signer_address(&recipient_address)?;

        let result = self
            .ctx
            .rpc_proxy()
            .create_payment_tab(CreatePaymentTabRequest {
                user_address,
                recipient_address,
                ttl,
            })
            .await?;
        Ok(result.id)
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

    pub async fn issue_payment_guarantee(
        &self,
        claims: PaymentGuaranteeClaims,
        signature: String,
        scheme: SigningScheme,
    ) -> Result<BLSCert, Error4Mica> {
        self.check_signer_address(&claims.recipient_address)?;

        let cert = self
            .ctx
            .rpc_proxy()
            .issue_guarantee(PaymentGuaranteeRequest {
                claims,
                signature,
                scheme,
            })
            .await?;
        Ok(cert)
    }

    pub async fn remunerate(&self, cert: BLSCert) -> Result<TransactionReceipt, Error4Mica> {
        let claims = crypto::hex::decode_hex(&cert.claims)
            .map_err(|e| Error4Mica::InvalidParams(format!("failed to parse claims: {}", e)))?;
        let claims = PaymentGuaranteeClaims::try_from(claims.as_slice())
            .map_err(|e| Error4Mica::InvalidParams(format!("failed to decode claims: {}", e)))?;

        let guarantee: Guarantee = claims.try_into()?;

        let sig = crypto::hex::decode_hex(&cert.signature)
            .map_err(|e| Error4Mica::InvalidParams(format!("Invalid signature: {}", e)))?;

        let sig_words = crypto::bls::g2_words_from_signature(sig.as_slice())
            .map_err(|e| Error4Mica::InvalidParams(format!("Invalid signature: {}", e)))?;

        let send_result = self
            .ctx
            .get_contract()
            .remunerate(guarantee, sig_words.into())
            .send()
            .await?;

        let receipt = send_result
            .get_receipt()
            .await
            .map_err(|e| alloy::contract::Error::from(e))?;

        Ok(receipt)
    }
}
