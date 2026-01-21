use alloy::{primitives::U256, rpc::types::TransactionReceipt};
use crypto::bls::BLSCert;
use rpc::{
    CreatePaymentTabRequest, PaymentGuaranteeClaims, PaymentGuaranteeRequest,
    PaymentGuaranteeRequestClaims, PaymentGuaranteeRequestClaimsV1, SigningScheme,
};

use crate::{
    client::model::{
        AssetBalanceInfo, CollateralEventInfo, GuaranteeInfo, PendingRemunerationInfo,
        RecipientPaymentInfo, TabInfo,
    },
    client::{ClientCtx, model::TabPaymentStatus},
    error::{
        CreateTabError, IssuePaymentGuaranteeError, RecipientQueryError, RemunerateError,
        TabPaymentStatusError, VerifyGuaranteeError,
    },
};

#[derive(Clone)]
pub struct RecipientClient {
    ctx: ClientCtx,
}

impl RecipientClient {
    pub(super) fn new(ctx: ClientCtx) -> Self {
        Self { ctx }
    }

    fn check_signer_address(&self, expected: &str) -> bool {
        let signer_address = self.ctx.signer().address();
        signer_address.to_string() == expected
    }

    pub fn guarantee_domain(&self) -> &[u8; 32] {
        self.ctx.guarantee_domain()
    }

    /// Creates a new payment tab and returns the tab id
    ///
    /// ### Arguments
    ///
    /// * `user_address` - The address of the user who is creating the tab
    /// * `recipient_address` - The address of the recipient who will receive the payment
    /// * `erc20_token` - The address of the ERC20 token to use for the payment, leave as `None` for ETH
    /// * `ttl` - The time to live for the tab in seconds
    pub async fn create_tab(
        &self,
        user_address: String,
        recipient_address: String,
        erc20_token: Option<String>,
        ttl: Option<u64>,
    ) -> Result<U256, CreateTabError> {
        if !self.check_signer_address(&recipient_address) {
            return Err(CreateTabError::InvalidParams(
                "signer address does not match recipient address".into(),
            ));
        }

        let result = self
            .ctx
            .rpc_proxy()
            .await?
            .create_payment_tab(CreatePaymentTabRequest {
                user_address,
                recipient_address,
                erc20_token,
                ttl,
            })
            .await?;
        Ok(result.id)
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

    pub async fn issue_payment_guarantee(
        &self,
        claims: PaymentGuaranteeRequestClaimsV1,
        signature: String,
        scheme: SigningScheme,
    ) -> Result<BLSCert, IssuePaymentGuaranteeError> {
        if !self.check_signer_address(&claims.user_address) {
            return Err(IssuePaymentGuaranteeError::InvalidParams(
                "signer address does not match user address".into(),
            ));
        }

        let cert = self
            .ctx
            .rpc_proxy()
            .await?
            .issue_guarantee(PaymentGuaranteeRequest::new(
                PaymentGuaranteeRequestClaims::V1(claims),
                signature,
                scheme,
            ))
            .await?;
        Ok(cert)
    }

    pub fn verify_payment_guarantee(
        &self,
        cert: &BLSCert,
    ) -> Result<PaymentGuaranteeClaims, VerifyGuaranteeError> {
        let is_valid = cert
            .verify(self.ctx.operator_public_key())
            .map_err(VerifyGuaranteeError::InvalidCertificate)?;
        if !is_valid {
            return Err(VerifyGuaranteeError::CertificateMismatch);
        }

        let claims_bytes = cert
            .claims_bytes()
            .map_err(VerifyGuaranteeError::InvalidCertificate)?;
        let claims = PaymentGuaranteeClaims::try_from(claims_bytes.as_slice())
            .map_err(VerifyGuaranteeError::InvalidCertificate)?;

        if claims.domain != *self.guarantee_domain() {
            return Err(VerifyGuaranteeError::GuaranteeDomainMismatch);
        }
        Ok(claims)
    }

    pub async fn remunerate(&self, cert: BLSCert) -> Result<TransactionReceipt, RemunerateError> {
        self.verify_payment_guarantee(&cert)
            .map_err(|err| match err {
                VerifyGuaranteeError::InvalidCertificate(source) => {
                    RemunerateError::CertificateInvalid(source)
                }
                VerifyGuaranteeError::CertificateMismatch => RemunerateError::CertificateMismatch,
                VerifyGuaranteeError::GuaranteeDomainMismatch => {
                    RemunerateError::GuaranteeDomainMismatch
                }
                VerifyGuaranteeError::UnsupportedGuaranteeVersion(version) => {
                    RemunerateError::UnsupportedGuaranteeVersion(version)
                }
            })?;

        let sig =
            crypto::hex::decode_hex(&cert.signature).map_err(RemunerateError::SignatureHex)?;

        let sig_words = crypto::bls::g2_words_from_signature(sig.as_slice())
            .map_err(RemunerateError::SignatureDecode)?;

        let claims_bytes = cert.claims_bytes().map_err(RemunerateError::ClaimsHex)?;

        // Static call first to surface a revert without submitting a transaction
        self.ctx
            .get_contract()
            .remunerate(claims_bytes.clone().into(), sig_words.into())
            .call()
            .await
            .map_err(RemunerateError::from)?;

        let send_result = self
            .ctx
            .get_contract()
            .remunerate(claims_bytes.into(), sig_words.into())
            .send()
            .await
            .map_err(RemunerateError::from)?;

        let receipt = send_result
            .get_receipt()
            .await
            .map_err(alloy::contract::Error::from)
            .map_err(RemunerateError::from)?;

        Ok(receipt)
    }

    pub async fn list_settled_tabs(&self) -> Result<Vec<TabInfo>, RecipientQueryError> {
        let address = self.ctx.signer().address().to_string();
        let tabs = self
            .ctx
            .rpc_proxy()
            .await?
            .list_settled_tabs(address)
            .await?
            .into_iter()
            .map(Into::into)
            .collect();
        Ok(tabs)
    }

    pub async fn list_pending_remunerations(
        &self,
    ) -> Result<Vec<PendingRemunerationInfo>, RecipientQueryError> {
        let address = self.ctx.signer().address().to_string();
        let items = self
            .ctx
            .rpc_proxy()
            .await?
            .list_pending_remunerations(address)
            .await?
            .into_iter()
            .map(Into::into)
            .collect();
        Ok(items)
    }

    pub async fn get_tab(&self, tab_id: U256) -> Result<Option<TabInfo>, RecipientQueryError> {
        let result = self.ctx.rpc_proxy().await?.get_tab(tab_id).await?;
        Ok(result.map(Into::into))
    }

    pub async fn list_recipient_tabs(
        &self,
        settlement_statuses: Option<Vec<String>>,
    ) -> Result<Vec<TabInfo>, RecipientQueryError> {
        let address = self.ctx.signer().address().to_string();
        let tabs = self
            .ctx
            .rpc_proxy()
            .await?
            .list_recipient_tabs(address, settlement_statuses)
            .await?
            .into_iter()
            .map(Into::into)
            .collect();
        Ok(tabs)
    }

    pub async fn get_tab_guarantees(
        &self,
        tab_id: U256,
    ) -> Result<Vec<GuaranteeInfo>, RecipientQueryError> {
        let guarantees = self
            .ctx
            .rpc_proxy()
            .await?
            .get_tab_guarantees(tab_id)
            .await?
            .into_iter()
            .map(Into::into)
            .collect();
        Ok(guarantees)
    }

    pub async fn get_latest_guarantee(
        &self,
        tab_id: U256,
    ) -> Result<Option<GuaranteeInfo>, RecipientQueryError> {
        let result = self
            .ctx
            .rpc_proxy()
            .await?
            .get_latest_guarantee(tab_id)
            .await?
            .map(Into::into);
        Ok(result)
    }

    pub async fn get_guarantee(
        &self,
        tab_id: U256,
        req_id: U256,
    ) -> Result<Option<GuaranteeInfo>, RecipientQueryError> {
        let result = self
            .ctx
            .rpc_proxy()
            .await?
            .get_guarantee(tab_id, req_id)
            .await?
            .map(Into::into);
        Ok(result)
    }

    pub async fn list_recipient_payments(
        &self,
    ) -> Result<Vec<RecipientPaymentInfo>, RecipientQueryError> {
        let address = self.ctx.signer().address().to_string();
        let payments = self
            .ctx
            .rpc_proxy()
            .await?
            .list_recipient_payments(address)
            .await?
            .into_iter()
            .map(Into::into)
            .collect();
        Ok(payments)
    }

    pub async fn get_collateral_events_for_tab(
        &self,
        tab_id: U256,
    ) -> Result<Vec<CollateralEventInfo>, RecipientQueryError> {
        let events = self
            .ctx
            .rpc_proxy()
            .await?
            .get_collateral_events_for_tab(tab_id)
            .await?
            .into_iter()
            .map(Into::into)
            .collect();
        Ok(events)
    }

    pub async fn get_user_asset_balance(
        &self,
        user_address: String,
        asset_address: String,
    ) -> Result<Option<AssetBalanceInfo>, RecipientQueryError> {
        let balance = self
            .ctx
            .rpc_proxy()
            .await?
            .get_user_asset_balance(user_address, asset_address)
            .await?
            .map(Into::into);
        Ok(balance)
    }
}
