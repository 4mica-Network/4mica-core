use alloy::{
    network::TxSigner,
    primitives::U256,
    rpc::types::TransactionReceipt,
    signers::{Signature, Signer},
};
use crypto::bls::{BLSCert, BlsError};
use rpc::{
    CreatePaymentTabRequest, PaymentGuaranteeClaims, PaymentGuaranteeRequest,
    PaymentGuaranteeRequestClaims, PaymentGuaranteeRequestClaimsV1,
    PaymentGuaranteeRequestClaimsV2, SigningScheme,
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
    guarantee::{PreparedPaymentGuaranteeClaims, PreparedPaymentGuaranteeRequest},
};
use std::collections::HashMap;

#[derive(Clone)]
pub struct RecipientClient<S> {
    ctx: ClientCtx<S>,
}

impl<S> RecipientClient<S> {
    pub(super) fn new(ctx: ClientCtx<S>) -> Self {
        Self { ctx }
    }

    pub fn active_guarantee_version(&self) -> u64 {
        self.ctx.active_guarantee_version()
    }

    pub fn active_guarantee_domain(&self) -> &[u8; 32] {
        self.ctx.active_guarantee_domain()
    }

    fn verify_guarantee_metadata(
        claims: &PaymentGuaranteeClaims,
        guarantee_domains: &HashMap<u64, [u8; 32]>,
    ) -> Result<(), VerifyGuaranteeError> {
        let Some(expected_domain) = guarantee_domains.get(&claims.version) else {
            return Err(VerifyGuaranteeError::UnsupportedGuaranteeVersion(
                claims.version,
            ));
        };

        if claims.domain != *expected_domain {
            return Err(VerifyGuaranteeError::GuaranteeDomainMismatch);
        }

        Ok(())
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
    ) -> Result<U256, CreateTabError>
    where
        S: Signer + Sync,
    {
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

    async fn issue_inner(
        &self,
        claims: PaymentGuaranteeRequestClaims,
        signature: String,
        scheme: SigningScheme,
    ) -> Result<BLSCert, IssuePaymentGuaranteeError>
    where
        S: Signer + Sync,
    {
        let cert = self
            .ctx
            .rpc_proxy()
            .await?
            .issue_guarantee(PaymentGuaranteeRequest::new(claims, signature, scheme))
            .await?;
        Ok(cert)
    }

    pub async fn issue_payment_guarantee(
        &self,
        claims: PaymentGuaranteeRequestClaimsV1,
        signature: String,
        scheme: SigningScheme,
    ) -> Result<BLSCert, IssuePaymentGuaranteeError>
    where
        S: Signer + Sync,
    {
        self.issue_inner(PaymentGuaranteeRequestClaims::V1(claims), signature, scheme)
            .await
    }

    pub async fn issue_payment_guarantee_v2(
        &self,
        claims: PaymentGuaranteeRequestClaimsV2,
        signature: String,
        scheme: SigningScheme,
    ) -> Result<BLSCert, IssuePaymentGuaranteeError>
    where
        S: Signer + Sync,
    {
        self.issue_inner(PaymentGuaranteeRequestClaims::V2(claims), signature, scheme)
            .await
    }

    pub async fn issue_prepared_payment_guarantee(
        &self,
        request: PreparedPaymentGuaranteeRequest,
    ) -> Result<BLSCert, IssuePaymentGuaranteeError>
    where
        S: Signer + Sync,
    {
        let claims = match request.claims {
            PreparedPaymentGuaranteeClaims::V1(c) => PaymentGuaranteeRequestClaims::V1(c),
            PreparedPaymentGuaranteeClaims::V2(c) => PaymentGuaranteeRequestClaims::V2(c),
        };
        self.issue_inner(claims, request.signature, request.scheme)
            .await
    }

    pub fn verify_payment_guarantee(
        &self,
        cert: &BLSCert,
    ) -> Result<PaymentGuaranteeClaims, VerifyGuaranteeError> {
        match cert.verify(self.ctx.operator_public_key()) {
            Ok(()) => {}
            Err(BlsError::VerificationFailed) => {
                return Err(VerifyGuaranteeError::CertificateMismatch);
            }
            Err(err) => {
                return Err(VerifyGuaranteeError::InvalidCertificate(
                    anyhow::Error::new(err),
                ));
            }
        }

        let claims = PaymentGuaranteeClaims::try_from(cert.claims().as_bytes())
            .map_err(VerifyGuaranteeError::InvalidCertificate)?;

        let Some(expected_domain) = self.ctx.guarantee_domain_for_version(claims.version) else {
            return Err(VerifyGuaranteeError::UnsupportedGuaranteeVersion(
                claims.version,
            ));
        };
        let guarantee_domains = HashMap::from([(claims.version, *expected_domain)]);
        Self::verify_guarantee_metadata(&claims, &guarantee_domains)?;
        Ok(claims)
    }

    pub async fn remunerate(&self, cert: BLSCert) -> Result<TransactionReceipt, RemunerateError>
    where
        S: TxSigner<Signature> + Send + Sync + Clone + 'static,
    {
        self.verify_payment_guarantee(&cert)
            .map_err(|err| match err {
                VerifyGuaranteeError::InvalidCertificate(source) => {
                    RemunerateError::CertificateInvalid(source)
                }
                VerifyGuaranteeError::CertificateMismatch => RemunerateError::CertificateMismatch,
                VerifyGuaranteeError::GuaranteeVersionMismatch { expected, actual } => {
                    RemunerateError::GuaranteeVersionMismatch { expected, actual }
                }
                VerifyGuaranteeError::GuaranteeDomainMismatch => {
                    RemunerateError::GuaranteeDomainMismatch
                }
                VerifyGuaranteeError::UnsupportedGuaranteeVersion(version) => {
                    RemunerateError::UnsupportedGuaranteeVersion(version)
                }
            })?;

        let sig_words = cert
            .signature()
            .to_solidity_words()
            .map_err(|e| RemunerateError::SignatureDecode(anyhow::Error::new(e)))?;

        let claims_bytes = cert.claims().to_vec();

        // Static call first to surface a revert without submitting a transaction
        self.ctx
            .get_write_contract()
            .await?
            .remunerate(claims_bytes.clone().into(), sig_words.into())
            .call()
            .await
            .map_err(RemunerateError::from)?;

        let send_result = self
            .ctx
            .get_write_contract()
            .await?
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

    pub async fn list_settled_tabs(&self) -> Result<Vec<TabInfo>, RecipientQueryError>
    where
        S: Signer + Sync,
    {
        let address = self.ctx.signer_address().to_string();
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
    ) -> Result<Vec<PendingRemunerationInfo>, RecipientQueryError>
    where
        S: Signer + Sync,
    {
        let address = self.ctx.signer_address().to_string();
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

    pub async fn get_tab(&self, tab_id: U256) -> Result<Option<TabInfo>, RecipientQueryError>
    where
        S: Signer + Sync,
    {
        let result = self.ctx.rpc_proxy().await?.get_tab(tab_id).await?;
        Ok(result.map(Into::into))
    }

    pub async fn list_recipient_tabs(
        &self,
        settlement_statuses: Option<Vec<String>>,
    ) -> Result<Vec<TabInfo>, RecipientQueryError>
    where
        S: Signer + Sync,
    {
        let address = self.ctx.signer_address().to_string();
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
    ) -> Result<Vec<GuaranteeInfo>, RecipientQueryError>
    where
        S: Signer + Sync,
    {
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
    ) -> Result<Option<GuaranteeInfo>, RecipientQueryError>
    where
        S: Signer + Sync,
    {
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
    ) -> Result<Option<GuaranteeInfo>, RecipientQueryError>
    where
        S: Signer + Sync,
    {
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
    ) -> Result<Vec<RecipientPaymentInfo>, RecipientQueryError>
    where
        S: Signer + Sync,
    {
        let address = self.ctx.signer_address().to_string();
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
    ) -> Result<Vec<CollateralEventInfo>, RecipientQueryError>
    where
        S: Signer + Sync,
    {
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
    ) -> Result<Option<AssetBalanceInfo>, RecipientQueryError>
    where
        S: Signer + Sync,
    {
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

#[cfg(test)]
mod tests {
    use super::RecipientClient;
    use alloy::primitives::{Address, U256};
    use rpc::{
        GUARANTEE_CLAIMS_VERSION, PaymentGuaranteeClaims, PaymentGuaranteeValidationPolicyV2,
    };
    use std::collections::HashMap;

    use crate::error::VerifyGuaranteeError;

    fn test_claims(version: u64, domain: [u8; 32]) -> PaymentGuaranteeClaims {
        PaymentGuaranteeClaims {
            domain,
            user_address: Address::repeat_byte(0x11).to_string(),
            recipient_address: Address::repeat_byte(0x22).to_string(),
            tab_id: U256::from(1u64),
            req_id: U256::from(2u64),
            amount: U256::from(3u64),
            total_amount: U256::from(4u64),
            asset_address: Address::ZERO.to_string(),
            timestamp: 1_700_000_000,
            version,
            validation_policy: (version == 2).then(|| PaymentGuaranteeValidationPolicyV2 {
                validation_registry_address: Address::repeat_byte(0x33),
                validation_request_hash: Default::default(),
                validation_chain_id: 1,
                validator_address: Address::repeat_byte(0x44),
                validator_agent_id: U256::from(7u64),
                min_validation_score: 80,
                validation_subject_hash: Default::default(),
                required_validation_tag: String::new(),
            }),
        }
    }

    #[test]
    fn verify_guarantee_metadata_accepts_v1_when_active_version_is_v1() {
        let claims = test_claims(GUARANTEE_CLAIMS_VERSION, [0x11; 32]);
        let result = RecipientClient::<()>::verify_guarantee_metadata(
            &claims,
            &HashMap::from([(GUARANTEE_CLAIMS_VERSION, [0x11; 32])]),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn verify_guarantee_metadata_accepts_v2_when_active_version_is_v2() {
        let claims = test_claims(2, [0x22; 32]);
        let result = RecipientClient::<()>::verify_guarantee_metadata(
            &claims,
            &HashMap::from([(2, [0x22; 32])]),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn verify_guarantee_metadata_rejects_unsupported_version() {
        let claims = test_claims(2, [0x22; 32]);
        let result = RecipientClient::<()>::verify_guarantee_metadata(
            &claims,
            &HashMap::from([(GUARANTEE_CLAIMS_VERSION, [0x22; 32])]),
        );
        assert!(matches!(
            result,
            Err(VerifyGuaranteeError::UnsupportedGuaranteeVersion(2))
        ));
    }

    #[test]
    fn verify_guarantee_metadata_rejects_domain_mismatch() {
        let claims = test_claims(2, [0x22; 32]);
        let result = RecipientClient::<()>::verify_guarantee_metadata(
            &claims,
            &HashMap::from([(2, [0x33; 32])]),
        );
        assert!(matches!(
            result,
            Err(VerifyGuaranteeError::GuaranteeDomainMismatch)
        ));
    }
}
