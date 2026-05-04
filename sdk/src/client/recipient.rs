use alloy::{
    network::TxSigner,
    rpc::types::TransactionReceipt,
    signers::{Signature, Signer},
};
use crypto::bls::{BLSCert, BlsError};
use rpc::{
    ClearingSettlementActionResponse, PaymentGuaranteeClaims, PaymentGuaranteeRequest,
    PaymentGuaranteeRequestClaims, PaymentGuaranteeRequestClaimsV1,
    PaymentGuaranteeRequestClaimsV2, SigningScheme,
};

use crate::{
    client::ClientCtx,
    client::model::{AssetBalanceInfo, RecipientPaymentInfo},
    error::{
        ClearingSettlementError, IssuePaymentGuaranteeError, RecipientQueryError,
        VerifyGuaranteeError,
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

    pub async fn get_clearing_claim_net_credit_action(
        &self,
        cycle_id: String,
    ) -> Result<ClearingSettlementActionResponse, ClearingSettlementError>
    where
        S: Signer + Sync,
    {
        let creditor = self.ctx.signer_address().to_string();
        let proxy = self.ctx.rpc_proxy().await?;
        Ok(proxy
            .get_clearing_claim_net_credit_action(cycle_id, creditor)
            .await?)
    }

    /// Claims the caller's committed net credit for a clearing cycle.
    pub async fn claim_net_credit(
        &self,
        cycle_id: String,
    ) -> Result<TransactionReceipt, ClearingSettlementError>
    where
        S: Signer + TxSigner<Signature> + Send + Sync + Clone + 'static,
    {
        let action = self.get_clearing_claim_net_credit_action(cycle_id).await?;
        let call = super::user::parse_clearing_action_call(&action)?;
        let contract = self
            .ctx
            .get_clearing_house_write_contract(call.contract_address)
            .await?;

        let send_result = contract
            .claimNetCredit(call.cycle_id, call.amount, call.proof)
            .send()
            .await
            .map_err(ClearingSettlementError::from)?;
        let receipt = send_result
            .get_receipt()
            .await
            .map_err(alloy::contract::Error::from)
            .map_err(ClearingSettlementError::from)?;

        Ok(receipt)
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
        self.issue_inner(
            PaymentGuaranteeRequestClaims::V2(Box::new(claims)),
            signature,
            scheme,
        )
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
    use alloy::primitives::{Address, B256, U256};
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
            cycle_id: U256::from(1u64),
            req_id: U256::from(2u64),
            amount: U256::from(3u64),
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
                job_hash: B256::repeat_byte(0x11),
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
