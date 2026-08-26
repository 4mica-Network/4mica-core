//! Payment guarantees: the payer signs a request, the recipient turns it into a certificate and
//! checks it. Both roles live here since they exchange the same claims.

use std::collections::HashMap;

use alloy::signers::Signer;
use crypto::bls::{BLSCert, BlsError};
use rpc::{
    PaymentGuaranteeClaims, PaymentGuaranteeRequest, PaymentGuaranteeRequestClaims, SigningScheme,
};

use crate::{
    PaymentSignature,
    client::{ClientCtx, model::RecipientPaymentInfo},
    error::PaymentError,
    sig::PaymentSigner,
};

pub struct PaymentClient<S> {
    ctx: ClientCtx<S>,
}

impl<S> Clone for PaymentClient<S> {
    fn clone(&self) -> Self {
        Self {
            ctx: self.ctx.clone(),
        }
    }
}

impl<S> PaymentClient<S> {
    pub(super) fn new(ctx: ClientCtx<S>) -> Self {
        Self { ctx }
    }

    /// The EIP-712 domain guarantees are signed under.
    pub fn guarantee_domain(&self) -> &[u8; 32] {
        self.ctx.guarantee_domain()
    }

    /// Checks that `cert` was issued by the operator this client trusts, returning the claims it
    /// certifies.
    pub fn verify_guarantee(&self, cert: &BLSCert) -> Result<PaymentGuaranteeClaims, PaymentError> {
        match cert.verify(self.ctx.operator_public_key()) {
            Ok(()) => {}
            Err(BlsError::VerificationFailed) => {
                return Err(PaymentError::CertificateMismatch);
            }
            Err(err) => {
                return Err(PaymentError::InvalidCertificate(anyhow::Error::new(err)));
            }
        }

        let claims = PaymentGuaranteeClaims::try_from(cert.claims().as_bytes())
            .map_err(PaymentError::InvalidCertificate)?;

        let Some(expected_domain) = self.ctx.guarantee_domain_for_version(claims.version) else {
            return Err(PaymentError::UnsupportedGuaranteeVersion(claims.version));
        };
        let guarantee_domains = HashMap::from([(claims.version, *expected_domain)]);
        Self::verify_guarantee_metadata(&claims, &guarantee_domains)?;
        Ok(claims)
    }

    fn verify_guarantee_metadata(
        claims: &PaymentGuaranteeClaims,
        guarantee_domains: &HashMap<u64, [u8; 32]>,
    ) -> Result<(), PaymentError> {
        let Some(expected_domain) = guarantee_domains.get(&claims.version) else {
            return Err(PaymentError::UnsupportedGuaranteeVersion(claims.version));
        };

        if claims.domain != *expected_domain {
            return Err(PaymentError::GuaranteeDomainMismatch);
        }

        Ok(())
    }
}

impl<S> PaymentClient<S>
where
    S: Signer + Send + Sync,
{
    /// Signs a guarantee request as the payer. Hand the signature to the recipient, who redeems it
    /// with [`Self::issue_guarantee`].
    pub async fn sign_request(
        &self,
        claims: PaymentGuaranteeRequestClaims,
        scheme: SigningScheme,
    ) -> Result<PaymentSignature, PaymentError> {
        // TODO: Cache public parameters for a while
        let pub_params = self.ctx.rpc_proxy().await?.get_public_params().await?;

        let sig = self
            .ctx
            .signer()
            .sign_claims(&pub_params, claims, scheme)
            .await?;

        Ok(sig)
    }
}

impl<S> PaymentClient<S>
where
    S: Signer + Sync,
{
    /// Redeems a payer's signed request for a certificate guaranteeing the payment, as the
    /// recipient.
    pub async fn issue_guarantee(
        &self,
        claims: PaymentGuaranteeRequestClaims,
        signature: String,
        scheme: SigningScheme,
    ) -> Result<BLSCert, PaymentError> {
        let cert = self
            .ctx
            .rpc_proxy()
            .await?
            .issue_guarantee(PaymentGuaranteeRequest::new(claims, signature, scheme))
            .await?;
        Ok(cert)
    }

    /// Payments guaranteed to the signer as a recipient.
    pub async fn list_received(&self) -> Result<Vec<RecipientPaymentInfo>, PaymentError> {
        let address = self.ctx.signer_address().to_string();
        self.ctx
            .rpc_proxy()
            .await?
            .list_recipient_payments(address)
            .await?
            .into_iter()
            .map(|payment| RecipientPaymentInfo::try_from(payment).map_err(PaymentError::Decode))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::PaymentClient;
    use alloy::primitives::{Address, U256};
    use rpc::{GUARANTEE_CLAIMS_VERSION, PaymentGuaranteeClaims};
    use std::collections::HashMap;

    use crate::error::PaymentError;

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
        }
    }

    #[test]
    fn verify_guarantee_metadata_accepts_a_supported_version() {
        let claims = test_claims(GUARANTEE_CLAIMS_VERSION, [0x11; 32]);
        let result = PaymentClient::<()>::verify_guarantee_metadata(
            &claims,
            &HashMap::from([(GUARANTEE_CLAIMS_VERSION, [0x11; 32])]),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn verify_guarantee_metadata_rejects_unsupported_version() {
        let claims = test_claims(99, [0x22; 32]);
        let result = PaymentClient::<()>::verify_guarantee_metadata(
            &claims,
            &HashMap::from([(GUARANTEE_CLAIMS_VERSION, [0x22; 32])]),
        );
        assert!(matches!(
            result,
            Err(PaymentError::UnsupportedGuaranteeVersion(99))
        ));
    }

    #[test]
    fn verify_guarantee_metadata_rejects_domain_mismatch() {
        let claims = test_claims(GUARANTEE_CLAIMS_VERSION, [0x22; 32]);
        let result = PaymentClient::<()>::verify_guarantee_metadata(
            &claims,
            &HashMap::from([(GUARANTEE_CLAIMS_VERSION, [0x33; 32])]),
        );
        assert!(matches!(result, Err(PaymentError::GuaranteeDomainMismatch)));
    }
}
