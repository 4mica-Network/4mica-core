use std::str::FromStr;

use crate::error::SignPaymentError;
use alloy::primitives::{Address, B256};
use alloy::signers::Signer;

use async_trait::async_trait;
use rpc::{
    CorePublicParameters, PaymentGuaranteeRequestClaims, PaymentGuaranteeRequestClaimsV1,
    PaymentGuaranteeRequestClaimsV2, PaymentGuaranteeRequestEssentials, SigningScheme,
};
use serde::Deserialize;

#[cfg(test)]
mod tests;

#[derive(Debug, Clone, Deserialize)]
pub struct PaymentSignature {
    pub signature: String,
    pub scheme: SigningScheme,
}

/// Signs a guarantee request claim (any version) with the chosen EIP scheme.
///
/// The single required method is [`PaymentSigner::sign_claims`], which accepts the version enum.
/// Adding V3 only requires extending the dispatch inside the blanket impl — no trait changes needed.
///
/// [`sign_request`] and [`sign_request_v2`] are convenience wrappers that wrap their typed
/// argument into the enum and delegate, so existing call sites continue to compile unchanged.
#[async_trait]
pub trait PaymentSigner: Send + Sync {
    /// Signs the claims and returns the resulting signature.
    ///
    /// Implementations MUST verify that the signer address equals `claims.user_address`.
    async fn sign_claims(
        &self,
        params: &CorePublicParameters,
        claims: PaymentGuaranteeRequestClaims,
        scheme: SigningScheme,
    ) -> Result<PaymentSignature, SignPaymentError>;

    /// Convenience wrapper for V1 claims. Delegates to [`sign_claims`].
    async fn sign_request(
        &self,
        params: &CorePublicParameters,
        claims: PaymentGuaranteeRequestClaimsV1,
        scheme: SigningScheme,
    ) -> Result<PaymentSignature, SignPaymentError> {
        self.sign_claims(params, PaymentGuaranteeRequestClaims::V1(claims), scheme)
            .await
    }

    /// Convenience wrapper for V2 claims. Delegates to [`sign_claims`].
    async fn sign_request_v2(
        &self,
        params: &CorePublicParameters,
        claims: PaymentGuaranteeRequestClaimsV2,
        scheme: SigningScheme,
    ) -> Result<PaymentSignature, SignPaymentError> {
        self.sign_claims(params, PaymentGuaranteeRequestClaims::V2(claims), scheme)
            .await
    }
}

#[async_trait]
impl<S> PaymentSigner for S
where
    S: Signer + Send + Sync,
{
    async fn sign_claims(
        &self,
        params: &CorePublicParameters,
        claims: PaymentGuaranteeRequestClaims,
        scheme: SigningScheme,
    ) -> Result<PaymentSignature, SignPaymentError> {
        let signer_addr = self.address();
        let expected = Address::from_str(claims.user_address())
            .map_err(|_| SignPaymentError::InvalidUserAddress)?;

        if signer_addr != expected {
            return Err(SignPaymentError::AddressMismatch {
                signer: signer_addr,
                claims: claims.user_address().to_owned(),
            });
        }

        let digest: B256 = match scheme {
            SigningScheme::Eip712 => crate::digest::eip712_digest_for_claims(params, &claims)
                .map_err(|e| SignPaymentError::Failed(e.to_string()))?,
            SigningScheme::Eip191 => {
                let user = Address::from_str(claims.user_address())
                    .map_err(|_| SignPaymentError::InvalidUserAddress)?;
                let recipient = Address::from_str(claims.recipient_address())
                    .map_err(|_| SignPaymentError::InvalidRecipientAddress)?;
                crate::digest::eip191_digest_for_claims(&claims, user, recipient)
                    .map_err(|e| SignPaymentError::Failed(e.to_string()))?
            }
        };

        let sig = self
            .sign_hash(&digest)
            .await
            .map_err(|e| SignPaymentError::Failed(e.to_string()))?;

        Ok(PaymentSignature {
            signature: sig.to_string(),
            scheme,
        })
    }
}
