use std::str::FromStr;

use crate::error::PaymentError;
use alloy::primitives::{Address, B256};
use alloy::signers::Signer;

use async_trait::async_trait;
use rpc::{CorePublicParameters, PaymentGuaranteeRequestClaims, SigningScheme};
use serde::Deserialize;

#[cfg(test)]
mod tests;

#[derive(Debug, Clone, Deserialize)]
pub struct PaymentSignature {
    pub signature: String,
    pub scheme: SigningScheme,
}

/// Signs a guarantee request with the chosen EIP scheme.
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
    ) -> Result<PaymentSignature, PaymentError>;
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
    ) -> Result<PaymentSignature, PaymentError> {
        let signer_addr = self.address();
        let expected = Address::from_str(claims.user_address())
            .map_err(|_| PaymentError::InvalidUserAddress)?;

        if signer_addr != expected {
            return Err(PaymentError::AddressMismatch {
                signer: signer_addr,
                claims: claims.user_address().to_string(),
            });
        }

        let digest: B256 = match scheme {
            SigningScheme::Eip712 => crate::digest::eip712_digest_for_claims(params, &claims)
                .map_err(|e| PaymentError::SigningFailed(e.to_string()))?,
            SigningScheme::Eip191 => {
                let user = Address::from_str(claims.user_address())
                    .map_err(|_| PaymentError::InvalidUserAddress)?;
                let recipient = Address::from_str(claims.recipient_address())
                    .map_err(|_| PaymentError::InvalidRecipientAddress)?;
                crate::digest::eip191_digest_for_claims(&claims, user, recipient)
                    .map_err(|e| PaymentError::SigningFailed(e.to_string()))?
            }
        };

        let sig = self
            .sign_hash(&digest)
            .await
            .map_err(|e| PaymentError::SigningFailed(e.to_string()))?;

        Ok(PaymentSignature {
            signature: sig.to_string(),
            scheme,
        })
    }
}
