use std::str::FromStr;

use crate::error::SignPaymentError;
use alloy::primitives::{Address, B256};
use alloy::signers::Signer;

use async_trait::async_trait;
use rpc::common::{PaymentGuaranteeClaims, SigningScheme};
use rpc::core::CorePublicParameters;

pub struct PaymentSignature {
    pub signature: String,
    pub scheme: SigningScheme,
}

#[async_trait]
pub trait PaymentSigner: Send + Sync {
    /// Signs the claims with the chosen scheme and returns a ready-to-send request.
    ///
    /// Implementations SHOULD ensure the signer address equals `claims.user_address`
    /// to avoid mismatched-key bugs.
    async fn sign_request(
        &self,
        params: &CorePublicParameters,
        claims: PaymentGuaranteeClaims,
        scheme: SigningScheme,
    ) -> Result<PaymentSignature, SignPaymentError>;
}

#[async_trait]
impl<S> PaymentSigner for S
where
    S: Signer + Send + Sync,
{
    async fn sign_request(
        &self,
        params: &CorePublicParameters,
        claims: PaymentGuaranteeClaims,
        scheme: SigningScheme,
    ) -> Result<PaymentSignature, SignPaymentError> {
        let signer_addr = self.address();
        let expected = Address::from_str(&claims.user_address)
            .map_err(|_| SignPaymentError::InvalidUserAddress)?;

        if signer_addr != expected {
            return Err(SignPaymentError::AddressMismatch {
                signer: signer_addr,
                claims: claims.user_address.clone(),
            }
            .into());
        }

        let digest: B256 = match scheme {
            SigningScheme::Eip712 => crate::digest::eip712_digest(params, &claims)
                .map_err(|e| SignPaymentError::Failed(e.to_string()))?,
            SigningScheme::Eip191 => {
                let user = Address::from_str(&claims.user_address)
                    .map_err(|_| SignPaymentError::InvalidUserAddress)?;
                let recipient = Address::from_str(&claims.recipient_address)
                    .map_err(|_| SignPaymentError::InvalidRecipientAddress)?;
                crate::digest::eip191_digest(&claims, user, recipient)
                    .map_err(|e| SignPaymentError::Failed(e.to_string()))?
            }
        };

        let sig = self
            .sign_hash(&digest)
            .await
            .map_err(|e| SignPaymentError::Failed(e.to_string()))?;

        let signature = sig.to_string();

        Ok(PaymentSignature { signature, scheme })
    }
}
