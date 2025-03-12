use std::fmt::Display;

use anyhow::anyhow;
use bls_signatures::{PrivateKey, PublicKey, Serialize, Signature};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BLSCert {
    pub claims: String,
    pub signature: String,
}

impl BLSCert {
    pub fn new<T: TryInto<Vec<u8>>>(priv_key: &[u8], claims: T) -> anyhow::Result<Self>
    where
        <T as TryInto<Vec<u8>>>::Error: Display,
    {
        let claims: Vec<u8> = claims.try_into().map_err(|err| anyhow!("{err}"))?;

        let priv_key = PrivateKey::from_bytes(priv_key)?;
        let signature = priv_key.sign(&claims);

        Ok(BLSCert {
            claims: hex::encode(claims),
            signature: hex::encode(signature.as_bytes()),
        })
    }

    pub fn verify(&self, pub_key: &[u8]) -> anyhow::Result<bool> {
        let pub_key = PublicKey::from_bytes(pub_key)?;

        let sig = hex::decode(&self.signature)?;
        let sig = Signature::from_bytes(&sig)?;

        Ok(pub_key.verify(sig, &self.claims_bytes()?))
    }
    
    pub fn claims_bytes(&self) -> anyhow::Result<Vec<u8>> {
        let claims = hex::decode(&self.claims)?;
        Ok(claims)
    }
}

pub fn pub_key_from_priv_key(priv_key: &[u8]) -> anyhow::Result<Vec<u8>> {
    let priv_key = PrivateKey::from_bytes(priv_key)?;
    Ok(priv_key.public_key().as_bytes())
}

// Just for development and testing purposes!
pub fn generate_private_key() -> String {
    let priv_key = PrivateKey::new("a5c5307ab61fa939de5337f3624ae537dab99065dd89e18bdf9ca95304886d0490580dafece6f9a25c2c2fc61ba0f0195b73693d97757006f62602544545aafb".as_bytes());
    hex::encode(priv_key.as_bytes())
}
