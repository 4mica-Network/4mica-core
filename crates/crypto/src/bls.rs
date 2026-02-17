use std::{fmt::Display, str::FromStr};

use blst::{
    self, blst_p2_affine,
    min_pk::{PublicKey as BlstPublicKey, SecretKey, Signature as BlstSignature},
};
use secrecy::zeroize::Zeroizing;
use secrecy::{ExposeSecret, SecretBox};

const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BLSCert {
    pub claims: String,    // hex of abi.encodePacked(...)
    pub signature: String, // hex of compressed G2 (96 bytes)
}

impl BLSCert {
    pub fn new<C: TryInto<Vec<u8>>>(sk: &BlsSecretKey, claims: C) -> anyhow::Result<Self>
    where
        C::Error: Display,
    {
        let claims_bytes = claims
            .try_into()
            .map_err(|e| anyhow::anyhow!("failed to convert claims to bytes: {}", e))?;
        let sig = sk.sign(&claims_bytes);
        Ok(BLSCert {
            claims: hex::encode(claims_bytes),
            signature: hex::encode(sig.compress()),
        })
    }

    pub fn verify(&self, pub_key: &[u8]) -> anyhow::Result<bool> {
        let pk = BlstPublicKey::from_bytes(pub_key)
            .map_err(|e| anyhow::anyhow!("invalid pubkey: {:?}", e))?;
        let sig = BlstSignature::from_bytes(&hex::decode(&self.signature)?)
            .map_err(|e| anyhow::anyhow!("invalid signature: {:?}", e))?;

        let msg = hex::decode(&self.claims)?;
        let err = sig.verify(true, &msg, DST, &[], &pk, true);
        Ok(err == blst::BLST_ERROR::BLST_SUCCESS)
    }

    pub fn claims_bytes(&self) -> anyhow::Result<Vec<u8>> {
        Ok(hex::decode(&self.claims)?)
    }
}

fn split_fp_be48_into_hi_lo32(be48: &[u8; 48]) -> ([u8; 32], [u8; 32]) {
    let mut hi = [0u8; 32];
    let mut lo = [0u8; 32];
    hi[16..].copy_from_slice(&be48[..16]);
    lo.copy_from_slice(&be48[16..]);
    (hi, lo)
}

pub fn g2_words_from_signature(sig_bytes: &[u8]) -> anyhow::Result<[[u8; 32]; 8]> {
    let sig = BlstSignature::from_bytes(sig_bytes)
        .map_err(|e| anyhow::anyhow!("invalid BLS signature: {:?}", e))?;
    let aff: blst_p2_affine = sig.into();

    let mut x_c0 = [0u8; 48];
    let mut x_c1 = [0u8; 48];
    let mut y_c0 = [0u8; 48];
    let mut y_c1 = [0u8; 48];
    unsafe {
        blst::blst_bendian_from_fp(x_c0.as_mut_ptr(), &aff.x.fp[0]); // c0
        blst::blst_bendian_from_fp(x_c1.as_mut_ptr(), &aff.x.fp[1]); // c1
        blst::blst_bendian_from_fp(y_c0.as_mut_ptr(), &aff.y.fp[0]); // c0
        blst::blst_bendian_from_fp(y_c1.as_mut_ptr(), &aff.y.fp[1]); // c1
    }

    let (x0_hi, x0_lo) = split_fp_be48_into_hi_lo32(&x_c0);
    let (x1_hi, x1_lo) = split_fp_be48_into_hi_lo32(&x_c1);
    let (y0_hi, y0_lo) = split_fp_be48_into_hi_lo32(&y_c0);
    let (y1_hi, y1_lo) = split_fp_be48_into_hi_lo32(&y_c1);

    Ok([x0_hi, x0_lo, x1_hi, x1_lo, y0_hi, y0_lo, y1_hi, y1_lo])
}

/// A secured BLS secret key.
pub struct BlsSecretKey(SecretBox<SecretKey>);

impl BlsSecretKey {
    pub fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        let sk = SecretKey::from_bytes(bytes)
            .map_err(|e| anyhow::anyhow!("invalid secret key: {:?}", e))?;
        Ok(Self(SecretBox::new(Box::new(sk))))
    }

    pub fn public_key(&self) -> Vec<u8> {
        self.0.expose_secret().sk_to_pk().compress().to_vec()
    }

    pub fn sign(&self, msg: &[u8]) -> BlstSignature {
        self.0.expose_secret().sign(msg, DST, &[])
    }
}

impl std::fmt::Debug for BlsSecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BlsSecretKey([REDACTED])")
    }
}

impl FromStr for BlsSecretKey {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let stripped = s.strip_prefix("0x").unwrap_or(s);
        let bytes = Zeroizing::new(hex::decode(stripped)?);

        let sk = SecretKey::from_bytes(&bytes)
            .map_err(|e| anyhow::anyhow!("invalid secret key: {:?}", e))?;
        Ok(Self(SecretBox::new(Box::new(sk))))
    }
}
