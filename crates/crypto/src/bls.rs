//! BLS primitives and certificate helpers used by the 4Mica network.
//!
//! This module provides a misuse-resistant interface around `blst` by
//! validating public keys and signatures on construction and keeping
//! cryptographic material in dedicated types.

use std::{fmt::Display, str::FromStr};

use blst::{
    self, blst_p2_affine,
    min_pk::{PublicKey as BlstPublicKey, SecretKey, Signature as BlstSignature},
};
use secrecy::zeroize::Zeroizing;
use secrecy::{ExposeSecret, SecretBox};
use thiserror::Error;

use crate::hex::HexBytes;

const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

/// Errors produced by BLS parsing and verification helpers.
#[derive(Debug, Error)]
pub enum BlsError {
    #[error("invalid hex: {0}")]
    InvalidHex(#[from] hex::FromHexError),
    #[error("invalid public key: {0:?}")]
    InvalidPublicKey(blst::BLST_ERROR),
    #[error("invalid signature: {0:?}")]
    InvalidSignature(blst::BLST_ERROR),
    #[error("invalid secret key: {0:?}")]
    InvalidSecretKey(blst::BLST_ERROR),
    #[error("signature verification failed")]
    VerificationFailed,
}

/// Opaque, validated BLS public key (compressed form, 48 bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlsPublicKey(HexBytes);

impl BlsPublicKey {
    /// Parse and validate a compressed public key.
    ///
    /// This calls `blst::PublicKey::validate`, which rejects infinity and
    /// ensures subgroup membership.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, BlsError> {
        let pk = BlstPublicKey::from_bytes(bytes).map_err(BlsError::InvalidPublicKey)?;
        pk.validate().map_err(BlsError::InvalidPublicKey)?;
        Ok(Self(HexBytes::from(bytes)))
    }

    /// Parse and validate a compressed public key from hex (with or without `0x`).
    pub fn from_hex(value: &str) -> Result<Self, BlsError> {
        let value = value.strip_prefix("0x").unwrap_or(value);
        let bytes = hex::decode(value)?;
        Self::from_bytes(&bytes)
    }

    /// Return the compressed public key bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Return the compressed public key bytes as an owned vector.
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    /// Return the compressed public key as lowercase hex (no `0x` prefix).
    pub fn to_hex(&self) -> String {
        self.0.to_hex()
    }

    fn as_blst(&self) -> Result<BlstPublicKey, BlsError> {
        let pk =
            BlstPublicKey::from_bytes(self.0.as_bytes()).map_err(BlsError::InvalidPublicKey)?;
        pk.validate().map_err(BlsError::InvalidPublicKey)?;
        Ok(pk)
    }

    fn from_compressed_unchecked(bytes: Vec<u8>) -> Self {
        Self(HexBytes::from(bytes))
    }
}

impl serde::Serialize for BlsPublicKey {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> serde::Deserialize<'de> for BlsPublicKey {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        let value = value.strip_prefix("0x").unwrap_or(value.as_str());
        let bytes = hex::decode(value)
            .map_err(|e| serde::de::Error::custom(format!("invalid hex: {e}")))?;
        BlsPublicKey::from_bytes(&bytes).map_err(|e| serde::de::Error::custom(e.to_string()))
    }
}

/// Opaque, validated BLS signature (compressed form, 96 bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlsSignature(HexBytes);

impl BlsSignature {
    /// Parse and validate a compressed signature.
    ///
    /// This calls `blst::Signature::validate(true)`, which rejects infinity
    /// and ensures subgroup membership.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, BlsError> {
        let sig = BlstSignature::from_bytes(bytes).map_err(BlsError::InvalidSignature)?;
        // Ensure subgroup inclusion and optionally reject infinity.
        sig.validate(true).map_err(BlsError::InvalidSignature)?;
        Ok(Self(HexBytes::from(bytes)))
    }

    /// Parse and validate a compressed signature from hex (with or without `0x`).
    pub fn from_hex(value: &str) -> Result<Self, BlsError> {
        let value = value.strip_prefix("0x").unwrap_or(value);
        let bytes = hex::decode(value)?;
        Self::from_bytes(&bytes)
    }

    /// Return the compressed signature bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Return the compressed signature bytes as an owned vector.
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    /// Return the compressed signature as lowercase hex (no `0x` prefix).
    pub fn to_hex(&self) -> String {
        self.0.to_hex()
    }

    /// Convert the signature into the 8 x 32-byte word representation expected by Solidity.
    pub fn to_solidity_words(&self) -> Result<[[u8; 32]; 8], BlsError> {
        let sig =
            BlstSignature::from_bytes(self.0.as_bytes()).map_err(BlsError::InvalidSignature)?;
        let aff: blst_p2_affine = sig.into();

        let mut x_c0 = [0u8; 48];
        let mut x_c1 = [0u8; 48];
        let mut y_c0 = [0u8; 48];
        let mut y_c1 = [0u8; 48];
        // SAFETY: `aff` is produced by `blst` from a validated signature, and
        // the output buffers are correctly sized for 48-byte field elements.
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

    fn from_blst_unchecked(sig: &BlstSignature) -> Self {
        Self(HexBytes::from(sig.compress().to_vec()))
    }

    fn as_blst(&self) -> Result<BlstSignature, BlsError> {
        let sig =
            BlstSignature::from_bytes(self.0.as_bytes()).map_err(BlsError::InvalidSignature)?;
        sig.validate(true).map_err(BlsError::InvalidSignature)?;
        Ok(sig)
    }
}

impl serde::Serialize for BlsSignature {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> serde::Deserialize<'de> for BlsSignature {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        let value = value.strip_prefix("0x").unwrap_or(value.as_str());
        let bytes = hex::decode(value)
            .map_err(|e| serde::de::Error::custom(format!("invalid hex: {e}")))?;
        BlsSignature::from_bytes(&bytes).map_err(|e| serde::de::Error::custom(e.to_string()))
    }
}

/// Raw claims bytes used as the message to be signed.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct BlsClaims(HexBytes);

impl BlsClaims {
    /// Wrap raw claims bytes.
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Self {
        Self(HexBytes::from_bytes(bytes))
    }

    /// Parse claims bytes from hex (with or without `0x`).
    pub fn from_hex(value: &str) -> Result<Self, BlsError> {
        let value = value.strip_prefix("0x").unwrap_or(value);
        let bytes = hex::decode(value)?;
        Ok(Self(HexBytes::from_bytes(bytes)))
    }

    /// Borrow the raw claims bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Return the raw claims bytes as an owned vector.
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    /// Return the claims as lowercase hex (no `0x` prefix).
    pub fn to_hex(&self) -> String {
        self.0.to_hex()
    }
}

impl From<Vec<u8>> for BlsClaims {
    fn from(value: Vec<u8>) -> Self {
        Self::from_bytes(value)
    }
}

impl AsRef<[u8]> for BlsClaims {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

/// BLS certificate, serialized as hex-encoded claims + signature.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BLSCert {
    pub claims: BlsClaims,
    pub signature: BlsSignature,
}

impl BLSCert {
    /// Sign a new certificate from claims bytes.
    pub fn sign(key: &KeyMaterial, claims: BlsClaims) -> Result<Self, BlsError> {
        let sig = key.sign(claims.as_bytes());
        Ok(BLSCert {
            claims,
            signature: sig,
        })
    }

    /// Legacy constructor that accepts any claims payload convertible to bytes.
    #[deprecated(note = "use BLSCert::sign")]
    pub fn new<C: TryInto<Vec<u8>>>(sk: &KeyMaterial, claims: C) -> anyhow::Result<Self>
    where
        C::Error: Display,
    {
        let claims_bytes = claims
            .try_into()
            .map_err(|e| anyhow::anyhow!("failed to convert claims to bytes: {}", e))?;
        let claims = BlsClaims::from_bytes(claims_bytes);
        Ok(BLSCert::sign(sk, claims)?)
    }

    /// Verify the certificate signature against a public key.
    ///
    /// Uses `blst::Signature::verify` with group checks enabled for both the
    /// signature and the public key.
    pub fn verify(&self, pub_key: &BlsPublicKey) -> Result<(), BlsError> {
        let pk = pub_key.as_blst()?;
        let sig = self.signature.as_blst()?;
        let err = sig.verify(true, self.claims.as_bytes(), DST, &[], &pk, true);
        if err == blst::BLST_ERROR::BLST_SUCCESS {
            Ok(())
        } else {
            Err(BlsError::VerificationFailed)
        }
    }

    /// Borrow the claims payload.
    pub fn claims(&self) -> &BlsClaims {
        &self.claims
    }

    /// Borrow the signature payload.
    pub fn signature(&self) -> &BlsSignature {
        &self.signature
    }

    /// Legacy helper that returns an owned copy of claims bytes.
    #[deprecated(note = "use claims() or claims.as_bytes()")]
    pub fn claims_bytes(&self) -> anyhow::Result<Vec<u8>> {
        Ok(self.claims.to_vec())
    }
}

fn split_fp_be48_into_hi_lo32(be48: &[u8; 48]) -> ([u8; 32], [u8; 32]) {
    let mut hi = [0u8; 32];
    let mut lo = [0u8; 32];
    hi[16..].copy_from_slice(&be48[..16]);
    lo.copy_from_slice(&be48[16..]);
    (hi, lo)
}

#[deprecated(note = "use BlsSignature::to_solidity_words")]
/// Legacy conversion helper for Solidity word encoding.
pub fn g2_words_from_signature(sig_bytes: &[u8]) -> anyhow::Result<[[u8; 32]; 8]> {
    let sig = BlsSignature::from_bytes(sig_bytes)?;
    Ok(sig.to_solidity_words()?)
}

/// BLS key material that owns the secret key.
pub struct KeyMaterial(SecretBox<SecretKey>);

impl KeyMaterial {
    /// Parse and validate a secret key from raw bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, BlsError> {
        let sk = SecretKey::from_bytes(bytes).map_err(BlsError::InvalidSecretKey)?;
        Ok(Self(SecretBox::new(Box::new(sk))))
    }

    /// Derive the corresponding compressed public key.
    pub fn public_key(&self) -> BlsPublicKey {
        let bytes = self.0.expose_secret().sk_to_pk().compress().to_vec();
        BlsPublicKey::from_compressed_unchecked(bytes)
    }

    /// Sign a message with the secret key.
    pub fn sign(&self, msg: &[u8]) -> BlsSignature {
        let sig = self.0.expose_secret().sign(msg, DST, &[]);
        BlsSignature::from_blst_unchecked(&sig)
    }
}

impl std::fmt::Debug for KeyMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KeyMaterial([REDACTED])")
    }
}

impl FromStr for KeyMaterial {
    type Err = BlsError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let stripped = s.strip_prefix("0x").unwrap_or(s);
        let bytes = Zeroizing::new(hex::decode(stripped)?);

        let sk = SecretKey::from_bytes(&bytes).map_err(BlsError::InvalidSecretKey)?;
        Ok(Self(SecretBox::new(Box::new(sk))))
    }
}

#[deprecated(note = "use KeyMaterial")]
pub type BlsSecretKey = KeyMaterial;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex::HexBytes;

    #[test]
    fn hex_bytes_round_trip() {
        let data = HexBytes::from_bytes(b"claims".to_vec());
        let json = serde_json::to_string(&data).expect("serialize hex bytes");
        assert_eq!(json, "\"636c61696d73\"");

        let parsed: HexBytes =
            serde_json::from_str("\"0x636c61696d73\"").expect("deserialize hex bytes");
        assert_eq!(parsed.as_bytes(), b"claims");
    }

    #[test]
    fn bls_cert_serialization_is_stable() {
        let sk_bytes = [1u8; 32];
        let key = KeyMaterial::from_bytes(&sk_bytes).expect("valid key");
        let claims = BlsClaims::from_bytes(b"hello".to_vec());
        let cert = BLSCert::sign(&key, claims.clone()).expect("sign cert");

        let json = serde_json::to_string(&cert).expect("serialize cert");
        let expected_claims_hex = hex::encode(b"hello");
        assert!(json.contains(&format!("\"claims\":\"{expected_claims_hex}\"")));

        let parsed: BLSCert = serde_json::from_str(&json).expect("deserialize cert");
        assert_eq!(parsed.claims.as_bytes(), claims.as_bytes());
    }

    #[test]
    fn verify_succeeds_and_fails() {
        let sk_bytes = [2u8; 32];
        let key = KeyMaterial::from_bytes(&sk_bytes).expect("valid key");
        let claims = BlsClaims::from_bytes(b"payload".to_vec());
        let cert = BLSCert::sign(&key, claims).expect("sign cert");
        let pk = key.public_key();

        assert!(cert.verify(&pk).is_ok());

        let other_key = KeyMaterial::from_bytes(&[3u8; 32]).expect("valid key");
        let other_pk = other_key.public_key();
        let err = cert.verify(&other_pk).expect_err("mismatch should fail");
        assert!(matches!(err, BlsError::VerificationFailed));
    }

    #[test]
    fn invalid_signature_rejected() {
        let bytes = vec![0u8; 96];
        let err = BlsSignature::from_bytes(&bytes).expect_err("invalid signature");
        assert!(matches!(err, BlsError::InvalidSignature(_)));
    }

    #[test]
    fn invalid_public_key_rejected() {
        let bytes = vec![0u8; 48];
        let err = BlsPublicKey::from_bytes(&bytes).expect_err("invalid public key");
        assert!(matches!(err, BlsError::InvalidPublicKey(_)));
    }
}
