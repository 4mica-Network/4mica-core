use alloy::primitives::{Address, U256};
use std::str::FromStr;

// === low-level imports from blst for signing and coordinate extraction ===
use blst::{
    self, blst_p1_affine, blst_p2_affine,
    min_pk::{PublicKey as BlstPublicKey, SecretKey, Signature as BlstSignature},
};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BLSCert {
    pub claims: String,    // hex of abi.encodePacked(...)
    pub signature: String, // hex of compressed G2 (96 bytes)
}

const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

pub fn encode_guarantee_bytes(
    tab_id: U256,
    req_id: U256,
    client: &str,
    recipient: &str,
    amount: U256,
    tab_timestamp: u64,
) -> anyhow::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(32 + 32 + 20 + 20 + 32 + 8);
    let addr_client = Address::from_str(client)?;
    let addr_recipient = Address::from_str(recipient)?;
    out.extend_from_slice(&tab_id.to_be_bytes::<32>());
    out.extend_from_slice(&req_id.to_be_bytes::<32>());
    out.extend_from_slice(addr_client.as_slice());
    out.extend_from_slice(addr_recipient.as_slice());
    out.extend_from_slice(&amount.to_be_bytes::<32>());
    out.extend_from_slice(&tab_timestamp.to_be_bytes());
    Ok(out)
}

impl BLSCert {
    /// Create and sign using IKM (seed) via `SecretKey::key_gen(ikm, info)`.
    /// `ikm` can be any bytes >= 32 (your HexBytes is perfect).
    pub fn new(
        ikm: &[u8],
        tab_id: U256,
        req_id: U256,
        client: &str,
        recipient: &str,
        amount: U256,
        tab_timestamp: u64,
    ) -> anyhow::Result<Self> {
        let claims_bytes =
            encode_guarantee_bytes(tab_id, req_id, client, recipient, amount, tab_timestamp)?;

        let sk = SecretKey::key_gen(ikm, &[]).map_err(|e| anyhow::anyhow!("key_gen: {:?}", e))?;
        let sig = sk.sign(&claims_bytes, DST, &[]); // BASIC / RO
        let signature = sig.compress();

        Ok(BLSCert {
            claims: hex::encode(claims_bytes),
            signature: hex::encode(signature),
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

/// Get BLS public key bytes from a private key – same as BlsHelper.getPublicKey
pub fn pub_key_from_priv_key(ikm: &[u8]) -> anyhow::Result<Vec<u8>> {
    let sk = SecretKey::key_gen(ikm, &[]).map_err(|e| anyhow::anyhow!("key_gen: {:?}", e))?;
    Ok(sk.sk_to_pk().compress().to_vec())
}

// ================== helpers for Solidity limb layout ==================

/// Split a 48-byte big-endian field element into two 32-byte words:
/// - hi: left-padded with zeros to 32 bytes (top 16 bytes)
/// - lo: bottom 32 bytes
fn split_fp_be48_into_hi_lo32(be48: &[u8; 48]) -> ([u8; 32], [u8; 32]) {
    let mut hi = [0u8; 32];
    let mut lo = [0u8; 32];
    hi[16..].copy_from_slice(&be48[..16]);
    lo.copy_from_slice(&be48[16..]);
    (hi, lo)
}

/// Convert a compressed min-pk public key (48 bytes) into the 4 * 32-byte words
/// that Solidity BLS.G1Point expects: (x_hi, x_lo, y_hi, y_lo).
pub fn g1_words_from_pubkey(
    pk_bytes: &[u8],
) -> anyhow::Result<([u8; 32], [u8; 32], [u8; 32], [u8; 32])> {
    let pk = BlstPublicKey::from_bytes(pk_bytes)
        .map_err(|e| anyhow::anyhow!("invalid BLS public key: {:?}", e))?;
    let aff: blst_p1_affine = pk.into();

    let mut x_be = [0u8; 48];
    let mut y_be = [0u8; 48];
    unsafe {
        blst::blst_bendian_from_fp(x_be.as_mut_ptr(), &aff.x);
        blst::blst_bendian_from_fp(y_be.as_mut_ptr(), &aff.y);
    }
    let (x_hi, x_lo) = split_fp_be48_into_hi_lo32(&x_be);
    let (y_hi, y_lo) = split_fp_be48_into_hi_lo32(&y_be);
    Ok((x_hi, x_lo, y_hi, y_lo))
}

/// Convert a compressed min-pk signature (96 bytes) into the 8 * 32-byte words
/// Solidity BLS.G2Point uses: X.c0, X.c1, Y.c0, Y.c1; each split (hi, lo).
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
