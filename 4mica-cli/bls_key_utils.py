#!/usr/bin/env python3
from math import ceil
from typing import Tuple

from py_ecc.bls import G2Basic as bls
from py_ecc.bls12_381 import curve_order
from py_ecc.bls.point_compression import decompress_G1, compress_G1
from py_ecc.optimized_bls12_381 import G1, multiply, normalize


# ----------------------------- helpers -----------------------------

def urandom_bytes(n: int) -> bytes:
    with open("/dev/urandom", "rb") as f:
        return f.read(n)


def generate_bls_secret_key() -> int:
    """Generate a random BLS12-381 secret key scalar in [1, r-1]."""
    r = curve_order
    r_bits = r.bit_length()
    byte_len = ceil(r_bits / 8)
    while True:
        candidate = int.from_bytes(urandom_bytes(byte_len), "big")
        if 1 <= candidate < r:
            return candidate


def secret_key_to_bytes(sk: int) -> bytes:
    """32-byte big-endian representation of secret scalar."""
    return sk.to_bytes(32, "big")


def fq_to_48_be(n: int) -> bytes:
    b = int(n).to_bytes(48, "big")
    if len(b) != 48:
        raise ValueError("Fp did not encode to 48 bytes")
    return b


def split48_to_fp_words(b48: bytes) -> Tuple[bytes, bytes]:
    """
    Split a 48-byte big-endian Fp element into Solady-style words {a,b}:
      - a: high 16 bytes, left-padded to 32 (bytes32)
      - b: low  32 bytes (bytes32)
    """
    hi16, lo32 = b48[:16], b48[16:]
    return (hi16.rjust(32, b"\x00"), lo32)


def reconstruct_48_from_words(a32: bytes, b32: bytes) -> bytes:
    """
    Inverse of split48_to_fp_words: recover the original 48-byte big-endian Fp element.
    `a32` is a 32-byte value whose low 16 bytes equal the high 16 bytes of the 48-byte Fp.
    `b32` is the low 32 bytes of the 48-byte Fp.
    """
    if len(a32) != 32 or len(b32) != 32:
        raise ValueError("Expected bytes32 for both limbs")
    hi16 = a32[-16:]        # drop the 16 bytes of left padding
    lo32 = b32
    return hi16 + lo32      # 16 + 32 = 48


def pubkey_limbs_from_sk(sk_int: int):
    """
    Derive compressed G1 pubkey via BLS.SkToPk, then decompress to affine,
    and return limbs {x_a, x_b, y_a, y_b} as bytes32 suitable for Solidity.
    """
    pk_comp = bls.SkToPk(sk_int)  # 48-byte compressed G1 pubkey
    if len(pk_comp) != 48:
        raise ValueError("Unexpected pubkey length (want 48 bytes)")

    zint = int.from_bytes(pk_comp, "big")
    x_aff, y_aff, _ = decompress_G1(zint)  # returns FQ, FQ, bool

    x_a, x_b = split48_to_fp_words(fq_to_48_be(int(x_aff)))
    y_a, y_b = split48_to_fp_words(fq_to_48_be(int(y_aff)))
    return (x_a, x_b, y_a, y_b), pk_comp, (x_aff, y_aff)


def bytes_diff(a: bytes, b: bytes) -> str:
    """Human-friendly first-difference report for two equal-length byte strings."""
    if len(a) != len(b):
        return f"lengths differ: {len(a)} vs {len(b)}"
    for i, (aa, bb) in enumerate(zip(a, b)):
        if aa != bb:
            return f"first diff at byte {i}: 0x{aa:02x} vs 0x{bb:02x}"
    return "no diff"


def verify_pubkey(sk_int: int, pk_comp: bytes, affine_xy):
    """
    Strong checks:
      A) Re-derive pubkey by scalar-multiplying base: P = sk * G1 (Jacobian).
         - normalize to affine (x2,y2)
         - check (x2,y2) == decompressed affine_xy
      B) Compress Jacobian P directly: compress_G1(P) must equal pk_comp
      C) Sign/verify a random message via BLS
    """
    x_aff, y_aff = affine_xy

    # A) Re-derive point from scalar and compare affine coordinates
    P = multiply(G1, sk_int)         # Jacobian (x, y, z)
    x2, y2 = normalize(P)            # affine
    if int(x2) != int(x_aff) or int(y2) != int(y_aff):
        raise RuntimeError("❌ Affine coords mismatch between decompressed SkToPk and scalar-multiplied G1")

    # B) Compress the Jacobian point directly (what compress_G1 expects)
    recompressed_int = compress_G1(P)                  # int
    recompressed = recompressed_int.to_bytes(48, "big")
    if recompressed != pk_comp:
        raise RuntimeError(
            "❌ Recompressed pubkey (from Jacobian P) != SkToPk bytes\n"
            f"  recompressed: 0x{recompressed.hex()}\n"
            f"  SkToPk:       0x{pk_comp.hex()}"
        )

    # C) Sign/verify sanity check
    test_msg = urandom_bytes(32)
    sig = bls.Sign(sk_int, test_msg)
    if not bls.Verify(pk_comp, test_msg, sig):
        raise RuntimeError("❌ Signature verification failed with derived public key!")

    print("✅ Public key integrity verified: coords match, compression match, and sign/verify passed.")


# ------------------------------ main -------------------------------

def main():
    """Generate a keypair and run all integrity checks."""
    sk_int = generate_bls_secret_key()
    sk_bytes = secret_key_to_bytes(sk_int)
    (x_a, x_b, y_a, y_b), pk_comp, affine_xy = pubkey_limbs_from_sk(sk_int)

    # run the full verification routine
    verify_pubkey(sk_int, pk_comp, affine_xy)

    print("\n=== BLS12-381 Key Pair ===")
    print("Secret key (int):", sk_int)
    print("Secret key (hex 0x…):", "0x" + sk_bytes.hex())
    print("\nPublic key (compressed, 48 bytes):")
    print("0x" + pk_comp.hex())
    print("\nPublic key limbs (Solidity bytes32 values):")
    print("x_a:", "0x" + x_a.hex())
    print("x_b:", "0x" + x_b.hex())
    print("y_a:", "0x" + y_a.hex())
    print("y_b:", "0x" + y_b.hex())


if __name__ == "__main__":
    main()
