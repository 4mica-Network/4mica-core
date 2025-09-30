import json
import os
import time
import binascii
import pytest

from py_ecc.bls import G2Basic as bls

from bls_key_utils import (
    generate_bls_secret_key,
    pubkey_limbs_from_sk,
    verify_pubkey,
    secret_key_to_bytes,
)

# ----------------------------------------------------------------------
# Helper to build a fake guarantee-like payload and sign it
# ----------------------------------------------------------------------
def build_fake_guarantee(sk_int: int):
    """
    Create a dict shaped like the real guarantee.json and
    return (guarantee_dict, message_bytes, signature_bytes).
    """
    now = int(time.time())
    claims = {
        "user_address": "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
        "recipient_address": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
        "tab_id": os.urandom(32).hex(),
        "req_id": "0",
        "amount": "200000000000000000",
        "timestamp": now,
    }
    tab_timestamp = now

    # Serialize the claims deterministically; here we just
    # hex-encode the JSON bytes to imitate the operator script.
    message_bytes = json.dumps(claims, separators=(",", ":")).encode("utf-8")
    msg_hex = binascii.hexlify(message_bytes)

    sig_bytes = bls.Sign(sk_int, message_bytes)

    guarantee_payload = {
        "claims": claims,
        "tab_timestamp": tab_timestamp,
        "bls_signature": sig_bytes.hex(),
    }
    return guarantee_payload, message_bytes, sig_bytes


# ----------------------------------------------------------------------
# Tests
# ----------------------------------------------------------------------

def test_end_to_end_bls_signature_and_pubkey():
    """
    1. Generate BLS keypair
    2. Verify pubkey integrity (coords, compression, sign/verify)
    3. Build a fake guarantee payload and sign it
    4. Verify the signature with the derived pubkey
    """
    sk_int = generate_bls_secret_key()
    sk_bytes = secret_key_to_bytes(sk_int)
    assert len(sk_bytes) == 32

    (x_a, x_b, y_a, y_b), pk_comp, affine_xy = pubkey_limbs_from_sk(sk_int)

    # Strong internal checks (coords & compression)
    verify_pubkey(sk_int, pk_comp, affine_xy)

    # Build and sign a fake guarantee
    guarantee_payload, message_bytes, sig_bytes = build_fake_guarantee(sk_int)

    # BLS verification must succeed with our derived pubkey
    assert bls.Verify(pk_comp, message_bytes, sig_bytes), \
        "BLS signature should verify with the correct public key"

    # Negative check: wrong message must fail
    wrong_message = b"x" + message_bytes[1:]
    assert not bls.Verify(pk_comp, wrong_message, sig_bytes), \
        "Verification should fail for a modified message"

    # Negative check: wrong public key must fail
    sk_other = generate_bls_secret_key()
    pk_other = bls.SkToPk(sk_other)
    assert not bls.Verify(pk_other, message_bytes, sig_bytes), \
        "Verification should fail with an unrelated public key"

    # Round-trip guarantee JSON to disk and back
    fname = "tmp_test_guarantee.json"
    with open(fname, "w", encoding="utf-8") as f:
        json.dump(guarantee_payload, f, indent=2)
    with open(fname, "r", encoding="utf-8") as f:
        loaded = json.load(f)
    os.remove(fname)

    # Ensure we recovered the same claims and signature
    assert loaded["claims"] == guarantee_payload["claims"]
    assert loaded["tab_timestamp"] == guarantee_payload["tab_timestamp"]
    assert loaded["bls_signature"] == guarantee_payload["bls_signature"]
