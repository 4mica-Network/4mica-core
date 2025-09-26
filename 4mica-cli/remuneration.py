import json
import os
from dotenv import load_dotenv
from eth_utils import to_checksum_address
from web3 import Web3
from py_ecc.bls.point_compression import decompress_G2

from core_4mica_client import w3, Core4Mica, remunerate

# =========================================================
# Load environment variables
# =========================================================
load_dotenv()
PRIVATE_KEY = os.getenv("PRIVATE_KEY")
RECIPIENT_ADDRESS = os.getenv("RECIPIENT_ADDRESS")
if not PRIVATE_KEY or not RECIPIENT_ADDRESS:
    raise EnvironmentError("PRIVATE_KEY and RECIPIENT_ADDRESS must be set in .env")

acct = w3.eth.account.from_key(PRIVATE_KEY)
USER_ADDR = acct.address
RECIPIENT_ADDRESS = to_checksum_address(RECIPIENT_ADDRESS)

# =========================================================
# Helpers
# =========================================================
def eth_balance(addr):
    return w3.from_wei(w3.eth.get_balance(addr), "ether")

def user_collateral(addr):
    collateral, _, _ = Core4Mica.functions.getUser(addr).call()
    return w3.from_wei(collateral, "ether")

def print_info(title: str):
    print(f"\n==== {title} ====")
    print(f"User address             : {USER_ADDR}")
    print(f"User ETH balance         : {eth_balance(USER_ADDR)} ETH")
    print(f"User Core4Mica collateral: {user_collateral(USER_ADDR)} ETH")
    print(f"Recipient address        : {RECIPIENT_ADDRESS}")
    print(f"Recipient ETH balance    : {eth_balance(RECIPIENT_ADDRESS)} ETH")
    print("=========================================")

def _fq_to_two_bytes32(val: int) -> tuple[str, str]:
    """
    Split a 381-bit FQ element into two bytes32 words:
    - high 24 bytes (MSB) left-padded to 32 bytes
    - low  24 bytes (LSB) left-padded to 32 bytes
    """
    b = val.to_bytes(48, "big")
    hi = b[:24]
    lo = b[24:]
    return (
        Web3.to_hex(hi.rjust(32, b"\x00")),
        Web3.to_hex(lo.rjust(32, b"\x00")),
    )

def signature_bytes32x8_from_compressed(sig_hex: str):
    """
    Input: 96-byte compressed G2 signature as hex string
    Output: flat tuple of 8×bytes32 (ABI-ready):
      (x.c0_hi, x.c0_lo, x.c1_hi, x.c1_lo, y.c0_hi, y.c0_lo, y.c1_hi, y.c1_lo)
    """
    sig_bytes = bytes.fromhex(sig_hex)
    if len(sig_bytes) != 96:
        raise ValueError("BLS signature must be exactly 96 bytes (G2 compressed)")

    z1 = int.from_bytes(sig_bytes[:48], "big")
    z2 = int.from_bytes(sig_bytes[48:], "big")

    x, y, _ = decompress_G2((z1, z2))  # x,y are FQ2; .coeffs = [c0, c1] as FQ (ints)

    return (
        *_fq_to_two_bytes32(x.coeffs[0]),
        *_fq_to_two_bytes32(x.coeffs[1]),
        *_fq_to_two_bytes32(y.coeffs[0]),
        *_fq_to_two_bytes32(y.coeffs[1]),
    )

# =========================================================
# Load guarantee and build ABI-ready signature
# =========================================================
with open("guarantee.json", "r", encoding="utf-8") as f:
    data = json.load(f)

guarantee = data["claims"]                   # expects keys: tab_id,timestamp,user_address,recipient_address,req_id,amount
sig_hex   = data["bls_signature"]            # 96-byte compressed signature hex
sig_tuple = signature_bytes32x8_from_compressed(sig_hex)  # -> 8×bytes32

# =========================================================
# Show info BEFORE remuneration
# =========================================================
print_info("Balances BEFORE remuneration")

# =========================================================
# Execute remuneration transaction
# =========================================================
print("\n➡️  Sending remuneration transaction …")
receipt = remunerate(PRIVATE_KEY, guarantee, sig_tuple)

print("\n==== Remunerate confirmed ====")
print("Tx hash :", receipt.transactionHash.hex())
print("Status  :", receipt.status)

# =========================================================
# Show info AFTER remuneration
# =========================================================
print_info("Balances AFTER remuneration")
