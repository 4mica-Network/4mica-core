import json
import os
from dotenv import load_dotenv
from core_4mica_client import w3, Core4Mica, remunerate  
from eth_utils import to_checksum_address
from py_ecc.bls import G2Basic as bls                    
from web3 import Web3

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
    """Return native ETH balance (in Ether)."""
    return w3.from_wei(w3.eth.get_balance(addr), "ether")

def user_collateral(addr):
    """Return the collateral locked in Core4Mica for a given address (in Ether)."""
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

def decompress_g2_signature(sig_hex: str):
    """
    Decompress a 96-byte compressed BLS12-381 G2 signature into the
    8 x bytes32 limbs expected by the Solidity contract.
    Returns a tuple formatted exactly for core_4mica_client.remunerate():
        ((x_c0_a, x_c0_b), (y_c0_a, y_c0_b))
    """
    sig_bytes = bytes.fromhex(sig_hex)

    # G2Basic._deserialize_g2 returns:
    # ((x_c0, x_c1), (y_c0, y_c1)) where each is an Fq element (python int)
    (x_c0, x_c1), (y_c0, y_c1) = bls._deserialize_g2(sig_bytes)

    def fq_to_hex(val: int) -> str:
        # Convert field element integer to 32-byte big-endian hex string
        return Web3.to_hex(val.to_bytes(32, "big"))

    return (
        (fq_to_hex(x_c0), fq_to_hex(x_c1)),   # X coordinates
        (fq_to_hex(y_c0), fq_to_hex(y_c1)),   # Y coordinates
    )

# =========================================================
# Load guarantee and decompress signature
# =========================================================
with open("guarantee.json", "r", encoding="utf-8") as f:
    data = json.load(f)

guarantee = data["guarantee"]
sig_hex   = data["signature"]      # 96-byte compressed signature as hex string
signature = decompress_g2_signature(sig_hex)

# =========================================================
# Show info BEFORE remuneration
# =========================================================
print_info("Balances BEFORE remuneration")

# =========================================================
# Execute remuneration transaction
# =========================================================
print("\n➡️  Sending remuneration transaction …")
receipt = remunerate(PRIVATE_KEY, guarantee, signature)

print("\n==== Remunerate confirmed ====")
print("Tx hash :", receipt.transactionHash.hex())
print("Status  :", receipt.status)

# =========================================================
# Show info AFTER remuneration
# =========================================================
print_info("Balances AFTER remuneration")
