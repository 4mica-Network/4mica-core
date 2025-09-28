#!/usr/bin/env python3
import os, json, uuid, httpx, binascii
from datetime import datetime, timezone
from dotenv import load_dotenv
from eth_account import Account
from eth_account.messages import encode_typed_data
from eth_utils import to_checksum_address
from py_ecc.bls import G2Basic as bls          # BLS pubkey in G1 (48 bytes), sig in G2 (96 bytes)
from core_4mica_client import w3, Core4Mica

# =========================================================
#  Load environment variables
# =========================================================
load_dotenv()

PRIVATE_KEY       = os.getenv("PRIVATE_KEY")        # EVM key (secp256k1)
BLS_PRIVATE_KEY   = os.getenv("BLS_PRIVATE_KEY")    # BLS key (scalar in [1, r-1])
RPC_URL           = os.getenv("RPC_URL")
OPERATOR_URL      = os.getenv("OPERATOR_URL", "http://localhost:3000")
RECIPIENT_ADDRESS = os.getenv("RECIPIENT_ADDRESS")

if not PRIVATE_KEY or not RPC_URL or not RECIPIENT_ADDRESS:
    raise EnvironmentError("PRIVATE_KEY, RPC_URL and RECIPIENT_ADDRESS must be set in .env")
if not BLS_PRIVATE_KEY:
    raise EnvironmentError("BLS_PRIVATE_KEY must be set in .env")

acct = w3.eth.account.from_key(PRIVATE_KEY)
USER_ADDR = acct.address
RECIPIENT_ADDRESS = to_checksum_address(RECIPIENT_ADDRESS)
print(f"Using USER_ADDR: {USER_ADDR}")

# =========================================================
#  JSON-RPC helper
# =========================================================
def api_call(method: str, params=None):
    payload = {"jsonrpc": "2.0", "id": str(uuid.uuid4()), "method": method, "params": params or []}
    r = httpx.post(OPERATOR_URL, json=payload)
    r.raise_for_status()
    data = r.json()
    if "error" in data:
        raise RuntimeError(data["error"])
    return data["result"]

# =========================================================
#  Helpers
# =========================================================
def eth_balance(addr):
    return w3.from_wei(w3.eth.get_balance(addr), "ether")

def normalize_pubkey_from_operator(value) -> bytes:
    """
    Operator may return BLS pubkey as:
      - list[int] length 48 (bytes), or
      - hex string "0x.." or plain hex.
    Normalize to raw bytes (48 bytes).
    """
    if isinstance(value, list):
        return bytes(value)
    if isinstance(value, str):
        h = value[2:] if value.startswith("0x") else value
        return bytes.fromhex(h)
    raise TypeError("Unsupported public_key format from operator")

# =========================================================
#  Main flow
# =========================================================
print("=======================================================")
print(f"User address        : {USER_ADDR}")
print(f"Initial ETH balance : {eth_balance(USER_ADDR)} ETH")
print("=======================================================\n")

# 1️⃣ Query on-chain user data
print("➡️  Reading on-chain user data via getUser() …")
collateral, w_timestamp, w_amount = Core4Mica.functions.getUser(USER_ADDR).call()
print(f"Collateral locked  : {w3.from_wei(collateral, 'ether')} ETH")
print("Withdrawal request : YES ({:.18f} ETH)".format(w3.from_wei(w_amount, 'ether')) if w_timestamp > 0 else "Withdrawal request : NO")
print("\n=======================================================")

# 2️⃣ Get public params from the operator
public_params = api_call("core_getPublicParams")
print("\n=== Core Public Parameters ===")
print(json.dumps(public_params, indent=2))

# Operator public key (bytes48)
operator_pubkey = normalize_pubkey_from_operator(public_params["public_key"])
print(f"\nOperator's BLS public key ({len(operator_pubkey)} bytes): {operator_pubkey.hex()}")

# Derive local BLS pubkey from BLS_PRIVATE_KEY (hex → int → SkToPk)
sk_int = int(BLS_PRIVATE_KEY, 16)
local_pubkey = bls.SkToPk(sk_int)  # returns compressed G1 bytes (48 bytes)
print(f"Locally derived BLS public key ({len(local_pubkey)} bytes): {local_pubkey.hex()}")

if local_pubkey == operator_pubkey:
    print("✅ Local BLS pubkey matches operator's public key")
else:
    print("❌ Local BLS pubkey does NOT match operator's public key")

# 3️⃣ Create a payment tab
print("\n➡️  Creating a new payment tab …")
create_req = {"user_address": USER_ADDR, "recipient_address": RECIPIENT_ADDRESS}
new_tab = api_call("core_createPaymentTab", [create_req])
tab_id = new_tab["id"]
print(f"✅ New tab created with id: {tab_id}")

# 4️⃣ Build & sign a PaymentGuaranteeRequest (EIP-712)
timestamp = int(datetime.now(timezone.utc).timestamp())
REQ_ID_INT      = 0                       # first request for a new tab is 0
AMOUNT_WEI_INT  = 200_000_000_000_000_000 # 0.2 ETH

claims = {
    "user_address": USER_ADDR,
    "recipient_address": RECIPIENT_ADDRESS,
    "tab_id": tab_id,
    "req_id": str(REQ_ID_INT),
    "amount": str(AMOUNT_WEI_INT),
    "timestamp": timestamp,
}

typed_data = {
    "types": {
        "EIP712Domain": [
            {"name": "name", "type": "string"},
            {"name": "version", "type": "string"},
            {"name": "chainId", "type": "uint256"},
        ],
        "PaymentGuarantee": [
            {"name": "user", "type": "address"},
            {"name": "recipient", "type": "address"},
            {"name": "tabId", "type": "uint256"},
            {"name": "reqId", "type": "uint256"},
            {"name": "amount", "type": "uint256"},
            {"name": "timestamp", "type": "uint64"},
        ],
    },
    "primaryType": "PaymentGuarantee",
    "domain": {
        "name": public_params["eip712_name"],
        "version": public_params["eip712_version"],
        "chainId": public_params["chain_id"],
    },
    "message": {
        "user": USER_ADDR,
        "recipient": RECIPIENT_ADDRESS,
        "tabId": tab_id,
        "reqId": REQ_ID_INT,
        "amount": AMOUNT_WEI_INT,
        "timestamp": timestamp,
    },
}

msg = encode_typed_data(full_message=typed_data)
signed = Account.sign_message(msg, private_key=PRIVATE_KEY)

payment_request = {
    "claims": claims,
    "signature": signed.signature.hex(),
    "scheme": "eip712"
}

# 5️⃣ Request a BLS guarantee
print("\n➡️  Requesting BLS guarantee …")
bls_cert = api_call("core_issueGuarantee", [payment_request])
print("\n=== BLS Certificate ===")
print(json.dumps(bls_cert, indent=2))

# 6️⃣ Verify the BLS certificate off-chain with operator's pubkey
print("\n➡️  Verifying BLS certificate …")
sig_bytes     = bytes.fromhex(bls_cert["signature"])       # G2 signature (compressed, 96 bytes) expected
message_bytes = binascii.unhexlify(bls_cert["claims"])     # exact bytes the operator signed

# Verification with Basic scheme: pubkey (48), message (bytes), signature (96)
if bls.Verify(operator_pubkey, message_bytes, sig_bytes):
    print("✅  BLS signature is VALID (using operator's public key)")
else:
    print("❌  BLS signature is INVALID (using operator's public key)")

# Optional: also verify with locally-derived pubkey if you expect them to be the same entity
if local_pubkey == operator_pubkey:
    if bls.Verify(local_pubkey, message_bytes, sig_bytes):
        print("✅  BLS signature also VALID against locally-derived pubkey")
    else:
        print("❌  Unexpected: signature invalid for locally-derived pubkey")

# 7️⃣ Save the guarantee for later remuneration
guarantee_file = "guarantee.json"
guarantee_payload = {
    "claims": claims,
    "tab_timestamp": claims["timestamp"],
    "bls_signature": bls_cert["signature"],
}
with open(guarantee_file, "w", encoding="utf-8") as f:
    json.dump(guarantee_payload, f, indent=2)
print(f"\n✅ Guarantee saved to {guarantee_file}")
