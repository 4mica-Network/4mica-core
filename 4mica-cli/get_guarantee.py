#!/usr/bin/env python3
import time, json, uuid, httpx, os, binascii
from datetime import datetime, timezone
from dotenv import load_dotenv
from eth_account import Account
from eth_account.messages import encode_typed_data
from eth_utils import to_checksum_address
from py_ecc.bls import G2Basic as bls
from core_4mica_client import w3, Core4Mica

# =========================================================
#  Load environment variables
# =========================================================
load_dotenv()

PRIVATE_KEY       = os.getenv("PRIVATE_KEY")
RPC_URL           = os.getenv("RPC_URL")
OPERATOR_URL      = os.getenv("OPERATOR_URL", "http://localhost:3000")
RECIPIENT_ADDRESS = os.getenv("RECIPIENT_ADDRESS")

if not PRIVATE_KEY or not RPC_URL or not RECIPIENT_ADDRESS:
    raise EnvironmentError(
        "PRIVATE_KEY, RPC_URL and RECIPIENT_ADDRESS must be set in .env"
    )

acct = w3.eth.account.from_key(PRIVATE_KEY)
USER_ADDR = acct.address
RECIPIENT_ADDRESS = to_checksum_address(RECIPIENT_ADDRESS)
print(f"Using USER_ADDR: {USER_ADDR}")

# =========================================================
#  JSON-RPC helper
# =========================================================
def api_call(method: str, params=None):
    payload = {
        "jsonrpc": "2.0",
        "id": str(uuid.uuid4()),
        "method": method,
        "params": params or []
    }
    r = httpx.post(OPERATOR_URL, json=payload)
    r.raise_for_status()
    data = r.json()
    if "error" in data:
        raise RuntimeError(data["error"])
    return data["result"]

# =========================================================
#  Helper functions
# =========================================================
def eth_balance(addr):
    return w3.from_wei(w3.eth.get_balance(addr), "ether")

def log_receipt(action: str, receipt):
    print(f"\n==== {action} confirmed ====")
    print(f"Transaction hash : {receipt.transactionHash.hex()}")
    print(f"Block number     : {receipt.blockNumber}")
    print(f"Gas used         : {receipt.gasUsed}")
    print(f"Status (1=OK)    : {receipt.status}")
    print(f"From             : {receipt['from']}")
    print(f"To               : {receipt['to']}")
    print(f"Etherscan link   : https://holesky.etherscan.io/tx/{receipt.transactionHash.hex()}")
    print("================================\n")

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
if w_timestamp > 0:
    print(f"Withdrawal request : YES ({w3.from_wei(w_amount, 'ether')} ETH)")
else:
    print("Withdrawal request : NO")
print("\n=======================================================")

# 2️⃣ Get public params from the operator
public_params = api_call("core_getPublicParams")
print("\n=== Core Public Parameters ===")
print(json.dumps(public_params, indent=2))

# 3️⃣ Create a payment tab FIRST (important!)
print("\n➡️  Creating a new payment tab …")
create_req = {
    "user_address": USER_ADDR,
    "recipient_address": RECIPIENT_ADDRESS,
}
new_tab = api_call("core_createPaymentTab", [create_req])
tab_id = new_tab["id"]
print(f"✅ New tab created with id: {tab_id}")

# 4️⃣ Build & sign a PaymentGuaranteeRequest (EIP-712)
timestamp = int(datetime.now(timezone.utc).timestamp())
REQ_ID_INT      = 0                      # first request for a new tab is 0
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

# 6️⃣ Verify the BLS certificate off-chain
# 6️⃣ Verify the BLS certificate off-chain
print("\n➡️  Verifying BLS certificate …")

# public_params["public_key"] is a hex string (e.g. "aabbcc…")
pubkey = bytes(public_params["public_key"])   
sig    = bytes.fromhex(bls_cert["signature"])        
message_bytes = binascii.unhexlify(bls_cert["claims"])

if bls.Verify(pubkey, message_bytes, sig):
    print("✅  BLS signature is VALID")
else:
    print("❌  BLS signature is INVALID")

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
