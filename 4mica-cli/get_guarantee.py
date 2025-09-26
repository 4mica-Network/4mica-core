import time, json, uuid, httpx, os, binascii
from dotenv import load_dotenv
from eth_account import Account
from eth_account.messages import encode_typed_data
from eth_utils import to_checksum_address
from py_ecc.bls import G2Basic as bls
from datetime import datetime, timezone
from core_4mica_client import w3, Core4Mica

# =========================================================
#  Load environment variables
# =========================================================
load_dotenv()

PRIVATE_KEY       = os.getenv("PRIVATE_KEY")
RPC_URL           = os.getenv("RPC_URL")
API_URL           = os.getenv("API_URL", "http://localhost:3000")
RECIPIENT_ADDRESS = os.getenv("RECIPIENT_ADDRESS") 

if not PRIVATE_KEY or not RPC_URL or not RECIPIENT_ADDRESS:
    raise EnvironmentError(
        "PRIVATE_KEY, RPC_URL and RECIPIENT_ADDRESS must be set in .env"
    )

acct = w3.eth.account.from_key(PRIVATE_KEY)
USER_ADDR = acct.address

# Convert to checksummed address (EIP-55)
RECIPIENT_ADDRESS = to_checksum_address(RECIPIENT_ADDRESS)

# Your date/time string
dt_str = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
dt = datetime.strptime(dt_str, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
timestamp = int(dt.timestamp())

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
    r = httpx.post(API_URL, json=payload)
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
    print("Withdrawal request : YES")
    print(f"  • request time   : {w_timestamp}")
    print(f"  • amount         : {w3.from_wei(w_amount, 'ether')} ETH")
else:
    print("Withdrawal request : NO")
print("\n=======================================================")

# 2️⃣ Off-chain API: get Core public params
public_params = api_call("core_getPublicParams")
print("\n=== Core Public Parameters ===")
print(json.dumps(public_params, indent=2))

# 3️⃣ Build & sign a PaymentGuaranteeRequest
claims = {
    "user_address": USER_ADDR,
    "recipient_address": RECIPIENT_ADDRESS, 
    "tab_id": "12345",
    "req_id": "0",
    "amount": "2000000000000000",
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
            {"name": "tabId", "type": "string"},
            {"name": "reqId", "type": "uint64"},
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
        "tabId": claims["tab_id"],
        "reqId": int(claims["req_id"]),
        "amount": int(claims["amount"]),
        "timestamp": claims["timestamp"],
    },
}

msg = encode_typed_data(full_message=typed_data)
signed = Account.sign_message(msg, private_key=PRIVATE_KEY)

payment_request = {
    "claims": claims,
    "signature": signed.signature.hex(),
    "scheme": "eip712"
}

# 4️⃣ Request a BLS guarantee
bls_cert = api_call("core_issueGuarantee", [payment_request])
print("\n=== BLS Certificate ===")
print(json.dumps(bls_cert, indent=2))

# 5️⃣ Verify the BLS certificate with the public key
print("\n➡️  Verifying BLS certificate …")
pubkey = bytes(public_params["public_key"])
sig = bytes.fromhex(bls_cert["signature"])
message_bytes = binascii.unhexlify(bls_cert["claims"])
if bls.Verify(pubkey, message_bytes, sig):
    print("✅  BLS signature is VALID")
else:
    print("❌  BLS signature is INVALID")

print("\n=======================================================")
# 6️⃣ Save the guarantee (claims + BLS signature) to a JSON file
guarantee_file = f"guarantee.json"

guarantee_payload = {
    "claims": claims,                    # the same claims dict
    "tab_timestamp": claims["timestamp"],# for convenience in remuneration
    "bls_signature": bls_cert["signature"]  # hex string of BLS signature
}

with open(guarantee_file, "w", encoding="utf-8") as f:
    json.dump(guarantee_payload, f, indent=2)

print(f"\n✅ Guarantee saved to {guarantee_file}")
