#!/usr/bin/env python3
import os, time, json
from dotenv import load_dotenv
from web3 import Web3
from pathlib import Path

# --------------------------------------------------------------------
# 1. Load environment & connect to chain
# --------------------------------------------------------------------
load_dotenv()
PRIVATE_KEY       = os.getenv("PRIVATE_KEY")        # admin/deployer key
RPC_URL           = os.getenv("RPC_URL")
CONTRACT_ADDRESS  = os.getenv("CONTRACT_ADDRESS")

if not all([PRIVATE_KEY, RPC_URL, CONTRACT_ADDRESS]):
    raise EnvironmentError("PRIVATE_KEY, RPC_URL, CONTRACT_ADDRESS must be set in .env")

w3 = Web3(Web3.HTTPProvider(RPC_URL))
if not w3.is_connected():
    raise ConnectionError(f"Cannot connect to RPC at {RPC_URL}")

acct = w3.eth.account.from_key(PRIVATE_KEY)
print(f"Using admin account: {acct.address}")

# --------------------------------------------------------------------
# 2. Load ABI
# --------------------------------------------------------------------
artifact_path = (
    Path(__file__).resolve().parent.parent
    / "contracts" / "out" / "Core4Mica.sol" / "Core4Mica.json"
)
with open(artifact_path, "r", encoding="utf-8") as f:
    artifact = json.load(f)
ABI = artifact["abi"]

core4mica = w3.eth.contract(address=w3.to_checksum_address(CONTRACT_ADDRESS), abi=ABI)

# --------------------------------------------------------------------
# 3. Helper: build & send a tx
# --------------------------------------------------------------------
def send_tx(tx):
    signed = acct.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    print(f"✓ {tx['to']} {tx['data'][:10]}…  tx: {tx_hash.hex()}  status: {receipt.status}")
    return receipt

def build_base_tx():
    latest = w3.eth.get_block("latest")
    base_fee = latest.baseFeePerGas
    prio_fee = w3.to_wei("2", "gwei")
    return {
        "from": acct.address,
        "nonce": w3.eth.get_transaction_count(acct.address),
        "gas": 300_000,
        "maxPriorityFeePerGas": prio_fee,
        "maxFeePerGas": base_fee + prio_fee,
    }

# --------------------------------------------------------------------
# 4. Set all periods to 1 second
# --------------------------------------------------------------------
for fn in [
    core4mica.functions.setRemunerationGracePeriod,
    core4mica.functions.setTabExpirationTime,
    core4mica.functions.setWithdrawalGracePeriod,
    core4mica.functions.setSynchronizationDelay,
]:
    tx = fn(1).build_transaction(build_base_tx())
    send_tx(tx)

# --------------------------------------------------------------------
# 5. (Optional) Fast-forward local chain time by 5 s (Anvil/Ganache only)
# --------------------------------------------------------------------
try:
    w3.provider.make_request("evm_increaseTime", [5])
    w3.provider.make_request("evm_mine", [])
    print("✓ Chain time advanced by 5 seconds")
except Exception as e:
    print("⧗ Could not fast-forward time (non-dev RPC?)", e)

# --------------------------------------------------------------------
# 6. Display new values for confirmation
# --------------------------------------------------------------------
print("\n--- Updated Core4Mica timing parameters ---")
print("remunerationGracePeriod :", core4mica.functions.remunerationGracePeriod().call())
print("tabExpirationTime       :", core4mica.functions.tabExpirationTime().call())
print("withdrawalGracePeriod   :", core4mica.functions.withdrawalGracePeriod().call())
print("synchronizationDelay    :", core4mica.functions.synchronizationDelay().call())
print("-------------------------------------------")
