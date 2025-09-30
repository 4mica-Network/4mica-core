import time
import os
from dotenv import load_dotenv  
from core_4mica_client import w3, Core4Mica, deposit 

# =========================================================
#  Configuration
# =========================================================
# Load variables from .env into environment
load_dotenv()

PRIVATE_KEY = os.getenv("PRIVATE_KEY")  # <-- read from .env
if not PRIVATE_KEY:
    raise EnvironmentError("PRIVATE_KEY is not set in .env")

acct = w3.eth.account.from_key(PRIVATE_KEY)
USER_ADDR = acct.address

# =========================================================
#  Helper functions
# =========================================================
def eth_balance(addr):
    """Return native ETH balance of an address as decimal ETH."""
    return w3.from_wei(w3.eth.get_balance(addr), "ether")


def log_receipt(action: str, receipt):
    """Pretty-print key information from a transaction receipt."""
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

# 1️⃣ Deposit 0.2 ETH into Core4Mica
print("➡️  Sending deposit transaction (0.2 ETH)…")
start = time.time()
receipt = deposit(PRIVATE_KEY, 0.2)
log_receipt("Deposit", receipt)
print(f"Elapsed time       : {time.time() - start:.1f} s")
print(f"Wallet ETH balance : {eth_balance(USER_ADDR)} ETH (after gas costs)\n")

# 2️⃣ Query on-chain user data from Core4Mica
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
