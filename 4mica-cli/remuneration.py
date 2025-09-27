#!/usr/bin/env python3
import json
import os
import time
from typing import Dict, Tuple

from dotenv import load_dotenv
from eth_utils import to_checksum_address
from web3 import Web3
from web3.types import TxReceipt
from py_ecc.bls.point_compression import decompress_G2

# -------------------------------------------------------------------
# wire up client
# -------------------------------------------------------------------
from core_4mica_client import w3, Core4Mica   # your generated web3 client

load_dotenv()
PRIVATE_KEY       = os.getenv("PRIVATE_KEY")
RECIPIENT_ADDRESS = os.getenv("RECIPIENT_ADDRESS")
if not PRIVATE_KEY or not RECIPIENT_ADDRESS:
    raise EnvironmentError("PRIVATE_KEY and RECIPIENT_ADDRESS must be set in .env")

acct = w3.eth.account.from_key(PRIVATE_KEY)
USER_ADDR = acct.address
RECIPIENT_ADDRESS = to_checksum_address(RECIPIENT_ADDRESS)

# -------------------------------------------------------------------
# helpers
# -------------------------------------------------------------------
def eth_balance(addr) -> float:
    return w3.from_wei(w3.eth.get_balance(addr), "ether")

def user_collateral(addr) -> float:
    col, _, _ = Core4Mica.functions.getUser(addr).call()
    return w3.from_wei(col, "ether")

def print_info(title: str):
    print(f"\n==== {title} ====")
    print(f"User address             : {USER_ADDR}")
    print(f"User ETH balance         : {eth_balance(USER_ADDR)} ETH")
    print(f"User Core4Mica collateral: {user_collateral(USER_ADDR)} ETH")
    print(f"Recipient address        : {RECIPIENT_ADDRESS}")
    print(f"Recipient ETH balance    : {eth_balance(RECIPIENT_ADDRESS)} ETH")
    print("=========================================")

def _base_tx() -> dict:
    latest = w3.eth.get_block("latest")
    base_fee = getattr(latest, "baseFeePerGas", w3.to_wei("1", "gwei"))
    prio = w3.to_wei("2", "gwei")
    return {
        "from": acct.address,
        "nonce": w3.eth.get_transaction_count(acct.address),
        "gas": 500_000,
        "maxPriorityFeePerGas": prio,
        "maxFeePerGas": base_fee + prio,
    }

def _send_tx(tx) -> TxReceipt:
    signed = acct.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    return w3.eth.wait_for_transaction_receipt(tx_hash)

def _as_u256(v) -> int:
    if isinstance(v, int):
        return v
    s = str(v)
    return int(s, 16) if s.lower().startswith("0x") else int(s)

# -------------------------------------------------------------------
# BLS limb helpers
# -------------------------------------------------------------------
def _fq_to_two_bytes32(v: int) -> Tuple[str, str]:
    """
    Convert a 48-byte BLS12-381 Fp element (as int) into two bytes32 words
    (hi, lo) exactly like Solady/Ithaca BLS.G2Point expects.
    """
    b = v.to_bytes(48, "big")
    hi = Web3.to_hex(b[:16].rjust(32, b"\x00"))  # top 16 bytes left-padded to 32
    lo = Web3.to_hex(b[16:].rjust(32, b"\x00"))  # bottom 32 bytes
    return hi, lo

def decompress_sig_to_limbs(sig_hex: str) -> Tuple[str, ...]:
    """
    Decompress a 96-byte compressed G2 signature into the 8×bytes32 limb
    ordering Solidity expects for BLS.G2Point:
      (x.c1_hi, x.c1_lo, x.c0_hi, x.c0_lo,
       y.c1_hi, y.c1_lo, y.c0_hi, y.c0_lo)
    """
    b = bytes.fromhex(sig_hex.removeprefix("0x"))
    if len(b) != 96:
        raise ValueError("BLS signature must be exactly 96 bytes (G2 compressed)")
    z1, z2 = int.from_bytes(b[:48], "big"), int.from_bytes(b[48:], "big")
    x, y, _ = decompress_G2((z1, z2))  # Fp2 elements

    return (
        *_fq_to_two_bytes32(x.coeffs[1]),  # x.c1
        *_fq_to_two_bytes32(x.coeffs[0]),  # x.c0
        *_fq_to_two_bytes32(y.coeffs[1]),  # y.c1
        *_fq_to_two_bytes32(y.coeffs[0]),  # y.c0
    )

# -------------------------------------------------------------------
# load guarantee.json
# -------------------------------------------------------------------
with open("guarantee.json", "r", encoding="utf-8") as f:
    data = json.load(f)

claims: Dict = data["claims"]
sig_hex: str = data["bls_signature"]

TAB_ID  = _as_u256(claims["tab_id"])
TAB_TS  = _as_u256(claims["timestamp"])
REQ_ID  = _as_u256(claims["req_id"])
AMOUNT  = _as_u256(claims["amount"])
CLIENT  = to_checksum_address(claims["user_address"])
RECIP   = to_checksum_address(claims["recipient_address"])

if TAB_TS > 10**12:
    print(f"⚠️  tab_timestamp looks very large ({TAB_TS}); check units")

# -------------------------------------------------------------------
# build the Guarantee tuple IN ABI ORDER
# -------------------------------------------------------------------
abi = Core4Mica.abi
rem = next(i for i in abi if i.get("type") == "function" and i.get("name") == "remunerate")
guarantee_components = rem["inputs"][0]["components"]

name_to_value = {
    "tab_id": TAB_ID,
    "tab_timestamp": TAB_TS,
    "client": CLIENT,
    "recipient": RECIP,
    "req_id": REQ_ID,
    "amount": AMOUNT,
}
order = [c["name"] for c in guarantee_components]
g_tuple = tuple(name_to_value[n] for n in order)

print("[ABI component order for Guarantee]:", order)
print("[value we will send as 'tab_timestamp']:", g_tuple[order.index("tab_timestamp")])

# -------------------------------------------------------------------
# diagnostics
# -------------------------------------------------------------------
print_info("Balances BEFORE remuneration")

now = int(time.time())
chain_now = w3.eth.get_block("latest").timestamp
rgp = Core4Mica.functions.remunerationGracePeriod().call()
print("\n---- Timing diagnostics ----")
print("tab_timestamp            :", TAB_TS)
print("now (wall-clock)         :", now,       f"(Δ={now - TAB_TS})")
print("latest block timestamp   :", chain_now, f"(Δ={chain_now - TAB_TS})")
print("remunerationGracePeriod  :", rgp)
print("tabExpirationTime        :", Core4Mica.functions.tabExpirationTime().call())
print("withdrawalGracePeriod    :", Core4Mica.functions.withdrawalGracePeriod().call())
print("synchronizationDelay     :", Core4Mica.functions.synchronizationDelay().call())
print("----------------------------")
threshold = TAB_TS + rgp
print(f"threshold (ts + gp)      : {threshold} (chain_now - threshold = {chain_now - threshold})")

# -------------------------------------------------------------------
# build signature argument: flat 8×bytes32 for BLS.G2Point
# -------------------------------------------------------------------
sig_arg = decompress_sig_to_limbs(sig_hex)

print("\n[signature limb order sent to contract]:")
for i, limb in enumerate(sig_arg):
    print(f"  {i}: {limb}")

# -------------------------------------------------------------------
# simulate and send the transaction
# -------------------------------------------------------------------
try:
    Core4Mica.functions.remunerate(g_tuple, sig_arg).call({"from": USER_ADDR})
    print("✅ Simulation passed; sending transaction…")
except Exception as e:
    raise SystemExit(f"❌ Simulation reverted: {e}")

receipt = _send_tx(
    Core4Mica.functions.remunerate(g_tuple, sig_arg).build_transaction(_base_tx())
)

print("\n==== Remunerate confirmed ====")
print("Tx hash :", receipt.transactionHash.hex())
print("Status  :", receipt.status)
mined_block = w3.eth.get_block(receipt.blockNumber)
print("\n---- Mined block ----")
print("blockNumber :", receipt.blockNumber)
print("timestamp   :", mined_block.timestamp)
print("---------------------")

print_info("Balances AFTER remuneration")

paid, remunerated = Core4Mica.functions.getPaymentStatus(TAB_ID).call()
print("\n---- Payment status for tab ----")
print("tab_id      :", TAB_ID)
print("paid        :", w3.from_wei(paid, 'ether'), "ETH")
print("remunerated :", remunerated)
print("---------------------------------")
