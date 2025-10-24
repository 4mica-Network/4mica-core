import json
import os
from pathlib import Path
from typing import Dict, Tuple
from eth_typing import HexStr
from eth_utils import to_checksum_address
from web3 import Web3
from web3.types import TxReceipt
from dotenv import load_dotenv

# ---------- Load environment variables ----------
load_dotenv()
RPC_URL = os.getenv("RPC_URL")
CONTRACT_ADDRESS = os.getenv("CONTRACT_ADDRESS")
if not RPC_URL or not CONTRACT_ADDRESS:
    raise EnvironmentError("RPC_URL and CONTRACT_ADDRESS must be set in .env")

# ---------- Configuration ----------
artifact_path = (
    Path(__file__).resolve().parent.parent
    / "contracts"
    / "out"
    / "Core4Mica.sol"
    / "Core4Mica.json"
)
print("artifact_path:", artifact_path)

# ---------- Load ABI ----------
with open(artifact_path, "r", encoding="utf-8") as f:
    artifact = json.load(f)
ABI = artifact["abi"]

# ---------- Web3 provider ----------
w3 = Web3(Web3.HTTPProvider(RPC_URL))
if not w3.is_connected():
    raise ConnectionError(f"Cannot connect to RPC at {RPC_URL}")

# Contract instance
Core4Mica = w3.eth.contract(
    address=Web3.to_checksum_address(CONTRACT_ADDRESS),
    abi=ABI
)

# Optional: quick read
collateral, ts, amt = Core4Mica.functions.getUser(
    "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
).call()
print("collateral:", collateral)
print("withdrawal_request_timestamp:", ts)
print("withdrawal_request_amount:", amt)

# ---------- Helpers ----------
def _send_tx(acct, tx):
    signed = acct.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    receipt: TxReceipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    return receipt

def _build_base_tx(acct) -> dict:
    latest_block = w3.eth.get_block("latest")
    base_fee = latest_block.baseFeePerGas
    priority_fee = w3.to_wei("2", "gwei")
    return {
        "from": acct.address,
        "nonce": w3.eth.get_transaction_count(acct.address),
        "gas": 300_000,
        "maxPriorityFeePerGas": priority_fee,
        "maxFeePerGas": base_fee + priority_fee,
    }

# ---------- User-flow wrappers ----------
def deposit(private_key: str, amount_eth: float) -> TxReceipt:
    acct = w3.eth.account.from_key(private_key)
    base_tx = _build_base_tx(acct)
    base_tx["value"] = w3.to_wei(amount_eth, "ether")
    tx = Core4Mica.functions.deposit().build_transaction(base_tx)
    return _send_tx(acct, tx)

def request_withdrawal(private_key: str, amount_eth: float) -> TxReceipt:
    acct = w3.eth.account.from_key(private_key)
    base_tx = _build_base_tx(acct)
    tx = Core4Mica.functions.requestWithdrawal(
        w3.to_wei(amount_eth, "ether")
    ).build_transaction(base_tx)
    return _send_tx(acct, tx)

def cancel_withdrawal(private_key: str) -> TxReceipt:
    acct = w3.eth.account.from_key(private_key)
    base_tx = _build_base_tx(acct)
    tx = Core4Mica.functions.cancelWithdrawal().build_transaction(base_tx)
    return _send_tx(acct, tx)

def finalize_withdrawal(private_key: str) -> TxReceipt:
    acct = w3.eth.account.from_key(private_key)
    base_tx = _build_base_tx(acct)
    tx = Core4Mica.functions.finalizeWithdrawal().build_transaction(base_tx)
    return _send_tx(acct, tx)

def remunerate(
    private_key: str,
    guarantee: Dict,
    # already-prepared 8×bytes32; decompression/splitting is done in remuneration.py
    signature: Tuple[HexStr, HexStr, HexStr, HexStr, HexStr, HexStr, HexStr, HexStr]
) -> TxReceipt:
    acct = w3.eth.account.from_key(private_key)
    base_tx = _build_base_tx(acct)

    # Map your JSON schema -> ABI struct
    # (uint256 tab_id, uint256 tab_timestamp, address client, address recipient, uint256 req_id, uint256 amount)
    g_tuple = (
        int(guarantee["tab_id"], 16),
        int(guarantee["timestamp"]),
        to_checksum_address(guarantee["user_address"]),
        to_checksum_address(guarantee["recipient_address"]),
        int(guarantee["req_id"], 16),
        int(guarantee["amount"]),
    )

    # signature is already flat (bytes32 x 8)
    sig_tuple = signature
    if len(sig_tuple) != 8:
        raise ValueError("Signature must be a tuple of 8 bytes32 values")

    tx = Core4Mica.functions.remunerate(g_tuple, sig_tuple).build_transaction(base_tx)
    return _send_tx(acct, tx)

def record_payment(
    private_key: str,
    tab_id: int,
    amount_wei: int,
    asset: str = "0x0000000000000000000000000000000000000000",
) -> TxReceipt:
    acct = w3.eth.account.from_key(private_key)
    base_tx = _build_base_tx(acct)
    tx = Core4Mica.functions.recordPayment(
        tab_id,
        to_checksum_address(asset),
        amount_wei
    ).build_transaction(base_tx)
    return _send_tx(acct, tx)
