#!/usr/bin/env python3
import os
import sys
import json
from typing import Tuple

from dotenv import load_dotenv
from web3 import Web3
from eth_account import Account
from py_ecc.bls import G2Basic as bls
from py_ecc.bls.point_compression import decompress_G1, decompress_G2


# ============================== helpers ==============================

def fq_to_48_be(n: int) -> bytes:
    b = int(n).to_bytes(48, "big")
    if len(b) != 48:
        raise ValueError("Fp did not encode to 48 bytes")
    return b

def split48_to_fp_words(b48: bytes) -> Tuple[bytes, bytes]:
    """Split 48-byte field element into Solady Fp words {a,b}."""
    hi16, lo32 = b48[:16], b48[16:]
    return (hi16.rjust(32, b"\x00"), lo32)

def fq2_to_fp2_words(fq2) -> Tuple[bytes, bytes, bytes, bytes]:
    c0, c1 = fq2.coeffs
    c0_a, c0_b = split48_to_fp_words(fq_to_48_be(int(c0)))
    c1_a, c1_b = split48_to_fp_words(fq_to_48_be(int(c1)))
    return c0_a, c0_b, c1_a, c1_b

def to_hex32(b: bytes) -> str:
    return "0x" + b.hex()

def pack_encode_guarantee(domain: bytes, tab_id: int, req_id: int, client: str, recipient: str,
                          amount: int, tab_timestamp: int) -> bytes:
    """Mirror Solidity: abi.encodePacked(domain, uint256,uint256,address,address,uint256,uint256)."""
    def u256(x): return x.to_bytes(32, "big")
    def addr(a): return bytes.fromhex(Web3.to_checksum_address(a)[2:])
    return b"".join([
        domain,
        u256(tab_id),
        u256(req_id),
        addr(client),
        addr(recipient),
        u256(amount),
        tab_timestamp.to_bytes(32, "big"),
    ])

def pubkey_g1_words_from_bls_sk(sk_hex: str):
    sk_int = int(sk_hex, 16)
    pk_comp = bls.SkToPk(sk_int)  # 48-byte compressed G1 pubkey
    z = int.from_bytes(pk_comp, "big")
    x_aff, y_aff, _ = decompress_G1(z)
    x_a, x_b = split48_to_fp_words(fq_to_48_be(int(x_aff)))
    y_a, y_b = split48_to_fp_words(fq_to_48_be(int(y_aff)))
    return {
        "x_a": to_hex32(x_a), "x_b": to_hex32(x_b),
        "y_a": to_hex32(y_a), "y_b": to_hex32(y_b),
    }, pk_comp

def to_checksum(addr: str) -> str:
    return Web3.to_checksum_address(addr)


# ============================== main ==============================

def main(guarantee_path: str = "guarantee.json", set_key_first: bool = True):
    load_dotenv()

    RPC_URL         = os.getenv("RPC_URL")
    CONTRACT_ADDR   = os.getenv("CONTRACT_ADDRESS")
    PRIVATE_KEY     = os.getenv("PRIVATE_KEY")
    BLS_PRIVATE_KEY = os.getenv("BLS_PRIVATE_KEY")

    if not RPC_URL or not CONTRACT_ADDR or not PRIVATE_KEY or not BLS_PRIVATE_KEY:
        raise EnvironmentError("Missing one of: RPC_URL, CONTRACT_ADDRESS, PRIVATE_KEY, BLS_PRIVATE_KEY")

    w3 = Web3(Web3.HTTPProvider(RPC_URL))
    acct = Account.from_key(PRIVATE_KEY)
    CONTRACT_ADDR = to_checksum(CONTRACT_ADDR)

    ABI = [
      { # remunerate
        "inputs":[
          {"components":[
            {"name":"tab_id","type":"uint256"},
            {"name":"tab_timestamp","type":"uint256"},
            {"name":"client","type":"address"},
            {"name":"recipient","type":"address"},
            {"name":"req_id","type":"uint256"},
            {"name":"amount","type":"uint256"}
          ],"name":"g","type":"tuple"},
          {"components":[
            {"name":"x_c0_a","type":"bytes32"},
            {"name":"x_c0_b","type":"bytes32"},
            {"name":"x_c1_a","type":"bytes32"},
            {"name":"x_c1_b","type":"bytes32"},
            {"name":"y_c0_a","type":"bytes32"},
            {"name":"y_c0_b","type":"bytes32"},
            {"name":"y_c1_a","type":"bytes32"},
            {"name":"y_c1_b","type":"bytes32"}
          ],"name":"signature","type":"tuple"}
        ],
        "name":"remunerate","outputs":[],
        "stateMutability":"nonpayable","type":"function"
      },
      { # setGuaranteeVerificationKey
        "inputs":[{"components":[
            {"name":"x_a","type":"bytes32"},
            {"name":"x_b","type":"bytes32"},
            {"name":"y_a","type":"bytes32"},
            {"name":"y_b","type":"bytes32"}
          ],"name":"verificationKey","type":"tuple"}],
        "name":"setGuaranteeVerificationKey","outputs":[],
        "stateMutability":"nonpayable","type":"function"
      },
      { "inputs": [], "name": "GUARANTEE_VERIFICATION_KEY",
        "outputs":[
          {"name":"x_a","type":"bytes32"},
          {"name":"x_b","type":"bytes32"},
          {"name":"y_a","type":"bytes32"},
          {"name":"y_b","type":"bytes32"}
        ],
        "stateMutability":"view","type":"function"
      },
      { "inputs":[{"name":"userAddr","type":"address"}],
        "name":"getUser","outputs":[
          {"name":"_collateral","type":"uint256"},
          {"name":"withdrawal_request_timestamp","type":"uint256"},
          {"name":"withdrawal_request_amount","type":"uint256"}
        ],"stateMutability":"view","type":"function"
      },
      { "inputs":[{"name":"tab_id","type":"uint256"}],
        "name":"getPaymentStatus","outputs":[
          {"name":"paid","type":"uint256"},
          {"name":"remunerated","type":"bool"}
        ],"stateMutability":"view","type":"function"
      },
      { "inputs": [], "name": "remunerationGracePeriod",
        "outputs":[{"type":"uint256"}],"stateMutability":"view","type":"function" },
      { "inputs": [], "name": "tabExpirationTime",
        "outputs":[{"type":"uint256"}],"stateMutability":"view","type":"function" },
      { "inputs":[{"components":[
            {"name":"tab_id","type":"uint256"},
            {"name":"tab_timestamp","type":"uint256"},
            {"name":"client","type":"address"},
            {"name":"recipient","type":"address"},
            {"name":"req_id","type":"uint256"},
            {"name":"amount","type":"uint256"}
        ],"name":"g","type":"tuple"}],
        "name":"encodeGuarantee","outputs":[{"type":"bytes"}],
        "stateMutability":"pure","type":"function"
      }
    ]

    core = w3.eth.contract(address=CONTRACT_ADDR, abi=ABI)
    chain_id = w3.eth.chain_id
    domain = Web3.solidity_keccak(
        ["string", "uint256", "address"],
        ["4MICA_CORE_GUARANTEE_V1", chain_id, CONTRACT_ADDR],
    )

    # ---- load guarantee.json ----
    with open(guarantee_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    claims = data["claims"]
    sig_hex = data["bls_signature"]
    sig_bytes = bytes.fromhex(sig_hex)
    if len(sig_bytes) != 96:
        raise ValueError("bls_signature must be 96 bytes")

    g = {
        "tab_id": int(claims["tab_id"], 16),
        "req_id": int(claims["req_id"]),
        "client": to_checksum(claims["user_address"]),
        "recipient": to_checksum(claims["recipient_address"]),
        "amount": int(claims["amount"]),
        "tab_timestamp": int(data["tab_timestamp"]),
    }

    # ---- print balances BEFORE ----
    print("\n=== BEFORE REMUNERATION ===")
    user_collateral, _, _ = core.functions.getUser(g["client"]).call()
    print(f"User (client):    {g['client']}")
    print(f"  Collateral in contract : {w3.from_wei(user_collateral, 'ether')} ETH")
    rec_bal_before = w3.eth.get_balance(g["recipient"])
    print(f"Recipient address: {g['recipient']}")
    print(f"  ETH balance             : {w3.from_wei(rec_bal_before, 'ether')} ETH")

    # ---- rebuild message & verify off-chain ----
    msg_bytes_off = pack_encode_guarantee(
        domain,
        g["tab_id"],
        g["req_id"],
        g["client"],
        g["recipient"],
        g["amount"],
        g["tab_timestamp"],
    )
    print(f"\nPacked off-chain length: {len(msg_bytes_off)} bytes (expect 200)")
    print("Off-chain last 32 bytes:", msg_bytes_off.hex()[-64:])

    pk48 = bls.SkToPk(int(BLS_PRIVATE_KEY, 16))
    sig_ok = bls.Verify(pk48, msg_bytes_off, sig_bytes)
    print(f"Off-chain BLS.Verify (py_ecc): {'✅ VALID' if sig_ok else '❌ INVALID'}")

    msg_bytes_on = core.functions.encodeGuarantee((
        g["tab_id"], g["tab_timestamp"], g["client"], g["recipient"], g["req_id"], g["amount"]
    )).call()
    print(f"Packed on-chain   length: {len(msg_bytes_on)} bytes (expect 200)")
    print("On-chain  last 32 bytes:", msg_bytes_on.hex()[-64:])

    if msg_bytes_on.hex() != msg_bytes_off.hex():
        print("encodeGuarantee() bytes: ❌ MISMATCH")
        print("off-chain:", msg_bytes_off.hex())
        print("on-chain :", msg_bytes_on.hex())
        diff_i = next((i for i,(a,b) in enumerate(zip(msg_bytes_off.hex(),
                                                     msg_bytes_on.hex())) if a!=b), None)
        print("DIFF AT  :", diff_i if diff_i is not None else 'n/a')
        print("Aborting to prevent a guaranteed revert.")
        return
    print("encodeGuarantee() bytes: ✅ match off-chain packed bytes")

    on_vk = core.functions.GUARANTEE_VERIFICATION_KEY().call()
    derived_vk_limbs, _ = pubkey_g1_words_from_bls_sk(BLS_PRIVATE_KEY)
    on_vk_hex = {k: Web3.to_hex(v) for k, v in zip(["x_a","x_b","y_a","y_b"], on_vk)}
    vk_matches = (on_vk_hex == derived_vk_limbs)
    print(f"On-chain verification key matches derived key: {'✅ YES' if vk_matches else '❌ NO'}")
    if not vk_matches:
        print("Derived (expected) VK:", json.dumps(derived_vk_limbs, indent=2))
        print("On-chain (actual) VK :", json.dumps(on_vk_hex, indent=2))
        if not set_key_first:
            print("Tip: run again with set_key_first=True to update the VK before remunerating.")
            return

    rem_gp = core.functions.remunerationGracePeriod().call()
    tab_exp = core.functions.tabExpirationTime().call()
    now = w3.eth.get_block("latest")["timestamp"]
    not_yet_overdue = now < g["tab_timestamp"] + rem_gp
    expired          = g["tab_timestamp"] + tab_exp < now
    if not_yet_overdue or expired:
        print("Time window check: ❌")
        print(f" now={now}, tab={g['tab_timestamp']}, grace={rem_gp}, expire={tab_exp}")
        if not_yet_overdue: print(" -> Would revert: TabNotYetOverdue()")
        if expired:         print(" -> Would revert: TabExpired()")
        return
    print("Time window check: ✅")

    paid, remunerated = core.functions.getPaymentStatus(g["tab_id"]).call()
    if remunerated:
        print("Payment status: ❌ already remunerated -> would revert TabPreviouslyRemunerated()")
        return
    if paid >= g["amount"]:
        print("Payment status: ❌ already paid >= amount -> would revert TabAlreadyPaid()")
        return
    print("Payment status: ✅ OK")

    if user_collateral < g["amount"]:
        print(f"Collateral check: ❌ {user_collateral} < {g['amount']} -> would revert DoubleSpendingDetected()")
        return
    print("Collateral check: ✅ OK")

    z1 = int.from_bytes(sig_bytes[:48], "big")
    z2 = int.from_bytes(sig_bytes[48:], "big")
    x_aff, y_aff, _ = decompress_G2((z1, z2))
    x_c0_a, x_c0_b, x_c1_a, x_c1_b = fq2_to_fp2_words(x_aff)
    y_c0_a, y_c0_b, y_c1_a, y_c1_b = fq2_to_fp2_words(y_aff)

    sig_for_solady = (
        to_hex32(x_c0_a), to_hex32(x_c0_b),
        to_hex32(x_c1_a), to_hex32(x_c1_b),
        to_hex32(y_c0_a), to_hex32(y_c0_b),
        to_hex32(y_c1_a), to_hex32(y_c1_b),
    )

    g_tuple = (
        g["tab_id"], g["tab_timestamp"], g["client"], g["recipient"],
        g["req_id"], g["amount"]
    )

    nonce = w3.eth.get_transaction_count(acct.address)
    if set_key_first and not vk_matches:
        tx1 = core.functions.setGuaranteeVerificationKey((
            derived_vk_limbs["x_a"],
            derived_vk_limbs["x_b"],
            derived_vk_limbs["y_a"],
            derived_vk_limbs["y_b"],
        )).build_transaction({
            "from": acct.address,
            "nonce": nonce,
            "gas": 200_000,
            "gasPrice": w3.eth.gas_price,
        })
        signed1 = acct.sign_transaction(tx1)
        w3.eth.send_raw_transaction(signed1.raw_transaction)
        w3.eth.wait_for_transaction_receipt(signed1.hash)
        print(" ✅ VK set on-chain")
        nonce += 1

    if not sig_ok:
        print("Final sanity: ❌ Off-chain signature verification failed; aborting to avoid revert.")
        return

    print("\nCalling remunerate …")
    tx2 = core.functions.remunerate(g_tuple, sig_for_solady).build_transaction({
        "from": acct.address,
        "nonce": nonce,
        "gas": 450_000,
        "gasPrice": w3.eth.gas_price,
    })
    signed2 = acct.sign_transaction(tx2)
    w3.eth.send_raw_transaction(signed2.raw_transaction)
    w3.eth.wait_for_transaction_receipt(signed2.hash)
    print(" ✅ remunerate confirmed")

    # ---- print balances AFTER ----
    print("\n=== AFTER REMUNERATION ===")
    user_collateral_after, _, _ = core.functions.getUser(g["client"]).call()
    print(f"User (client):    {g['client']}")
    print(f"  Collateral in contract : {w3.from_wei(user_collateral_after, 'ether')} ETH")
    rec_bal_after = w3.eth.get_balance(g["recipient"])
    print(f"Recipient address: {g['recipient']}")
    print(f"  ETH balance             : {w3.from_wei(rec_bal_after, 'ether')} ETH")
    print("=======================================================")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "guarantee.json")
