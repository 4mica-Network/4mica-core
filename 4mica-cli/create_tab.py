#!/usr/bin/env python3
"""
create_tab.py
-------------
Call the Core JSON-RPC API to create a new payment tab.
Reads all required addresses from .env.
"""

import os
import sys
import json
import requests
from dotenv import load_dotenv

# =========================================================
#  Load environment variables
# =========================================================
load_dotenv()

OPERATOR_URL     = os.getenv("OPERATOR_URL")
USER_ADDRESS     = os.getenv("USER_ADDRESS")
RECIPIENT_ADDRESS = os.getenv("RECIPIENT_ADDRESS")

if not OPERATOR_URL:
    sys.exit("❌ OPERATOR_URL not set in .env")
if not USER_ADDRESS or not RECIPIENT_ADDRESS:
    sys.exit("❌ USER_ADDRESS and/or RECIPIENT_ADDRESS missing in .env")

# =========================================================
#  Helper: generic JSON-RPC request
# =========================================================
def rpc_call(method: str, params: dict | list = None):
    """Send a JSON-RPC call and return the result field."""
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": f"core_{method}",
        "params": [params] if params is not None else [],
    }
    resp = requests.post(OPERATOR_URL, json=payload, timeout=20)
    resp.raise_for_status()
    data = resp.json()
    if "error" in data:
        raise RuntimeError(f"RPC error: {data['error']}")
    return data["result"]

# =========================================================
#  1️⃣ Inspect the public parameters (optional)
# =========================================================
print("➡️  Fetching Core public parameters …")
public_params = rpc_call("getPublicParams")
print(json.dumps(public_params, indent=2))

# =========================================================
#  2️⃣ Create a new payment tab
# =========================================================
# Adjust fields to match your backend's CreatePaymentTabRequest
create_req = {
    "user_address": USER_ADDRESS,
    "recipient_address": RECIPIENT_ADDRESS,
    "amount": 200_000_000_000_000_000,  # 0.2 ETH in wei
    "metadata": "optional note or description"
}

print("\n➡️  Creating payment tab …")
tab_result = rpc_call("createPaymentTab", create_req)

print("\n==== Payment tab created ====")
print(json.dumps(tab_result, indent=2))
print("================================")
