#!/usr/bin/env bash
set -euo pipefail

# ========== Helper Functions ==========
command_exists() {
  command -v "$1" >/dev/null 2>&1
}

# ========== 1. Check Rust ==========
if ! command_exists cargo; then
  echo "Rust not found. Installing..."
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
  source $HOME/.cargo/env
else
  echo "Rust is installed ✅"
fi

# ========== 2. Check Docker ==========
if ! command_exists docker; then
  echo "Docker not found."
else
  echo "Docker is installed ✅"
fi

# ========== 3. Docker Compose Up ==========
echo "Starting Docker services..."
docker compose up -d

# ========== 4. Run Anvil ==========
if ! command_exists anvil; then
  echo "Anvil not found. Installing (via foundryup)..."
  curl -L https://foundry.paradigm.xyz | bash
  source ~/.foundry/bin
  foundryup
else
  echo "Foundry is installed ✅"
fi

echo "Starting Anvil..."
# Kill existing anvil if running
pkill -f anvil || true
anvil --host 0.0.0.0 --port 8545 > anvil.log 2>&1 &

# save PID if you want to stop it later
ANVIL_PID=$!
echo "Anvil started with PID $ANVIL_PID. Logs are being written to anvil.log."
# Start Anvil in background and capture RPC URLs
for i in {1..20}; do
  if curl -s -X POST http://127.0.0.1:8545 \
       -H "Content-Type: application/json" \
       --data '{"jsonrpc":"2.0","method":"web3_clientVersion","params":[],"id":1}' \
       | grep -q "anvil"; then
    echo "Anvil is ready ✅"
    break
  fi
  echo "Waiting for anvil..."
  sleep 1
done
if ! ps -p $ANVIL_PID > /dev/null; then
  echo "Anvil failed to start. Check anvil.log for details."
  exit 1
fi

ETHEREUM_HTTP_RPC_URL="http://127.0.0.1:8545"
ETHEREUM_WS_RPC_URL="ws://127.0.0.1:8545"

# ========== 5. Export Environment Variables ==========
cat > .env <<EOF
DATABASE_URL="postgres://postgres:qwerty123456@localhost:5432/core"
BLS_PRIVATE_KEY="9f3eff11070f29192c5f2dde4d047f99fc7861fd82593d22859d5ca03d9e476b"
ETHEREUM_HTTP_RPC_URL="$ETHEREUM_HTTP_RPC_URL"
ETHEREUM_WS_RPC_URL="$ETHEREUM_WS_RPC_URL"
ETHEREUM_CONTRACT_ADDRESS="0x5FbDB2315678afecb367f032d93F642f64180aa3"
EOF

echo "Environment variables written to core/.env:"
cat core/.env

echo "If you want to deploy contracts with Forge, run the following command:"
echo ""
echo "RPC_URL=\"$ETHEREUM_HTTP_RPC_URL\" forge script contracts/script/Core4Mica.s.sol:Core4MicaScript \\"
echo "  --rpc-url \"\$RPC_URL\" \\"
echo "  --broadcast \\"
echo "  --via-ir \\"
echo "  -vvvv"
echo ""

# ========== 6. Build Project ==========
echo "Building local binary..."
cargo build

echo "✅ Setup complete. You can now run your local binary with:"
echo "cargo run --bin <service-name>"
