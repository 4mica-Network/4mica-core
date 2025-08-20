#!/bin/bash

# Configuration
RPC_URL="https://holesky.4mica.xyz"
PRIVATE_KEY="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

# Navigate to the script's directory
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)

# Deploy scripts
declare -a SCRIPTS=(
    "ServiceManager4MicaDeployer.s.sol"
    "ContractsRegistry.s.sol --slow"
    "SetupPayments.s.sol --slow"
    "OperatorDirectedPayments.s.sol --slow"
)

for SCRIPT in "${SCRIPTS[@]}"; do
    forge script $SCRIPT --rpc-url "$RPC_URL" --private-key "$PRIVATE_KEY" --broadcast
done