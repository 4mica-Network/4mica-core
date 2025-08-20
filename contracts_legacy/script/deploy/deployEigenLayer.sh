#!/bin/bash

# Exit immediately on error, unset variables, or pipe failures
set -euo pipefail

# Function to handle unexpected errors
handle_error() {
    echo "❌ Error occurred in script at line $1."
    exit 1
}
trap 'handle_error $LINENO' ERR

# Config
RPC_URL="https://holesky.4mica.xyz"
PRIVATE_KEY="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

# Ensure required tools are installed
command -v forge >/dev/null 2>&1 || { echo >&2 "🔧 forge is not installed. Aborting."; exit 1; }

# Navigate to the script directory
echo "📁 Navigating to script directory..."
parent_path=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
cd "$parent_path"

root_dir=$(realpath "$parent_path/../../..")
echo "📦 Root directory resolved to: $root_dir"

# Deploy ContractsRegistry
echo "🚀 Deploying ContractsRegistry..."
cd "$root_dir/contracts"
forge create src/ContractsRegistry.sol:ContractsRegistry \
    --rpc-url "$RPC_URL" \
    --private-key "$PRIVATE_KEY" \
    --broadcast

# Run DeployEigenLayerCore script
echo "🛠 Running DeployEigenLayerCore script..."
forge script script/deploy/DeployEigenLayerCore.s.sol:DeployEigenlayerCore \
    --rpc-url "$RPC_URL" \
    --broadcast \
    --slow

echo "✅ Deployment complete!"
