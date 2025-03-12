#!/bin/bash
CONTRACT_NAME='AuthorityContract'
RPC_URL='http://127.0.0.1:8545'
PRIVATE_KEY='0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'

# Ensure Foundry is installed
if ! command -v forge &> /dev/null
then
    echo "Foundry (forge) is not installed. Install it with: curl -L https://foundry.paradigm.xyz | bash && foundryup"
    exit 1
fi

# Compile the smart contract
forge clean
forge build
if [ $? -ne 0 ]; then
    echo "Compilation failed."
    exit 1
fi

echo "Compilation successful. Deploying $CONTRACT_NAME..."

# Deploy the contract
DEPLOY_OUTPUT=$(forge create --rpc-url "$RPC_URL" --private-key "$PRIVATE_KEY" "contracts/$CONTRACT_NAME.sol:$CONTRACT_NAME" 2>&1)

if [ $? -ne 0 ]; then
    echo "Deployment failed:"
    echo "$DEPLOY_OUTPUT"
    exit 1
fi

echo "Deployment successful!"
echo "$DEPLOY_OUTPUT"

# Extract contract address
CONTRACT_ADDRESS=$(echo "$DEPLOY_OUTPUT" | grep -op '(?<=Deployed to: )\S+')
echo "Contract Address: $CONTRACT_ADDRESS"

# Save ABI to file
forge inspect "contracts/$CONTRACT_NAME.sol:$CONTRACT_NAME" abi > "contracts/$CONTRACT_NAME.abi"
if [ $? -ne 0 ]; then
    echo "Failed to save ABI."
    exit 1
fi

echo "ABI saved to contracts/$CONTRACT_NAME.abi"
