# Guarantee V2 Activation Runbook

This runbook activates guarantee version `2` with `ValidationRegistryGuaranteeDecoder`.

## Prerequisites

- Foundry installed (`forge`, `cast`)
- Deployer has AccessManager permission to call `configureGuaranteeVersion`
- `CORE4MICA_ADDRESS` points to the deployed core contract
- Trusted ERC-8004 validation registry addresses are finalized

## Environment

```bash
export DEPLOY_RPC_URL=<rpc-url>
export DEPLOYER_PRIVATE_KEY=<private-key>
export CORE4MICA_ADDRESS=<core4mica-address>

# Guarantee version config
export GUARANTEE_VERSION=2
export GUARANTEE_ENABLED=true
export GUARANTEE_REUSE_EXISTING_KEY=true
export GUARANTEE_KEY_SOURCE_VERSION=1

# Domain must be non-zero for enabled versions
export GUARANTEE_DOMAIN_SEPARATOR=$(cast keccak "4MICA_CORE_GUARANTEE_V2" \
  $(cast chain-id --rpc-url "$DEPLOY_RPC_URL") \
  "$CORE4MICA_ADDRESS")

# Trusted validation registry set (choose one style)
export TRUSTED_VALIDATION_REGISTRIES_COUNT=1
export TRUSTED_VALIDATION_REGISTRY_0=<registry-address>
# OR:
# export TRUSTED_VALIDATION_REGISTRY=<registry-address>
```

## Step 1: Deploy Decoder

Dry-run first:

```bash
cd contracts
forge script script/DeployValidationRegistryGuaranteeDecoder.s.sol:DeployValidationRegistryGuaranteeDecoderScript \
  --rpc-url "$DEPLOY_RPC_URL" \
  --via-ir \
  -vvvv
```

Broadcast:

```bash
forge script script/DeployValidationRegistryGuaranteeDecoder.s.sol:DeployValidationRegistryGuaranteeDecoderScript \
  --rpc-url "$DEPLOY_RPC_URL" \
  --broadcast \
  --via-ir \
  -vvvv
```

Capture the printed decoder address:

```bash
export GUARANTEE_DECODER=<decoder-address-from-output>
```

## Step 2: Configure Core4Mica V2

Dry-run first:

```bash
forge script script/ConfigureGuaranteeVersion.s.sol:ConfigureGuaranteeVersionScript \
  --rpc-url "$DEPLOY_RPC_URL" \
  --via-ir \
  -vvvv
```

Broadcast:

```bash
forge script script/ConfigureGuaranteeVersion.s.sol:ConfigureGuaranteeVersionScript \
  --rpc-url "$DEPLOY_RPC_URL" \
  --broadcast \
  --via-ir \
  -vvvv
```

`ConfigureGuaranteeVersionScript` enforces the safety checks for v2 enablement:

- `decoder` is non-zero
- `domainSeparator` is non-zero
- `enabled == true`
- all expected trusted validation registries return `true` in decoder
- `getGuaranteeVersionConfig(2)` readback matches configured values

## Step 3: Explicit Readback

```bash
cast call "$CORE4MICA_ADDRESS" \
  "getGuaranteeVersionConfig(uint64)((bytes32,bytes32,bytes32,bytes32),bytes32,address,bool)" \
  2 \
  --rpc-url "$DEPLOY_RPC_URL"
```

Optional trusted-registry checks:

```bash
cast call "$GUARANTEE_DECODER" "isTrustedValidationRegistry(address)(bool)" \
  "$TRUSTED_VALIDATION_REGISTRY_0" \
  --rpc-url "$DEPLOY_RPC_URL"
```

Expected result: `true`.
