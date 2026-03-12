# Guarantee Versioning Runbook

## Goal

Allow `Core4Mica` to support new guarantee versions without redeploying `Core4Mica`.

This is achieved by:
- Core-level version registry: `configureGuaranteeVersion(...)`
- Optional decoder indirection per version: `IGuaranteeDecoder`
- Router-based decoder dispatch for future versions: `GuaranteeDecoderRouter`

## Architecture

### Core4Mica

`Core4Mica.verifyAndDecodeGuarantee(guarantee, signature)` uses:

1. Envelope decode: `(uint64 version, bytes encodedGuarantee)`
2. Version config lookup: `guaranteeVersions[version]`
3. BLS signature verification over the full envelope bytes
4. Decode path:
   - Version 1: inline decode to `Guarantee` when `decoder == address(0)`
   - Version > 1: delegated decode via `IGuaranteeDecoder.decode(encodedGuarantee)`
5. Domain check: decoded `Guarantee.domain` must equal configured `domainSeparator`

If a version is disabled or missing a required decoder, verification reverts.

### GuaranteeDecoderRouter

`GuaranteeDecoderRouter` is an optional `IGuaranteeDecoder` implementation for versions > 1.

Input to `router.decode(bytes)` must be:
- `abi.encode(uint64 version, bytes payload)`

Router behavior:
- looks up `moduleByVersion[version]`
- calls `IGuaranteeVersionModule(module).decodeModule(payload)`
- requires returned `Guarantee.version == version`

This allows one router deployment to host many future versions (`v3`, `v4`, ...).

### Per-version modules

Each version module implements:
- `decodeModule(bytes payload) -> Guarantee`

The module can decode a richer payload type than the base `Guarantee`, then map it back to `Guarantee`.

## Current versions

- `v1`: inline in `Core4Mica` (no external decoder)
- `v2`: `ValidationRegistryGuaranteeDecoder` (ERC-8004 validation-gated)
- `v3+`: recommended via `GuaranteeDecoderRouter` + per-version modules

## Future version onboarding (no Core4Mica redeploy)

### Step 1: Implement module for the new version

Create a module contract implementing `IGuaranteeVersionModule`:
- define version payload struct
- decode payload
- enforce version-specific invariants
- map to base `Guarantee` and return

### Step 2: Test module behavior in isolation

At minimum test:
- valid payload decode
- malformed payload revert
- each version-specific invariant revert

### Step 3: Wire module into router

Call:
- `setVersionModule(version, module)`
- optionally `freezeVersion(version)` after validation

Use script:
- `script/ConfigureGuaranteeRouter.s.sol:ConfigureGuaranteeRouterScript`

### Step 4: Configure Core4Mica to use router for that version

Call `configureGuaranteeVersion(version, key, domain, decoder, enabled)` with:
- `decoder = <router address>`
- `enabled = true`
- valid BLS public key for this version
- valid domain separator for this version

Use script:
- `script/ConfigureGuaranteeVersion.s.sol:ConfigureGuaranteeVersionScript`

### Step 5: Roll out clients

Ensure issuer/SDK/facilitator components:
- emit the same `version` in envelope
- encode payload in the module-expected layout
- use the matching BLS key/domain for signing and verification

## Operational command examples

### Configure router module

```bash
cd contracts
forge script script/ConfigureGuaranteeRouter.s.sol:ConfigureGuaranteeRouterScript \
  --rpc-url $RPC_URL \
  --broadcast \
  --via-ir \
  -vvvv
```

Required env:
- `DEPLOYER_PRIVATE_KEY`
- `GUARANTEE_ROUTER_ADDRESS`
- `GUARANTEE_VERSION`
- `GUARANTEE_MODULE_ADDRESS`

Optional env:
- `GUARANTEE_FREEZE_VERSION=true|false`

### Configure Core4Mica version

```bash
cd contracts
forge script script/ConfigureGuaranteeVersion.s.sol:ConfigureGuaranteeVersionScript \
  --rpc-url $RPC_URL \
  --broadcast \
  --via-ir \
  -vvvv
```

Required env:
- `DEPLOYER_PRIVATE_KEY`
- `CORE4MICA_ADDRESS`
- `GUARANTEE_VERSION`
- `GUARANTEE_ENABLED`

If `GUARANTEE_REUSE_EXISTING_KEY=false` (default), also provide:
- `VK_X0`, `VK_X1`, `VK_Y0`, `VK_Y1`

Optional env:
- `GUARANTEE_REUSE_EXISTING_KEY`
- `GUARANTEE_DOMAIN_SEPARATOR`
- `GUARANTEE_DECODER`

## Safety checklist before enabling a version

1. Module tests pass.
2. Router points version to intended module.
3. `Core4Mica.getGuaranteeVersionConfig(version)` returns:
   - expected key
   - expected domain
   - expected decoder
   - `enabled=true`
4. SDK/issuer can produce valid payload/signature for that version.
5. Foundry integration tests for `verifyAndDecodeGuarantee` and `remunerate` pass.

## Test matrix in this repo

- `contracts/test/Core4MicaGuaranteeVersions.t.sol`
  - version config lifecycle and guardrails
- `contracts/test/ValidationRegistryGuaranteeDecoder.t.sol`
  - v2 validation-gated decode logic
- `contracts/test/GuaranteeDecoderRouter.t.sol`
  - router dispatch, freeze, mismatch, and Core4Mica integration

Recommended commands:

```bash
cd contracts
forge test --match-path test/Core4MicaGuaranteeVersions.t.sol
forge test --match-path test/ValidationRegistryGuaranteeDecoder.t.sol
forge test --match-path test/GuaranteeDecoderRouter.t.sol
forge test
```
