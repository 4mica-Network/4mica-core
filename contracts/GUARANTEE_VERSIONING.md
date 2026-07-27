# Guarantee Versioning Runbook

## Goal

Allow `Core4Mica` to support new guarantee claim layouts without redeploying `Core4Mica`.

This is achieved by:

- Core-level version registry: `configureGuaranteeVersion(...)`
- Optional decoder indirection per version: `IGuaranteeDecoder`

A version is a **claims layout**, nothing more. Optional features that do not change the
on-chain bytes — such as [validated guarantees](../README.md#validated-guarantees), which are
enforced off-chain — are not versions and must not consume one.

## Architecture

`Core4Mica.verifyAndDecodeGuarantee(guarantee, signature)` uses:

1. Envelope decode: `(uint64 version, bytes encodedGuarantee)`
2. Version config lookup: `guaranteeVersions[version]`
3. BLS signature verification over the full envelope bytes
4. Decode path:
   - Version 1: inline decode to `Guarantee` when `decoder == address(0)`
   - Version > 1: delegated decode via `IGuaranteeDecoder.decode(encodedGuarantee)`
5. Domain check: decoded `Guarantee.domain` must equal configured `domainSeparator`

If a version is disabled or missing a required decoder, verification reverts.

## Current versions

- `v1`: inline in `Core4Mica` (no external decoder)

`v1` is the only version. Core accepts every version listed in the Rust crate's
`SUPPORTED_GUARANTEE_VERSIONS`, and clients always sign at their own
`GUARANTEE_CLAIMS_VERSION`; there is no accepted-versions configuration.

## Adding a version (no Core4Mica redeploy)

### Step 1: Implement a decoder

Create a contract implementing `IGuaranteeDecoder`:

- define the version's payload struct
- decode the payload
- enforce version-specific invariants
- map to the base `Guarantee` and return it

If several future versions need to share one deployment, that decoder can itself dispatch
per version — but do not build that indirection before a second version exists.

### Step 2: Test the decoder in isolation

At minimum test:

- valid payload decode
- malformed payload revert
- each version-specific invariant revert

### Step 3: Configure Core4Mica to use it

Call `configureGuaranteeVersion(version, key, domain, decoder, enabled)` with:

- `decoder = <decoder address>`
- `enabled = true`
- valid BLS public key for this version
- valid domain separator for this version

Use script: `script/ConfigureGuaranteeVersion.s.sol:ConfigureGuaranteeVersionScript`

### Step 4: Roll out clients

Append the new version to `SUPPORTED_GUARANTEE_VERSIONS` in `crates/rpc`, teach the codec its
layout, and ensure issuer/SDK components:

- emit the same `version` in the envelope
- encode the payload in the decoder-expected layout
- use the matching BLS key/domain for signing and verification

Core keeps accepting the older versions in that list, so old clients keep working.

## Operational command examples

### Configure a Core4Mica version

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
- `GUARANTEE_KEY_SOURCE_VERSION`
- `GUARANTEE_DOMAIN_SEPARATOR`
- `GUARANTEE_DECODER`

## Safety checklist before enabling a version

1. Decoder tests pass.
2. `Core4Mica.getGuaranteeVersionConfig(version)` returns:
   - expected key
   - expected domain
   - expected decoder
   - `enabled=true`
3. SDK/issuer can produce a valid payload/signature for that version.
4. Foundry integration tests for `verifyAndDecodeGuarantee` pass.

Core refuses to start if any version in `SUPPORTED_GUARANTEE_VERSIONS` is disabled on-chain, so
a half-configured version fails the boot rather than the first guarantee.

## Test matrix in this repo

- `contracts/test/Core4MicaGuaranteeVersions.t.sol`
  - version config lifecycle and guardrails, exercised against a mock decoder
- `contracts/test/GuaranteeCrossBoundary.t.sol`
  - Rust-encoded, Rust-BLS-signed guarantee verifies and decodes on-chain
  - fixtures regenerate via `crates/rpc/tests/guarantee_golden_vectors.rs`

Recommended commands:

```bash
cd contracts
forge test --match-path test/Core4MicaGuaranteeVersions.t.sol
forge test --match-path test/GuaranteeCrossBoundary.t.sol
forge test
```
