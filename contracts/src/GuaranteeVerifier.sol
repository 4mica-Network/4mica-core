// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {AccessManaged} from "@openzeppelin/contracts/access/manager/AccessManaged.sol";
import {BLS} from "@solady/src/utils/ext/ithaca/BLS.sol";
import {Guarantee, IGuaranteeDecoder} from "./GuaranteeTypes.sol";

/// @title GuaranteeVerifier
/// @notice BLS verification and version registry for 4mica payment guarantees.
/// @dev Extracted from Core4Mica: guarantee verification reads none of the vault's collateral
/// state and is never invoked on-chain by Core4Mica or the ClearingHouse — it is a pure
/// verification service consumed by the off-chain core service and the SDK. Keeping it in its
/// own contract keeps the vault's deployed size clear of the BLS pairing code and lets the
/// version registry evolve without redeploying collateral.
///
/// Governance (`setGuaranteeVerificationKey`, `configureGuaranteeVersion`) is gated by the same
/// AccessManager instance that governs Core4Mica, so role topology is unchanged by the split.
contract GuaranteeVerifier is AccessManaged {
    // ========= Errors =========
    error InvalidSignature();
    error UnsupportedGuaranteeVersion(uint64 version);
    error InvalidGuaranteeDomain();
    error MissingGuaranteeDecoder(uint64 version);

    // ========= Storage =========
    struct VersionConfig {
        BLS.G1Point verificationKey;
        bytes32 domainSeparator;
        address decoder;
        bool enabled;
    }

    uint64 public constant INITIAL_GUARANTEE_VERSION = 1;

    // forge-lint: disable-next-line(mixed-case-variable)
    BLS.G1Point public GUARANTEE_VERIFICATION_KEY;
    bytes32 public guaranteeDomainSeparator;

    mapping(uint64 => VersionConfig) private guaranteeVersions;

    // ========= Events =========
    event VerificationKeyUpdated(BLS.G1Point newVerificationKey);
    event GuaranteeVersionUpdated(
        uint64 indexed version, BLS.G1Point verificationKey, bytes32 domainSeparator, address decoder, bool enabled
    );

    // ========= Constructor =========
    /// @param manager The AccessManager governing key rotation and version configuration.
    /// @param verificationKey The initial BLS verification key, installed as version 1.
    /// @dev The version-1 domain separator binds `address(this)`, so it is derived from the
    /// verifier's own address. Signers must read it from this contract (or from
    /// `getGuaranteeVersionConfig`) rather than deriving it from the Core4Mica address.
    constructor(address manager, BLS.G1Point memory verificationKey) AccessManaged(manager) {
        GUARANTEE_VERIFICATION_KEY = verificationKey;
        guaranteeDomainSeparator = keccak256(abi.encode("4MICA_CORE_GUARANTEE_V1", block.chainid, address(this)));
        guaranteeVersions[INITIAL_GUARANTEE_VERSION] = VersionConfig({
            verificationKey: verificationKey,
            domainSeparator: guaranteeDomainSeparator,
            decoder: address(0),
            enabled: true
        });
        emit GuaranteeVersionUpdated(
            INITIAL_GUARANTEE_VERSION, verificationKey, guaranteeDomainSeparator, address(0), true
        );
    }

    // ========= Governance =========
    function setGuaranteeVerificationKey(BLS.G1Point calldata verificationKey) external restricted {
        GUARANTEE_VERIFICATION_KEY = verificationKey;
        VersionConfig storage config = guaranteeVersions[INITIAL_GUARANTEE_VERSION];
        config.verificationKey = verificationKey;
        emit VerificationKeyUpdated(verificationKey);
        emit GuaranteeVersionUpdated(
            INITIAL_GUARANTEE_VERSION, verificationKey, config.domainSeparator, config.decoder, config.enabled
        );
    }

    function configureGuaranteeVersion(
        uint64 version,
        BLS.G1Point calldata verificationKey,
        bytes32 domainSeparator,
        address decoder,
        bool enabled
    ) external restricted {
        if (version == 0) revert UnsupportedGuaranteeVersion(version);
        if (version == INITIAL_GUARANTEE_VERSION && decoder != address(0)) {
            revert UnsupportedGuaranteeVersion(version);
        }
        VersionConfig storage config = guaranteeVersions[version];
        address decoderToUse = decoder;
        if (version != INITIAL_GUARANTEE_VERSION && decoderToUse == address(0)) {
            if (enabled) revert MissingGuaranteeDecoder(version);
            decoderToUse = config.decoder;
        }
        bytes32 domainSeparatorToUse = domainSeparator;
        if (enabled && domainSeparatorToUse == bytes32(0)) {
            revert InvalidGuaranteeDomain();
        }
        if (!enabled && domainSeparatorToUse == bytes32(0)) {
            domainSeparatorToUse = config.domainSeparator;
        }

        config.verificationKey = verificationKey;
        config.domainSeparator = domainSeparatorToUse;
        config.decoder = decoderToUse;
        config.enabled = enabled;

        if (version == INITIAL_GUARANTEE_VERSION) {
            GUARANTEE_VERIFICATION_KEY = verificationKey;
            guaranteeDomainSeparator = domainSeparatorToUse;
        }

        emit GuaranteeVersionUpdated(version, verificationKey, domainSeparatorToUse, decoderToUse, enabled);
    }

    // ========= Views =========
    function getGuaranteeVersionConfig(uint64 version)
        external
        view
        returns (BLS.G1Point memory verificationKey, bytes32 domainSeparator, address decoder, bool enabled)
    {
        VersionConfig storage config = guaranteeVersions[version];
        return (config.verificationKey, config.domainSeparator, config.decoder, config.enabled);
    }

    function verifyAndDecodeGuarantee(bytes memory guarantee, BLS.G2Point memory signature)
        public
        view
        returns (Guarantee memory)
    {
        (uint64 version, bytes memory encodedGuarantee) = abi.decode(guarantee, (uint64, bytes));
        VersionConfig storage config = guaranteeVersions[version];
        if (!config.enabled) revert UnsupportedGuaranteeVersion(version);

        BLS.G1Point[] memory g1Points = new BLS.G1Point[](2);
        g1Points[0] = _negatedG1Generator();
        g1Points[1] = config.verificationKey;

        BLS.G2Point[] memory g2Points = new BLS.G2Point[](2);
        g2Points[0] = signature;
        g2Points[1] = BLS.hashToG2(guarantee);

        if (!BLS.pairing(g1Points, g2Points)) revert InvalidSignature();

        Guarantee memory g;
        if (version == INITIAL_GUARANTEE_VERSION && config.decoder == address(0)) {
            g = abi.decode(encodedGuarantee, (Guarantee));
        } else {
            if (config.decoder == address(0)) {
                revert MissingGuaranteeDecoder(version);
            }
            g = IGuaranteeDecoder(config.decoder).decode(encodedGuarantee);
        }

        if (g.domain != config.domainSeparator) {
            revert InvalidGuaranteeDomain();
        }
        return g;
    }

    /// @notice The negated generator point in G1 (-G1), derived from EIP-2537's standard G1 generator.
    /// @dev A `pure` builder rather than a storage variable: Solidity cannot mark a struct
    /// `constant`, and holding it in storage costs four SSTOREs at deploy plus four SLOADs on
    /// every verification for a value that never changes.
    function _negatedG1Generator() internal pure returns (BLS.G1Point memory) {
        return BLS.G1Point(
            bytes32(0x0000000000000000000000000000000017F1D3A73197D7942695638C4FA9AC0F),
            bytes32(0xC3688C4F9774B905A14E3A3F171BAC586C55E83FF97A1AEFFB3AF00ADB22C6BB),
            bytes32(0x00000000000000000000000000000000114D1D6855D545A8AA7D76C8CF2E21F2),
            bytes32(0x67816AEF1DB507C96655B9D5CAAC42364E6F38BA0ECB751BAD54DCD6B939C2CA)
        );
    }
}
