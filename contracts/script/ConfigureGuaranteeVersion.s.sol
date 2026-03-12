// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import "forge-std/Script.sol";
import {Core4Mica} from "../src/Core4Mica.sol";
import {BLS} from "@solady/src/utils/ext/ithaca/BLS.sol";

/// @notice Configures a guarantee version in Core4Mica and validates readback.
/// @dev Required env vars:
/// - DEPLOYER_PRIVATE_KEY
/// - CORE4MICA_ADDRESS
/// - GUARANTEE_VERSION
/// - GUARANTEE_ENABLED
/// Optional env vars:
/// - GUARANTEE_REUSE_EXISTING_KEY (bool, default false)
/// - GUARANTEE_KEY_SOURCE_VERSION (uint64, default 1; used when GUARANTEE_REUSE_EXISTING_KEY=true)
/// - VK_X0, VK_X1, VK_Y0, VK_Y1 (required when GUARANTEE_REUSE_EXISTING_KEY=false)
/// - GUARANTEE_DOMAIN_SEPARATOR (bytes32, optional when disabling)
/// - GUARANTEE_DECODER (address, optional when disabling/reusing)
contract ConfigureGuaranteeVersionScript is Script {
    error InvalidCoreAddress(address core);
    error InvalidVersion(uint64 version);
    error InvalidVerificationKey();
    error ReadbackMismatch(string field);

    function run() external {
        uint256 deployerPrivateKey = vm.envUint("DEPLOYER_PRIVATE_KEY");
        address coreAddress = vm.envAddress("CORE4MICA_ADDRESS");
        if (coreAddress == address(0)) revert InvalidCoreAddress(coreAddress);

        Core4Mica core = Core4Mica(payable(coreAddress));
        uint64 version = uint64(vm.envUint("GUARANTEE_VERSION"));
        if (version == 0) revert InvalidVersion(version);

        bool enabled = vm.envBool("GUARANTEE_ENABLED");
        bool reuseExistingKey = vm.envOr("GUARANTEE_REUSE_EXISTING_KEY", false);
        uint64 keySourceVersion = uint64(vm.envOr("GUARANTEE_KEY_SOURCE_VERSION", uint256(1)));
        bytes32 domainSeparator = vm.envOr("GUARANTEE_DOMAIN_SEPARATOR", bytes32(0));
        address decoder = vm.envOr("GUARANTEE_DECODER", address(0));
        uint64 initialVersion = core.INITIAL_GUARANTEE_VERSION();
        (, bytes32 currentDomain, address currentDecoder,) = core.getGuaranteeVersionConfig(version);

        BLS.G1Point memory verificationKey;
        if (reuseExistingKey) {
            (verificationKey,,,) = core.getGuaranteeVersionConfig(keySourceVersion);
        } else {
            verificationKey = BLS.G1Point({
                x_a: vm.envBytes32("VK_X0"),
                x_b: vm.envBytes32("VK_X1"),
                y_a: vm.envBytes32("VK_Y0"),
                y_b: vm.envBytes32("VK_Y1")
            });
        }
        if (_isZeroG1(verificationKey)) revert InvalidVerificationKey();

        vm.startBroadcast(deployerPrivateKey);
        core.configureGuaranteeVersion(version, verificationKey, domainSeparator, decoder, enabled);
        vm.stopBroadcast();

        (BLS.G1Point memory storedKey, bytes32 storedDomain, address storedDecoder, bool storedEnabled) =
            core.getGuaranteeVersionConfig(version);
        bytes32 expectedDomain = domainSeparator;
        if (!enabled && expectedDomain == bytes32(0)) {
            expectedDomain = currentDomain;
        }

        address expectedDecoder = decoder;
        if (version == initialVersion) {
            expectedDecoder = address(0);
        } else if (!enabled && expectedDecoder == address(0)) {
            expectedDecoder = currentDecoder;
        }

        if (!_sameKey(storedKey, verificationKey)) revert ReadbackMismatch("verificationKey");
        if (storedDomain != expectedDomain) revert ReadbackMismatch("domainSeparator");
        if (storedDecoder != expectedDecoder) revert ReadbackMismatch("decoder");
        if (storedEnabled != enabled) revert ReadbackMismatch("enabled");

        console.log("Configured guarantee version:", version);
        console.log("Core4Mica:", coreAddress);
        console.log("Enabled:", enabled);
        if (reuseExistingKey) {
            console.log("Reused key source version:", keySourceVersion);
        }
        console.log("Decoder:", storedDecoder);
        console.log("Domain separator:");
        console.logBytes32(storedDomain);
    }

    function _sameKey(BLS.G1Point memory a, BLS.G1Point memory b) internal pure returns (bool) {
        return a.x_a == b.x_a && a.x_b == b.x_b && a.y_a == b.y_a && a.y_b == b.y_b;
    }

    function _isZeroG1(BLS.G1Point memory key) internal pure returns (bool) {
        return key.x_a == bytes32(0) && key.x_b == bytes32(0) && key.y_a == bytes32(0) && key.y_b == bytes32(0);
    }
}
