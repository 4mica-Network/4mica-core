// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Script, console} from "forge-std/Script.sol";
import {ValidationRegistryGuaranteeDecoder} from "../src/ValidationRegistryGuaranteeDecoder.sol";
import {DeterministicCreate2} from "./utils/DeterministicCreate2.sol";

/// @notice Deploys ValidationRegistryGuaranteeDecoder deterministically and verifies trusted registries readback.
/// @dev Required env vars:
/// - DEPLOYER_PRIVATE_KEY
/// - TRUSTED_VALIDATION_REGISTRY (single)
///   OR
/// - TRUSTED_VALIDATION_REGISTRIES_COUNT + TRUSTED_VALIDATION_REGISTRY_0..n-1
/// Optional env vars:
/// - CREATE2_SALT (default: "4mica-core-v1")
contract DeployValidationRegistryGuaranteeDecoderScript is Script {
    error MissingTrustedValidationRegistries();
    error InvalidTrustedValidationRegistry(address registry);
    error DecoderDeploymentFailed(address decoder);
    error TrustedRegistryReadbackMismatch(address decoder, address registry);

    function run() external returns (address decoderAddress) {
        uint256 deployerPrivateKey = vm.envUint("DEPLOYER_PRIVATE_KEY");
        address[] memory trustedRegistries = _loadTrustedValidationRegistries();
        if (trustedRegistries.length == 0) revert MissingTrustedValidationRegistries();

        string memory saltSeed = vm.envOr("CREATE2_SALT", string("4mica-core-v1"));
        bytes32 baseSalt = keccak256(bytes(saltSeed));
        bytes32 decoderSalt = _deriveSalt(baseSalt, "VALIDATION_REGISTRY_GUARANTEE_DECODER");

        vm.startBroadcast(deployerPrivateKey);
        decoderAddress = DeterministicCreate2.deploy(
            decoderSalt,
            abi.encodePacked(type(ValidationRegistryGuaranteeDecoder).creationCode, abi.encode(trustedRegistries))
        );
        vm.stopBroadcast();

        if (decoderAddress == address(0) || decoderAddress.code.length == 0) {
            revert DecoderDeploymentFailed(decoderAddress);
        }

        ValidationRegistryGuaranteeDecoder decoder = ValidationRegistryGuaranteeDecoder(decoderAddress);
        for (uint256 i = 0; i < trustedRegistries.length; i++) {
            if (!decoder.isTrustedValidationRegistry(trustedRegistries[i])) {
                revert TrustedRegistryReadbackMismatch(decoderAddress, trustedRegistries[i]);
            }
        }

        console.log("ValidationRegistryGuaranteeDecoder:", decoderAddress);
        console.log("Trusted registries count:", trustedRegistries.length);
        console.log("CREATE2 base salt:");
        console.logBytes32(baseSalt);
        console.log("CREATE2 decoder salt:");
        console.logBytes32(decoderSalt);
    }

    function _loadTrustedValidationRegistries() internal view returns (address[] memory registries) {
        uint256 count = vm.envOr("TRUSTED_VALIDATION_REGISTRIES_COUNT", uint256(0));
        if (count > 0) {
            registries = new address[](count);
            for (uint256 i = 0; i < count; i++) {
                string memory key = string.concat("TRUSTED_VALIDATION_REGISTRY_", vm.toString(i));
                registries[i] = vm.envAddress(key);
                if (registries[i] == address(0)) {
                    revert InvalidTrustedValidationRegistry(address(0));
                }
            }
            return registries;
        }

        address single = vm.envOr("TRUSTED_VALIDATION_REGISTRY", address(0));
        if (single == address(0)) return new address[](0);

        registries = new address[](1);
        registries[0] = single;
        return registries;
    }

    function _deriveSalt(bytes32 baseSalt, string memory label) internal pure returns (bytes32) {
        return keccak256(abi.encode(baseSalt, label));
    }
}
