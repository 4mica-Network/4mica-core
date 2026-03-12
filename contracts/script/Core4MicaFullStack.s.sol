// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import "forge-std/Script.sol";
import {AccessManager} from "@openzeppelin/contracts/access/manager/AccessManager.sol";
import {BLS} from "@solady/src/utils/ext/ithaca/BLS.sol";

import {Core4Mica} from "../src/Core4Mica.sol";
import {GuaranteeDecoderRouter} from "../src/GuaranteeDecoderRouter.sol";
import {ValidationRegistryGuaranteeDecoder} from "../src/ValidationRegistryGuaranteeDecoder.sol";
import {DeterministicCreate2} from "./utils/DeterministicCreate2.sol";

/// @notice Deploys full guarantee stack:
/// AccessManager + Core4Mica + GuaranteeDecoderRouter + ValidationRegistryGuaranteeDecoder.
///
/// Required env:
/// - DEPLOYER_PRIVATE_KEY
/// - VK_X0
/// - VK_X1
/// - VK_Y0
/// - VK_Y1
///
/// Stablecoin configuration (optional):
/// - STABLECOINS_COUNT=<n> and STABLECOIN_0..n-1
///   OR
/// - USDC_TOKEN + USDT_TOKEN (legacy compatibility)
///
/// Validation registry allowlist:
/// - TRUSTED_VALIDATION_REGISTRY=<address>
///   OR
/// - TRUSTED_VALIDATION_REGISTRIES_COUNT=<n> and TRUSTED_VALIDATION_REGISTRY_0..n-1
///
/// Deterministic deployment:
/// - CREATE2_SALT (optional, default "4mica-core-v1")
/// - ACCESS_MANAGER_ADMIN (optional, default broadcaster address)
contract Core4MicaFullStackScript is Script {
    bytes4 private constant RECORD_PAYMENT_SELECTOR = bytes4(keccak256("recordPayment(uint256,address,uint256)"));
    bytes4 private constant SET_TIMING_PARAMETERS_SELECTOR =
        bytes4(keccak256("setTimingParameters(uint256,uint256,uint256,uint256)"));

    uint64 public constant USER_ADMIN_ROLE = 4;
    uint64 public constant OPERATOR_ROLE = 9;
    uint64 public constant GUARANTEE_V2 = 2;

    function run() external {
        uint256 deployerPrivateKey = vm.envUint("DEPLOYER_PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);
        address managerAdmin = vm.envOr("ACCESS_MANAGER_ADMIN", deployer);
        address[] memory stablecoins = _loadStablecoinAssets();

        BLS.G1Point memory guaranteeVerificationKey = BLS.G1Point({
            x_a: vm.envBytes32("VK_X0"),
            x_b: vm.envBytes32("VK_X1"),
            y_a: vm.envBytes32("VK_Y0"),
            y_b: vm.envBytes32("VK_Y1")
        });

        address[] memory trustedRegistries = _loadTrustedValidationRegistries();
        string memory saltSeed = vm.envOr("CREATE2_SALT", string("4mica-core-v1"));
        bytes32 baseSalt = keccak256(bytes(saltSeed));

        vm.startBroadcast(deployerPrivateKey);

        address managerAddress = DeterministicCreate2.deploy(
            _deriveSalt(baseSalt, "ACCESS_MANAGER"),
            abi.encodePacked(type(AccessManager).creationCode, abi.encode(managerAdmin))
        );
        AccessManager manager = AccessManager(managerAddress);

        address core4MicaAddress = DeterministicCreate2.deploy(
            _deriveSalt(baseSalt, "CORE4MICA"),
            abi.encodePacked(type(Core4Mica).creationCode, abi.encode(managerAddress, guaranteeVerificationKey))
        );
        Core4Mica core4Mica = Core4Mica(payable(core4MicaAddress));

        address routerAddress = DeterministicCreate2.deploy(
            _deriveSalt(baseSalt, "GUARANTEE_DECODER_ROUTER"),
            abi.encodePacked(type(GuaranteeDecoderRouter).creationCode, abi.encode(managerAddress))
        );
        GuaranteeDecoderRouter router = GuaranteeDecoderRouter(routerAddress);

        address validationDecoderAddress = DeterministicCreate2.deploy(
            _deriveSalt(baseSalt, "VALIDATION_REGISTRY_GUARANTEE_DECODER"),
            abi.encodePacked(type(ValidationRegistryGuaranteeDecoder).creationCode, abi.encode(trustedRegistries))
        );
        ValidationRegistryGuaranteeDecoder validationDecoder = ValidationRegistryGuaranteeDecoder(validationDecoderAddress);

        _configureCoreRoles(manager, core4Mica, deployer);
        _configureRouterRoles(manager, router);
        if (stablecoins.length > 0) {
            core4Mica.setStablecoinAssets(stablecoins, true);
        }

        BLS.G1Point memory v2VerificationKey = guaranteeVerificationKey;
        bytes32 v2Domain = keccak256(abi.encode("4MICA_CORE_GUARANTEE_V2", block.chainid, address(core4Mica)));
        core4Mica.configureGuaranteeVersion(GUARANTEE_V2, v2VerificationKey, v2Domain, address(validationDecoder), true);

        vm.stopBroadcast();

        console.log("AccessManager:", address(manager));
        console.log("Core4Mica:", address(core4Mica));
        console.log("GuaranteeDecoderRouter:", address(router));
        console.log("ValidationRegistryGuaranteeDecoder:", address(validationDecoder));
        console.log("Trusted registries count:", trustedRegistries.length);
        console.log("AccessManager admin:", managerAdmin);
        console.log("CREATE2 base salt:");
        console.logBytes32(baseSalt);
    }

    function _configureCoreRoles(AccessManager manager, Core4Mica core4Mica, address deployer) internal {
        manager.setTargetFunctionRole(address(core4Mica), _asSingletonArray(RECORD_PAYMENT_SELECTOR), OPERATOR_ROLE);

        bytes4[] memory adminSelectors = new bytes4[](11);
        adminSelectors[0] = Core4Mica.setWithdrawalGracePeriod.selector;
        adminSelectors[1] = Core4Mica.setRemunerationGracePeriod.selector;
        adminSelectors[2] = Core4Mica.setTabExpirationTime.selector;
        adminSelectors[3] = Core4Mica.setGuaranteeVerificationKey.selector;
        adminSelectors[4] = SET_TIMING_PARAMETERS_SELECTOR;
        adminSelectors[5] = Core4Mica.setSynchronizationDelay.selector;
        adminSelectors[6] = Core4Mica.configureGuaranteeVersion.selector;
        adminSelectors[7] = Core4Mica.pause.selector;
        adminSelectors[8] = Core4Mica.unpause.selector;
        adminSelectors[9] = Core4Mica.setStablecoinAsset.selector;
        adminSelectors[10] = Core4Mica.setStablecoinAssets.selector;

        for (uint256 i = 0; i < adminSelectors.length; i++) {
            manager.setTargetFunctionRole(address(core4Mica), _asSingletonArray(adminSelectors[i]), USER_ADMIN_ROLE);
        }

        manager.grantRole(OPERATOR_ROLE, deployer, 0);
        manager.grantRole(USER_ADMIN_ROLE, deployer, 0);
    }

    function _configureRouterRoles(AccessManager manager, GuaranteeDecoderRouter router) internal {
        manager.setTargetFunctionRole(
            address(router), _asSingletonArray(router.setVersionModule.selector), USER_ADMIN_ROLE
        );
        manager.setTargetFunctionRole(
            address(router), _asSingletonArray(router.freezeVersion.selector), USER_ADMIN_ROLE
        );
    }

    function _loadTrustedValidationRegistries() internal view returns (address[] memory registries) {
        uint256 count = vm.envOr("TRUSTED_VALIDATION_REGISTRIES_COUNT", uint256(0));
        if (count > 0) {
            registries = new address[](count);
            for (uint256 i = 0; i < count; i++) {
                string memory key = string.concat("TRUSTED_VALIDATION_REGISTRY_", vm.toString(i));
                registries[i] = vm.envAddress(key);
                require(registries[i] != address(0), "trusted registry is zero");
            }
            return registries;
        }

        address single = vm.envOr("TRUSTED_VALIDATION_REGISTRY", address(0));
        require(single != address(0), "trusted validation registry required");
        registries = new address[](1);
        registries[0] = single;
    }

    function _asSingletonArray(bytes4 selector) internal pure returns (bytes4[] memory arr) {
        arr = new bytes4[](1);
        arr[0] = selector;
    }

    function _deriveSalt(bytes32 baseSalt, string memory label) internal pure returns (bytes32) {
        return keccak256(abi.encode(baseSalt, label));
    }

    function _loadStablecoinAssets() internal view returns (address[] memory assets) {
        uint256 count = vm.envOr("STABLECOINS_COUNT", uint256(0));
        if (count > 0) {
            assets = new address[](count);
            for (uint256 i = 0; i < count; i++) {
                string memory key = string.concat("STABLECOIN_", vm.toString(i));
                assets[i] = vm.envAddress(key);
                require(assets[i] != address(0), "stablecoin address is zero");
            }
            return assets;
        }

        address usdc = vm.envOr("USDC_TOKEN", address(0));
        address usdt = vm.envOr("USDT_TOKEN", address(0));
        if (usdc != address(0) && usdt != address(0)) {
            assets = new address[](2);
            assets[0] = usdc;
            assets[1] = usdt;
            return assets;
        }
        if (usdc != address(0) || usdt != address(0)) {
            revert("set both USDC_TOKEN and USDT_TOKEN or use STABLECOIN_*");
        }
        return new address[](0);
    }
}
