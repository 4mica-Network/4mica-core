// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Script, console} from "forge-std/Script.sol";
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
    error InvalidStablecoinConfiguration();
    error PartialAaveConfiguration();
    error StablecoinReadbackMismatch();
    error AaveReadbackMismatch(string field);
    error YieldFeeReadbackMismatch(uint256 expected, uint256 actual);

    bytes4 private constant RECORD_PAYMENT_SELECTOR = bytes4(keccak256("recordPayment(uint256,address,uint256)"));
    bytes4 private constant SET_TIMING_PARAMETERS_SELECTOR =
        bytes4(keccak256("setTimingParameters(uint256,uint256,uint256,uint256)"));

    // Delayed governance role for protocol policy, trust roots, and Aave configuration.
    uint64 public constant GOVERNANCE_ROLE = 1;
    // Delayed governance role for any function that moves protocol-owned value out of Core4Mica.
    uint64 public constant TREASURY_ROLE = 2;
    // Fast incident-response role limited to emergency halts; cannot change protocol economics or move funds.
    uint64 public constant GUARDIAN_ROLE = 3;
    // Immediate 4mica operator role for settlement bookkeeping only.
    uint64 public constant FOURMICA_OPERATOR_ROLE = 4;
    uint64 public constant GUARANTEE_V2 = 2;

    uint32 public constant DEFAULT_GOVERNANCE_EXECUTION_DELAY = 72 hours;
    uint32 public constant DEFAULT_TREASURY_EXECUTION_DELAY = 72 hours;
    uint32 public constant DEFAULT_GUARDIAN_EXECUTION_DELAY = 0;
    uint32 public constant DEFAULT_FOURMICA_OPERATOR_EXECUTION_DELAY = 0;

    struct FullStackDeployment {
        AccessManager manager;
        Core4Mica core4Mica;
        GuaranteeDecoderRouter router;
        ValidationRegistryGuaranteeDecoder validationDecoder;
    }

    struct DeploymentConfig {
        address deployer;
        address managerAdmin;
        address[] stablecoins;
        address[] trustedRegistries;
        bytes32 baseSalt;
        BLS.G1Point guaranteeVerificationKey;
    }

    function run() external {
        uint256 deployerPrivateKey = vm.envUint("DEPLOYER_PRIVATE_KEY");
        DeploymentConfig memory config = _loadDeploymentConfig(vm.addr(deployerPrivateKey));

        vm.startBroadcast(deployerPrivateKey);

        FullStackDeployment memory deployment = _deployFullStack(
            config.baseSalt,
            config.managerAdmin,
            config.guaranteeVerificationKey,
            config.stablecoins,
            config.trustedRegistries
        );
        _configureDeployedStack(deployment, config);

        vm.stopBroadcast();

        console.log("AccessManager:", address(deployment.manager));
        console.log("Core4Mica:", address(deployment.core4Mica));
        console.log("GuaranteeDecoderRouter:", address(deployment.router));
        console.log("ValidationRegistryGuaranteeDecoder:", address(deployment.validationDecoder));
        console.log("Trusted registries count:", config.trustedRegistries.length);
        console.log("AccessManager admin:", config.managerAdmin);
        console.log("CREATE2 base salt:");
        console.logBytes32(config.baseSalt);
    }

    function _loadDeploymentConfig(address deployer) internal view returns (DeploymentConfig memory config) {
        address[] memory stablecoins = _loadStablecoinAssets();
        require(stablecoins.length == 2, "need exactly 2 stablecoins");
        if (stablecoins[0] == stablecoins[1]) revert InvalidStablecoinConfiguration();

        config.deployer = deployer;
        config.managerAdmin = vm.envOr("ACCESS_MANAGER_ADMIN", deployer);
        config.stablecoins = stablecoins;
        config.trustedRegistries = _loadTrustedValidationRegistries();
        config.baseSalt = keccak256(bytes(vm.envOr("CREATE2_SALT", string("4mica-core-v1"))));
        config.guaranteeVerificationKey = BLS.G1Point({
            x_a: vm.envBytes32("VK_X0"),
            x_b: vm.envBytes32("VK_X1"),
            y_a: vm.envBytes32("VK_Y0"),
            y_b: vm.envBytes32("VK_Y1")
        });
    }

    function _configureDeployedStack(FullStackDeployment memory deployment, DeploymentConfig memory config) internal {
        _assertStablecoinReadback(deployment.core4Mica, config.stablecoins);
        _configureOptionalAave(deployment.core4Mica, config.stablecoins);

        bytes32 v2Domain =
            keccak256(abi.encode("4MICA_CORE_GUARANTEE_V2", block.chainid, address(deployment.core4Mica)));
        deployment.core4Mica.configureGuaranteeVersion(
            GUARANTEE_V2,
            config.guaranteeVerificationKey,
            v2Domain,
            address(deployment.validationDecoder),
            true
        );
        _configureCoreRoles(deployment.manager, deployment.core4Mica, config.deployer);
        _configureRouterRoles(deployment.manager, deployment.router);
    }

    function _deployFullStack(
        bytes32 baseSalt,
        address managerAdmin,
        BLS.G1Point memory guaranteeVerificationKey,
        address[] memory stablecoins,
        address[] memory trustedRegistries
    ) internal returns (FullStackDeployment memory deployment) {
        address managerAddress = DeterministicCreate2.deploy(
            _deriveSalt(baseSalt, "ACCESS_MANAGER"),
            abi.encodePacked(type(AccessManager).creationCode, abi.encode(managerAdmin))
        );
        address core4MicaAddress = DeterministicCreate2.deploy(
            _deriveSalt(baseSalt, "CORE4MICA"),
            abi.encodePacked(
                type(Core4Mica).creationCode,
                abi.encode(managerAddress, guaranteeVerificationKey, stablecoins)
            )
        );
        address routerAddress = DeterministicCreate2.deploy(
            _deriveSalt(baseSalt, "GUARANTEE_DECODER_ROUTER"),
            abi.encodePacked(type(GuaranteeDecoderRouter).creationCode, abi.encode(managerAddress))
        );
        address validationDecoderAddress = DeterministicCreate2.deploy(
            _deriveSalt(baseSalt, "VALIDATION_REGISTRY_GUARANTEE_DECODER"),
            abi.encodePacked(type(ValidationRegistryGuaranteeDecoder).creationCode, abi.encode(trustedRegistries))
        );

        deployment.manager = AccessManager(managerAddress);
        deployment.core4Mica = Core4Mica(payable(core4MicaAddress));
        deployment.router = GuaranteeDecoderRouter(routerAddress);
        deployment.validationDecoder = ValidationRegistryGuaranteeDecoder(validationDecoderAddress);
    }

    function _configureCoreRoles(AccessManager manager, Core4Mica core4Mica, address deployer) internal {
        bytes4[] memory governanceSelectors = new bytes4[](9);
        governanceSelectors[0] = Core4Mica.setWithdrawalGracePeriod.selector;
        governanceSelectors[1] = Core4Mica.setRemunerationGracePeriod.selector;
        governanceSelectors[2] = Core4Mica.setTabExpirationTime.selector;
        governanceSelectors[3] = Core4Mica.setGuaranteeVerificationKey.selector;
        governanceSelectors[4] = SET_TIMING_PARAMETERS_SELECTOR;
        governanceSelectors[5] = Core4Mica.setSynchronizationDelay.selector;
        governanceSelectors[6] = Core4Mica.configureGuaranteeVersion.selector;
        governanceSelectors[7] = Core4Mica.configureAave.selector;
        governanceSelectors[8] = Core4Mica.setYieldFeeBps.selector;

        for (uint256 i = 0; i < governanceSelectors.length; i++) {
            manager.setTargetFunctionRole(address(core4Mica), _asSingletonArray(governanceSelectors[i]), GOVERNANCE_ROLE);
        }

        manager.setTargetFunctionRole(
            address(core4Mica), _asSingletonArray(Core4Mica.claimProtocolYield.selector), TREASURY_ROLE
        );
        manager.setTargetFunctionRole(
            address(core4Mica), _asSingletonArray(Core4Mica.claimSurplusATokens.selector), TREASURY_ROLE
        );
        manager.setTargetFunctionRole(address(core4Mica), _asSingletonArray(Core4Mica.pause.selector), GUARDIAN_ROLE);
        manager.setTargetFunctionRole(
            address(core4Mica), _asSingletonArray(RECORD_PAYMENT_SELECTOR), FOURMICA_OPERATOR_ROLE
        );
        manager.setTargetFunctionRole(
            address(core4Mica), _asSingletonArray(Core4Mica.unpause.selector), GOVERNANCE_ROLE
        );

        manager.grantRole(GOVERNANCE_ROLE, _roleHolder("GOVERNANCE_ROLE_HOLDER", deployer), _governanceDelay());
        manager.grantRole(TREASURY_ROLE, _roleHolder("TREASURY_ROLE_HOLDER", deployer), _treasuryDelay());
        manager.grantRole(GUARDIAN_ROLE, _roleHolder("GUARDIAN_ROLE_HOLDER", deployer), _guardianDelay());
        manager.grantRole(
            FOURMICA_OPERATOR_ROLE,
            _roleHolder("FOURMICA_OPERATOR_ROLE_HOLDER", deployer),
            _fourmicaOperatorDelay()
        );
    }

    function _configureRouterRoles(AccessManager manager, GuaranteeDecoderRouter router) internal {
        manager.setTargetFunctionRole(
            address(router), _asSingletonArray(router.setVersionModule.selector), GOVERNANCE_ROLE
        );
        manager.setTargetFunctionRole(
            address(router), _asSingletonArray(router.freezeVersion.selector), GOVERNANCE_ROLE
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
        revert("set STABLECOINS_COUNT and STABLECOIN_0..n");
    }

    function _assertStablecoinReadback(Core4Mica core4Mica, address[] memory expectedAssets) internal view {
        address[] memory storedAssets = core4Mica.getERC20Tokens();
        if (storedAssets.length != expectedAssets.length) revert StablecoinReadbackMismatch();
        for (uint256 i = 0; i < expectedAssets.length; i++) {
            if (storedAssets[i] != expectedAssets[i]) revert StablecoinReadbackMismatch();
        }
    }

    function _configureOptionalAave(Core4Mica core4Mica, address[] memory stablecoins) internal {
        bool configureAave = vm.envOr("CONFIGURE_AAVE", false);
        address provider = vm.envOr("AAVE_POOL_ADDRESSES_PROVIDER", address(0));
        address stablecoinAToken0 = vm.envOr("STABLECOIN_ATOKEN_0", address(0));
        address stablecoinAToken1 = vm.envOr("STABLECOIN_ATOKEN_1", address(0));

        if (
            (provider != address(0) || stablecoinAToken0 != address(0) || stablecoinAToken1 != address(0))
                && (
                    !configureAave || provider == address(0) || stablecoinAToken0 == address(0)
                        || stablecoinAToken1 == address(0)
                )
        ) {
            revert PartialAaveConfiguration();
        }

        if (configureAave) {
            address[] memory aTokens = new address[](2);
            aTokens[0] = stablecoinAToken0;
            aTokens[1] = stablecoinAToken1;
            core4Mica.configureAave(provider, aTokens);
            if (address(core4Mica.aaveAddressesProvider()) != provider) {
                revert AaveReadbackMismatch("provider");
            }
            if (core4Mica.stablecoinAToken(stablecoins[0]) != stablecoinAToken0) {
                revert AaveReadbackMismatch("stablecoinAToken0");
            }
            if (core4Mica.stablecoinAToken(stablecoins[1]) != stablecoinAToken1) {
                revert AaveReadbackMismatch("stablecoinAToken1");
            }
        }

        bool setYieldFee = vm.envOr("SET_YIELD_FEE_BPS", false);
        uint256 yieldFeeBps = vm.envOr("YIELD_FEE_BPS", uint256(0));
        if (setYieldFee) {
            core4Mica.setYieldFeeBps(yieldFeeBps);
            uint256 storedYieldFeeBps = core4Mica.yieldFeeBps();
            if (storedYieldFeeBps != yieldFeeBps) {
                revert YieldFeeReadbackMismatch(yieldFeeBps, storedYieldFeeBps);
            }
        }
    }

    function _roleHolder(string memory envKey, address fallbackAddress) internal view returns (address) {
        return vm.envOr(envKey, fallbackAddress);
    }

    function _governanceDelay() internal view returns (uint32) {
        return uint32(vm.envOr("GOVERNANCE_EXECUTION_DELAY", uint256(DEFAULT_GOVERNANCE_EXECUTION_DELAY)));
    }

    function _treasuryDelay() internal view returns (uint32) {
        return uint32(vm.envOr("TREASURY_EXECUTION_DELAY", uint256(DEFAULT_TREASURY_EXECUTION_DELAY)));
    }

    function _guardianDelay() internal view returns (uint32) {
        return uint32(vm.envOr("GUARDIAN_EXECUTION_DELAY", uint256(DEFAULT_GUARDIAN_EXECUTION_DELAY)));
    }

    function _fourmicaOperatorDelay() internal view returns (uint32) {
        return uint32(
            vm.envOr("FOURMICA_OPERATOR_EXECUTION_DELAY", uint256(DEFAULT_FOURMICA_OPERATOR_EXECUTION_DELAY))
        );
    }
}
