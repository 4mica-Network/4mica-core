// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Script, console} from "forge-std/Script.sol";
import {Core4Mica} from "../src/Core4Mica.sol";
import {AccessManager} from "@openzeppelin/contracts/access/manager/AccessManager.sol";
import {BLS} from "@solady/src/utils/ext/ithaca/BLS.sol";
import {DeterministicCreate2} from "./utils/DeterministicCreate2.sol";

contract Core4MicaScript is Script {
    error InvalidStablecoinConfiguration();
    error PartialAaveConfiguration();
    error StablecoinReadbackMismatch();
    error AaveReadbackMismatch(string field);
    error YieldFeeReadbackMismatch(uint256 expected, uint256 actual);
    error StablecoinDepositsEnabledReadbackMismatch(address asset, bool expected, bool actual);

    AccessManager manager;
    bytes4 private constant RECORD_PAYMENT_SELECTOR = bytes4(keccak256("recordPayment(uint256,address,uint256)"));
    bytes4 private constant SET_TIMING_PARAMETERS_SELECTOR =
        bytes4(keccak256("setTimingParameters(uint256,uint256,uint256,uint256)"));

    // Roles
    uint64 public constant CALLER_ROLE = 1;
    uint64 public constant CALLER_ADMIN_ROLE = 2;

    uint64 public constant USER_ROLE = 3;
    uint64 public constant USER_ADMIN_ROLE = 4;

    uint64 public constant AGGREGATOR_ROLE = 7;
    uint64 public constant AGGREGATOR_ADMIN_ROLE = 8;

    uint64 public constant OPERATOR_ROLE = 9;
    uint64 public constant OPERATOR_ADMIN_ROLE = 10;

    uint64 public constant DEFAULT_ADMIN_ROLE = 0;

    // Execution delays (real values; for local/test we’ll pass 0 in grantRole)
    uint32 public constant CALLER_ROLE_EXECUTION_DELAY = 0 hours;
    uint32 public constant CALLER_ADMIN_ROLE_EXECUTION_DELAY = 0 hours;

    uint32 public constant USER_ROLE_EXECUTION_DELAY = 0 hours;
    uint32 public constant USER_ADMIN_ROLE_EXECUTION_DELAY = 0 hours;

    uint32 public constant AGGREGATOR_ROLE_EXECUTION_DELAY = 0 hours;
    uint32 public constant AGGREGATOR_ADMIN_ROLE_EXECUTION_DELAY = 0 hours;

    uint32 public constant OPERATOR_ROLE_EXECUTION_DELAY = 0 hours;
    uint32 public constant OPERATOR_ADMIN_ROLE_EXECUTION_DELAY = 0 hours;

    function run() external {
        uint256 deployerPrivateKey = vm.envUint("DEPLOYER_PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);
        address managerAdmin = vm.envOr("ACCESS_MANAGER_ADMIN", deployer);
        address[] memory stablecoins = _loadStablecoinAssets();
        require(stablecoins.length == 2, "need USDC and USDT");
        if (stablecoins[0] == stablecoins[1]) revert InvalidStablecoinConfiguration();
        string memory saltSeed = vm.envOr("CREATE2_SALT", string("4mica-core-v1"));
        bytes32 baseSalt = keccak256(bytes(saltSeed));

        BLS.G1Point memory guaranteeVerificationKey = BLS.G1Point({
            x_a: vm.envBytes32("VK_X0"),
            x_b: vm.envBytes32("VK_X1"),
            y_a: vm.envBytes32("VK_Y0"),
            y_b: vm.envBytes32("VK_Y1")
        });

        vm.startBroadcast(deployerPrivateKey);

        // 1. Deploy AccessManager and Core4Mica via deterministic CREATE2.
        address managerAddress = DeterministicCreate2.deploy(
            _deriveSalt(baseSalt, "ACCESS_MANAGER"),
            abi.encodePacked(type(AccessManager).creationCode, abi.encode(managerAdmin))
        );
        manager = AccessManager(managerAddress);
        address core4MicaAddress = DeterministicCreate2.deploy(
            _deriveSalt(baseSalt, "CORE4MICA"),
            abi.encodePacked(
                type(Core4Mica).creationCode,
                abi.encode(managerAddress, guaranteeVerificationKey, stablecoins[0], stablecoins[1])
            )
        );
        Core4Mica core4Mica = Core4Mica(payable(core4MicaAddress));

        // 2. Map Core4Mica functions to roles
        // Operator functions → OPERATOR_ROLE
        manager.setTargetFunctionRole(address(core4Mica), _asSingletonArray(RECORD_PAYMENT_SELECTOR), OPERATOR_ROLE);

        // Admin-only config functions → USER_ADMIN_ROLE
        bytes4[] memory adminSelectors = new bytes4[](15);
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
        adminSelectors[11] = Core4Mica.configureAave.selector;
        adminSelectors[12] = Core4Mica.setYieldFeeBps.selector;
        adminSelectors[13] = Core4Mica.setStablecoinDepositsEnabled.selector;
        adminSelectors[14] = Core4Mica.claimProtocolYield.selector;
        for (uint256 i = 0; i < adminSelectors.length; i++) {
            manager.setTargetFunctionRole(address(core4Mica), _asSingletonArray(adminSelectors[i]), USER_ADMIN_ROLE);
        }

        // 3. Grant roles (immediate in local/test: 0 delay)
        manager.grantRole(OPERATOR_ROLE, deployer, 0); // deployer can act as OPERATOR
        manager.grantRole(USER_ADMIN_ROLE, deployer, 0); // deployer can manage OPERATORs
        if (stablecoins.length > 0) {
            core4Mica.setStablecoinAssets(stablecoins, true);
            _assertStablecoinReadback(core4Mica, stablecoins);
            _configureOptionalAave(core4Mica, stablecoins);
        }
        vm.stopBroadcast();

        console.log("AccessManager deployed at:", address(manager));
        console.log("Core4Mica deployed at:", address(core4Mica));
        console.log("AccessManager admin:", managerAdmin);
        console.log("CREATE2 base salt:");
        console.logBytes32(baseSalt);
    }

    // helper to wrap selector into array
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
        address usdcAToken = vm.envOr("USDC_ATOKEN", address(0));
        address usdtAToken = vm.envOr("USDT_ATOKEN", address(0));

        if (
            (provider != address(0) || usdcAToken != address(0) || usdtAToken != address(0))
                && (!configureAave || provider == address(0) || usdcAToken == address(0) || usdtAToken == address(0))
        ) {
            revert PartialAaveConfiguration();
        }

        if (configureAave) {
            core4Mica.configureAave(provider, usdcAToken, usdtAToken);
            if (address(core4Mica.aaveAddressesProvider()) != provider) {
                revert AaveReadbackMismatch("provider");
            }
            if (core4Mica.stablecoinAToken(stablecoins[0]) != usdcAToken) {
                revert AaveReadbackMismatch("usdcAToken");
            }
            if (core4Mica.stablecoinAToken(stablecoins[1]) != usdtAToken) {
                revert AaveReadbackMismatch("usdtAToken");
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

        bool enableUsdcDeposits = vm.envOr("ENABLE_USDC_DEPOSITS", false);
        bool enableUsdtDeposits = vm.envOr("ENABLE_USDT_DEPOSITS", false);
        core4Mica.setStablecoinDepositsEnabled(stablecoins[0], enableUsdcDeposits);
        core4Mica.setStablecoinDepositsEnabled(stablecoins[1], enableUsdtDeposits);

        bool storedUsdcDepositsEnabled = core4Mica.stablecoinDepositsEnabled(stablecoins[0]);
        if (storedUsdcDepositsEnabled != enableUsdcDeposits) {
            revert StablecoinDepositsEnabledReadbackMismatch(
                stablecoins[0], enableUsdcDeposits, storedUsdcDepositsEnabled
            );
        }

        bool storedUsdtDepositsEnabled = core4Mica.stablecoinDepositsEnabled(stablecoins[1]);
        if (storedUsdtDepositsEnabled != enableUsdtDeposits) {
            revert StablecoinDepositsEnabledReadbackMismatch(
                stablecoins[1], enableUsdtDeposits, storedUsdtDepositsEnabled
            );
        }
    }
}
