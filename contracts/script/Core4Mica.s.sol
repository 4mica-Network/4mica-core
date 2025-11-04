// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import "forge-std/Script.sol";
import "../src/Core4Mica.sol";
import {AccessManager} from "@openzeppelin/contracts/access/manager/AccessManager.sol";
import {BLS} from "@solady/src/utils/ext/ithaca/BLS.sol";

contract Core4MicaScript is Script {
    AccessManager manager;
    bytes4 private constant RECORD_PAYMENT_SELECTOR =
        bytes4(keccak256("recordPayment(uint256,address,uint256)"));
    bytes4 private constant SET_TIMING_PARAMETERS_SELECTOR =
        bytes4(
            keccak256("setTimingParameters(uint256,uint256,uint256,uint256)")
        );

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
        address usdc = vm.envAddress("USDC_TOKEN");
        address usdt = vm.envAddress("USDT_TOKEN");
        require(
            usdc != address(0) && usdt != address(0),
            "Stablecoin addresses required"
        );

        BLS.G1Point memory guaranteeVerificationKey = BLS.G1Point({
            x_a: vm.envBytes32("VK_X0"),
            x_b: vm.envBytes32("VK_X1"),
            y_a: vm.envBytes32("VK_Y0"),
            y_b: vm.envBytes32("VK_Y1")
        });

        vm.startBroadcast(deployerPrivateKey);

        // 1. Deploy AccessManager and Core4Mica
        manager = new AccessManager(deployer);
        Core4Mica core4Mica = new Core4Mica(
            address(manager),
            guaranteeVerificationKey,
            usdc,
            usdt
        );

        // 2. Map Core4Mica functions to roles
        // Operator functions → OPERATOR_ROLE
        manager.setTargetFunctionRole(
            address(core4Mica),
            _asSingletonArray(RECORD_PAYMENT_SELECTOR),
            OPERATOR_ROLE
        );

        // Admin-only config functions → USER_ADMIN_ROLE
        bytes4[] memory adminSelectors = new bytes4[](7);
        adminSelectors[0] = Core4Mica.setWithdrawalGracePeriod.selector;
        adminSelectors[1] = Core4Mica.setRemunerationGracePeriod.selector;
        adminSelectors[2] = Core4Mica.setTabExpirationTime.selector;
        adminSelectors[3] = Core4Mica.setGuaranteeVerificationKey.selector;
        adminSelectors[4] = SET_TIMING_PARAMETERS_SELECTOR;
        adminSelectors[5] = Core4Mica.setSynchronizationDelay.selector;
        adminSelectors[6] = Core4Mica.configureGuaranteeVersion.selector;
        for (uint256 i = 0; i < adminSelectors.length; i++) {
            manager.setTargetFunctionRole(
                address(core4Mica),
                _asSingletonArray(adminSelectors[i]),
                USER_ADMIN_ROLE
            );
        }

        // 3. Grant roles (immediate in local/test: 0 delay)
        manager.grantRole(OPERATOR_ROLE, deployer, 0); // deployer can act as OPERATOR
        manager.grantRole(USER_ADMIN_ROLE, deployer, 0); // deployer can manage OPERATORs
        vm.stopBroadcast();

        console.log("AccessManager deployed at:", address(manager));
        console.log("Core4Mica deployed at:", address(core4Mica));
    }

    // helper to wrap selector into array
    function _asSingletonArray(
        bytes4 selector
    ) internal pure returns (bytes4[] memory arr) {
        arr = new bytes4[](1);
        arr[0] = selector;
    }
}
