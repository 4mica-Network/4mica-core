// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import "forge-std/Script.sol";
import "../src/Core4Mica.sol";
import {AccessManager} from "@openzeppelin/contracts/access/manager/AccessManager.sol";

contract Core4MicaScript is Script {
    AccessManager manager;

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

        vm.startBroadcast(deployerPrivateKey);

        // 1. Deploy AccessManager and Core4Mica
        manager = new AccessManager(deployer);
        Core4Mica core4Mica = new Core4Mica(address(manager));

        // 2. Map Core4Mica functions to roles
        // User-facing functions → USER_ROLE
        bytes4[] memory userSelectors = new bytes4[](5);
        userSelectors[0] = Core4Mica.addDeposit.selector;
        userSelectors[1] = Core4Mica.withdrawCollateral.selector;
        userSelectors[2] = Core4Mica.requestDeregistration.selector;
        userSelectors[3] = Core4Mica.cancelDeregistration.selector;
        userSelectors[4] = Core4Mica.finalizeDeregistration.selector;
        for (uint256 i = 0; i < userSelectors.length; i++) {
            manager.setTargetFunctionRole(
                address(core4Mica),
                _asSingletonArray(userSelectors[i]),
                USER_ROLE
            );
        }

        // Operator functions → OPERATOR_ROLE
        bytes4[] memory operatorSelectors = new bytes4[](3);
        operatorSelectors[0] = Core4Mica.lockCollateral.selector;
        operatorSelectors[1] = Core4Mica.unlockCollateral.selector;
        operatorSelectors[2] = Core4Mica.makeWhole.selector;
        for (uint256 i = 0; i < operatorSelectors.length; i++) {
            manager.setTargetFunctionRole(
                address(core4Mica),
                _asSingletonArray(operatorSelectors[i]),
                OPERATOR_ROLE
            );
        }

        // Admin-only config functions → USER_ADMIN_ROLE
        manager.setTargetFunctionRole(
            address(core4Mica),
            _asSingletonArray(Core4Mica.setGracePeriod.selector),
            USER_ADMIN_ROLE
        );

        // 3. Grant roles (immediate in local/test: 0 delay)
        manager.grantRole(USER_ROLE, deployer, 0); // deployer can act as USER
        manager.grantRole(OPERATOR_ROLE, deployer, 0); // deployer can act as OPERATOR

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
