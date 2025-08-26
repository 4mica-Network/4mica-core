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

    // Execution delays
    uint32 public constant CALLER_ROLE_EXECUTION_DELAY = 5 hours;
    uint32 public constant CALLER_ADMIN_ROLE_EXECUTION_DELAY = 8 hours;

    uint32 public constant USER_ROLE_EXECUTION_DELAY = 2 hours;
    uint32 public constant USER_ADMIN_ROLE_EXECUTION_DELAY = 6 hours;

    uint32 public constant AGGREGATOR_ROLE_EXECUTION_DELAY = 4 hours;
    uint32 public constant AGGREGATOR_ADMIN_ROLE_EXECUTION_DELAY = 12 hours;

    uint32 public constant OPERATOR_ROLE_EXECUTION_DELAY = 3 hours;
    uint32 public constant OPERATOR_ADMIN_ROLE_EXECUTION_DELAY = 10 hours;

    function run() external {
        // Load deployer private key from environment
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);
        manager = new AccessManager(deployer);
        vm.startBroadcast(deployerPrivateKey);

        // Deploy Core4Mica with deployer as manager
        Core4Mica core4Mica = new Core4Mica(address(manager));

        vm.stopBroadcast();

        console.log("Core4Mica deployed at:", address(core4Mica));
    }
}
