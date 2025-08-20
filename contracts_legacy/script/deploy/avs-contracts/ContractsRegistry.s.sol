// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Script} from "forge-std/Script.sol";

import {CoreDeploymentLib} from "../utils/CoreDeploymentLib.sol";
import {DeploymentLib4Mica} from "../utils/DeploymentLib4Mica.sol";
import {WriteToContractsRegistryLib} from "../utils/WriteToContractsRegistryLib.sol";

contract ContractsRegistry is Script {
    address private deployer;
    address public CONTRACT_REGISTRY;
    CoreDeploymentLib.DeploymentData coreConfigData;
    DeploymentLib4Mica.DeploymentData avsConfigData;

    function setUp() public {
        deployer = vm.rememberKey(vm.envUint("PRIVATE_KEY"));
        vm.label(deployer, "Deployer");
        CONTRACT_REGISTRY = vm.envAddress("CONTRACTS_REGISTRY_ADDR");

        coreConfigData = CoreDeploymentLib.readDeploymentJson("script/deployments/core/", "31337.json");
        avsConfigData = DeploymentLib4Mica.readDeploymentJson("script/deployments/4mica/", block.chainid);
    }

    function run() external {
        vm.startBroadcast(deployer);
        if (block.chainid == 31337 || block.chainid == 1337) {
            WriteToContractsRegistryLib.writeCoreContractsToRegistry(CONTRACT_REGISTRY, coreConfigData);
            WriteToContractsRegistryLib.write4MicaContractsToRegistry(CONTRACT_REGISTRY, avsConfigData);
        }
        vm.stopBroadcast();
    }
}
