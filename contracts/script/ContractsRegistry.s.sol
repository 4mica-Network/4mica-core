// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.12;

import {Script} from "forge-std/Script.sol";

import {CoreDeploymentLib} from "./utils/CoreDeploymentLib.sol";
import {FourMicaDeploymentLib} from "./utils/FourMicaDeploymentLib.sol";
import {WriteToContractsRegistryLib} from "./utils/WriteToContractsRegistryLib.sol";

contract ContractsRegistry is Script {
    address private deployer;
    address public CONTRACT_REGISTRY;
    CoreDeploymentLib.DeploymentData coreConfigData;
    FourMicaDeploymentLib.DeploymentData avsConfigData;

    function setUp() public {
        deployer = vm.rememberKey(vm.envUint("PRIVATE_KEY"));
        vm.label(deployer, "Deployer");
        CONTRACT_REGISTRY = vm.envAddress("CONTRACTS_REGISTRY_ADDR");

        coreConfigData = CoreDeploymentLib.readDeploymentJson("script/deployments/core/", "31337.json");
        avsConfigData =
            FourMicaDeploymentLib.readDeploymentJson("script/deployments/fourmica/", block.chainid);
    }

    function run() external {
        vm.startBroadcast(deployer);
        if (block.chainid == 31337 || block.chainid == 1337) {
            WriteToContractsRegistryLib.writeCoreContractsToRegistry(CONTRACT_REGISTRY, coreConfigData);
            WriteToContractsRegistryLib.writeFourMicaContractsToRegistry(CONTRACT_REGISTRY, avsConfigData);
        }
        vm.stopBroadcast();
    }
}
