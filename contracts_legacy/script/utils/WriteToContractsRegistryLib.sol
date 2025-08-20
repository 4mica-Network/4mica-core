// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.12;

import {Vm} from "forge-std/Vm.sol";
import {ContractsRegistry} from "../../src/ContractsRegistry.sol";
import {CoreDeploymentLib} from "./CoreDeploymentLib.sol";
import {DeploymentLib4Mica} from "./DeploymentLib4Mica.sol";

library WriteToContractsRegistryLib {
    function writeCoreContractsToRegistry(
        address contracts_registry_addr,
        CoreDeploymentLib.DeploymentData memory deploymentdata
    ) internal {
        ContractsRegistry contractsRegistry = ContractsRegistry(contracts_registry_addr);
        contractsRegistry.registerContract("delegationManager", address(deploymentdata.delegationManager));
        contractsRegistry.registerContract("strategyManager", address(deploymentdata.strategyManager));
        contractsRegistry.registerContract("avsDirectory", address(deploymentdata.avsDirectory));
    }

    function write4MicaContractsToRegistry(
        address contracts_registry_addr,
        DeploymentLib4Mica.DeploymentData memory deploymentdata
    ) internal {
        ContractsRegistry contractsRegistry = ContractsRegistry(contracts_registry_addr);

        contractsRegistry.registerContract("4mica_service_manager", address(deploymentdata.serviceManager4Micar));
        contractsRegistry.registerContract("erc20MockStrategy", address(deploymentdata.strategy));
        contractsRegistry.registerContract("4mica_registry_coordinator", address(deploymentdata.registryCoordinator));
        contractsRegistry.registerContract(
            "4mica_operator_state_retriever", address(deploymentdata.operatorStateRetriever)
        );
    }
}
