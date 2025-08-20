// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import "forge-std/Script.sol";
import "forge-std/StdJson.sol";
import "forge-std/Test.sol";
import "forge-std/console.sol";

import "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";

import "@eigenlayer/contracts/permissions/PauserRegistry.sol";
import {IDelegationManager} from "@eigenlayer/contracts/interfaces/IDelegationManager.sol";
import {IAVSDirectory} from "@eigenlayer/contracts/interfaces/IAVSDirectory.sol";
import {ISlasher} from "@eigenlayer/contracts/interfaces/ISlasher.sol";
import {IStrategy, IStrategyManager} from "@eigenlayer/contracts/interfaces/IStrategyManager.sol";
import {StrategyBaseTVLLimits} from "@eigenlayer/contracts/strategies/StrategyBaseTVLLimits.sol";
import {StrategyFactory} from "@eigenlayer/contracts/strategies/StrategyFactory.sol";

import "@eigenlayer/test/mocks/EmptyContract.sol";

import "@eigenlayer-middleware/src/OperatorStateRetriever.sol";
import "@eigenlayer-middleware/src/RegistryCoordinator.sol" as regcoord;
import {BLSApkRegistry} from "@eigenlayer-middleware/src/BLSApkRegistry.sol";
import {IBLSApkRegistry, IIndexRegistry, IStakeRegistry} from "@eigenlayer-middleware/src/RegistryCoordinator.sol";
import {IndexRegistry} from "@eigenlayer-middleware/src/IndexRegistry.sol";
import {StakeRegistry} from "@eigenlayer-middleware/src/StakeRegistry.sol";

import {ServiceManager4Mica, IServiceManager} from "../../src/ServiceManager4Mica.sol";
import {ContractsRegistry} from "../src/ContractsRegistry.sol";
import "../src/MockERC20.sol";

import {DeploymentLib4Mica} from "../script/utils/DeploymentLib4Mica.sol";
import {CoreDeploymentLib} from "../utils/CoreDeploymentLib.sol";
import {UpgradeableProxyLib} from "../utils/UpgradeableProxyLib.sol";
import {FundOperator} from "../utils/FundOperator.sol";

contract Deployer4Mica is Script {
    // DEPLOYMENT CONSTANTS
    address public AGGREGATOR_ADDR;
    address public TASK_GENERATOR_ADDR;
    address public CONTRACTS_REGISTRY_ADDR;
    address public OPERATOR_ADDR;
    address public OPERATOR_2_ADDR;
    ContractsRegistry contractsRegistry;

    StrategyBaseTVLLimits public erc20MockStrategy;

    address public rewardscoordinator;

    ProxyAdmin public proxyAdmin4Mica;
    PauserRegistry public pauserRegistry4Mica;

    regcoord.RegistryCoordinator public registryCoordinator;
    regcoord.IRegistryCoordinator public registryCoordinatorImplementation;

    IBLSApkRegistry public blsApkRegistry;
    IBLSApkRegistry public blsApkRegistryImplementation;

    IIndexRegistry public indexRegistry;
    IIndexRegistry public indexRegistryImplementation;

    IStakeRegistry public stakeRegistry;
    IStakeRegistry public stakeRegistryImplementation;

    OperatorStateRetriever public operatorStateRetriever;

    ServiceManager4Mica public serviceManager4Mica;
    IServiceManager public serviceManagerImplementation4Mica;

    CoreDeploymentLib.DeploymentData internal configData;
    IStrategy strategy4Mica;
    address private deployer;
    MockERC20 public erc20Mock;
    DeploymentLib4Mica.DeploymentData deployment4Mica;

    using UpgradeableProxyLib for address;

    address proxyAdmin;

    function setUp() public virtual {
        deployer = vm.rememberKey(vm.envUint("PRIVATE_KEY"));
        vm.label(deployer, "Deployer");
    }

    function run() external {
        vm.startBroadcast(deployer);

        DeploymentLib4Mica.SetupConfig4Mica memory isConfig = DeploymentLib4Mica.read4MicaConfigJson("4mica_config");

        configData = CoreDeploymentLib.readDeploymentJson("script/deployments/core/", block.chainid);

        erc20Mock = new MockERC20();
        FundOperator.fund_operator(address(erc20Mock), isConfig.operator_addr, 15000e18);
        FundOperator.fund_operator(address(erc20Mock), isConfig.operator_2_addr, 30000e18);
        console.log(isConfig.operator_2_addr);
        (bool s,) = isConfig.operator_2_addr.call{value: 0.1 ether}("");
        require(s);
        console.log(isConfig.operator_2_addr.balance);

        strategy4Mica = IStrategy(StrategyFactory(configData.strategyFactory).deployNewStrategy(erc20Mock));
        rewardscoordinator = configData.rewardsCoordinator;

        proxyAdmin = UpgradeableProxyLib.deployProxyAdmin();
        require(address(strategy4Mica) != address(0));
        require(address(strategy4Mica) != address(0));

        deployment4Mica =
            DeploymentLib4Mica.deployContracts(proxyAdmin, configData, address(strategy4Mica), isConfig, msg.sender);

        FundOperator.fund_operator(address(erc20Mock), deployment4Mica.serviceManager4Mica, 1e18);

        DeploymentLib4Mica.writeDeploymentJson(deployment4Mica);

        vm.stopBroadcast();
    }
}
