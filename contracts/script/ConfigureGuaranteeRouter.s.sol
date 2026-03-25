// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import "forge-std/Script.sol";
import {GuaranteeDecoderRouter} from "../src/GuaranteeDecoderRouter.sol";

/// @notice Configures a version module in GuaranteeDecoderRouter and optionally freezes it.
/// @dev Required env vars:
/// - DEPLOYER_PRIVATE_KEY
/// - GUARANTEE_ROUTER_ADDRESS
/// - GUARANTEE_VERSION
/// - GUARANTEE_MODULE_ADDRESS
/// Optional env vars:
/// - GUARANTEE_FREEZE_VERSION (bool, default false)
contract ConfigureGuaranteeRouterScript is Script {
    error InvalidRouterAddress(address router);
    error InvalidVersion(uint64 version);
    error InvalidModuleAddress(address module);
    error ReadbackMismatch(string field);

    function run() external {
        uint256 deployerPrivateKey = vm.envUint("DEPLOYER_PRIVATE_KEY");
        address routerAddress = vm.envAddress("GUARANTEE_ROUTER_ADDRESS");
        if (routerAddress == address(0)) revert InvalidRouterAddress(routerAddress);
        GuaranteeDecoderRouter router = GuaranteeDecoderRouter(routerAddress);

        uint64 version = uint64(vm.envUint("GUARANTEE_VERSION"));
        if (version == 0) revert InvalidVersion(version);
        address module = vm.envAddress("GUARANTEE_MODULE_ADDRESS");
        if (module == address(0)) revert InvalidModuleAddress(module);
        bool freezeVersion = vm.envOr("GUARANTEE_FREEZE_VERSION", false);

        vm.startBroadcast(deployerPrivateKey);
        router.setVersionModule(version, module);
        if (freezeVersion) {
            router.freezeVersion(version);
        }
        vm.stopBroadcast();

        address storedModule = router.moduleByVersion(version);
        bool frozen = router.isVersionFrozen(version);

        if (storedModule != module) revert ReadbackMismatch("moduleByVersion");
        if (freezeVersion && !frozen) revert ReadbackMismatch("isVersionFrozen");

        console.log("Configured guarantee router:");
        console.log("Router:", routerAddress);
        console.log("Version:", version);
        console.log("Module:", storedModule);
        console.log("Frozen:", frozen);
    }
}
