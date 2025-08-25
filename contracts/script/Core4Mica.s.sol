// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import "forge-std/Script.sol";
import "../src/Core4Mica.sol";

contract Core4MicaScript is Script {
    function run() external {
        // Load deployer private key from environment
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);

        vm.startBroadcast(deployerPrivateKey);

        // Deploy Core4Mica with deployer as manager
        Core4Mica core4Mica = new Core4Mica(deployer);

        vm.stopBroadcast();

        console.log("Core4Mica deployed at:", address(core4Mica));
    }
}
