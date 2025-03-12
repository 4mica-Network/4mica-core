// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "../src/MyContract.sol";

contract DeployScript is Script {
    function run() external {
        // Start broadcasting the transaction
        vm.startBroadcast();

        // Deploy the contract
        MyContract deployed = new MyContract();

        // Log the deployed contract address
        console.log("Contract deployed at:", address(deployed));

        // Stop broadcasting the transaction
        vm.stopBroadcast();
    }
}
