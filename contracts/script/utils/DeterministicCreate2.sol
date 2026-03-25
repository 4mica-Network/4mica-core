// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

/// @notice Deterministic deployment helper using the well-known CREATE2 deployer at `0x4e59...`.
/// @dev Reuses already deployed bytecode at the predicted address, making scripts idempotent.
library DeterministicCreate2 {
    /// @dev EIP-2470 singleton CREATE2 deployer.
    address internal constant CREATE2_DEPLOYER = 0x4e59b44847b379578588920cA78FbF26c0B4956C;

    error Create2DeployerMissing(address deployer);
    error Create2DeploymentFailed(bytes32 salt, bytes32 initCodeHash, bytes reason);
    error Create2DeploymentNotFound(bytes32 salt, bytes32 initCodeHash, address expected);

    function computeAddress(bytes32 salt, bytes32 initCodeHash) internal pure returns (address) {
        bytes32 digest = keccak256(abi.encodePacked(bytes1(0xff), CREATE2_DEPLOYER, salt, initCodeHash));
        return address(uint160(uint256(digest)));
    }

    function deploy(bytes32 salt, bytes memory initCode) internal returns (address deployed) {
        bytes32 initCodeHash = keccak256(initCode);
        deployed = computeAddress(salt, initCodeHash);
        if (deployed.code.length > 0) {
            return deployed;
        }
        if (CREATE2_DEPLOYER.code.length == 0) {
            revert Create2DeployerMissing(CREATE2_DEPLOYER);
        }

        // Deterministic deployment proxy ABI is raw bytes:
        // calldata = salt (32 bytes) ++ init_code.
        bytes memory payload = abi.encodePacked(salt, initCode);
        (bool ok, bytes memory reason) = CREATE2_DEPLOYER.call(payload);
        if (!ok) {
            revert Create2DeploymentFailed(salt, initCodeHash, reason);
        }
        if (deployed.code.length == 0) {
            revert Create2DeploymentNotFound(salt, initCodeHash, deployed);
        }
    }
}
