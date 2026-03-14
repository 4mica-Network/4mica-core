// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

interface IValidationRegistry {
    function getValidationStatus(bytes32 requestHash)
        external
        view
        returns (
            address validatorAddress,
            uint256 agentId,
            uint8 response,
            bytes32 responseHash,
            string memory tag,
            uint256 lastUpdate
        );
}
