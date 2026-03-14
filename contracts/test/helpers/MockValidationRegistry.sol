// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {IValidationRegistry} from "../../src/interfaces/IValidationRegistry.sol";

contract MockValidationRegistry is IValidationRegistry {
    struct Status {
        address validatorAddress;
        uint256 agentId;
        uint8 response;
        bytes32 responseHash;
        string tag;
        uint256 lastUpdate;
        bool exists;
    }

    mapping(bytes32 => Status) private statuses;
    bool public shouldRevert;

    function setShouldRevert(bool value) external {
        shouldRevert = value;
    }

    function setStatus(
        bytes32 requestHash,
        address validatorAddress,
        uint256 agentId,
        uint8 response,
        bytes32 responseHash,
        string calldata tag,
        uint256 lastUpdate
    ) external {
        statuses[requestHash] = Status({
            validatorAddress: validatorAddress,
            agentId: agentId,
            response: response,
            responseHash: responseHash,
            tag: tag,
            lastUpdate: lastUpdate,
            exists: true
        });
    }

    function getValidationStatus(bytes32 requestHash)
        external
        view
        override
        returns (
            address validatorAddress,
            uint256 agentId,
            uint8 response,
            bytes32 responseHash,
            string memory tag,
            uint256 lastUpdate
        )
    {
        if (shouldRevert) {
            revert("mock-registry-revert");
        }

        Status storage s = statuses[requestHash];
        if (!s.exists) {
            return (address(0), 0, 0, bytes32(0), "", 0);
        }
        return (s.validatorAddress, s.agentId, s.response, s.responseHash, s.tag, s.lastUpdate);
    }
}
