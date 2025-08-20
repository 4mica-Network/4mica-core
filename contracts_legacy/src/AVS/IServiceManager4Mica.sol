// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IBLSSignatureChecker} from "eigenlayer-middleware/src/interfaces/IBLSSignatureChecker.sol";

interface IServiceManager4Mica {
    event NewTask(address senderAddress, Task task);

    event TaskCompleted(TaskResponse taskResponse, TaskResponseMetadata taskResponseMetadata);

    //Structs
    struct Task {
        bytes32 transactionHash;
        uint32 taskCreatedBlock;
        bytes quorumNumbers;
    }

    struct TaskResponse {
        bytes32[3] blsCertificate;
        address senderAddress;
    }

    struct TaskResponseMetadata {
        uint32 taskResponsedBlock;
        bytes32 hashOfNonSigners;
    }

    event OperatorDisabled(uint8 indexed operatorIdx);
    event OperatorEnabled(uint8 indexed operatorIdx);

    // @notice Thrown when a transaction hash does not match the expected or valid hash
    error InvalidTransaction(bytes32 transactionHash);

    error TaskDoesNotExist(bytes32 taskIdentifier);
    error TaskAlreadySubmitted(bytes32 taskIdentifier);
    error TaskAlreadyResponded(bytes32 taskIdentifier);
    error TaskAlreadyExists(bytes32 taskIdentifier);
    error InvalidAddress(string param);
    error InvalidQuorumThreshold(uint256 signedStake, uint256 requiredStake);

    function createNewTask(bytes32 transactionHash, bytes calldata quorumNumbers) external;

    /**
     * @notice Returns the current task number
     */
    function taskNumber() external view returns (uint32);

    function respondToTask(
        TaskResponse calldata taskResponse,
        IBLSSignatureChecker.NonSignerStakesAndSignature memory nonSignerStakesAndSignature
    ) external;
}
