// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IServiceManager4Mica} from "./IServiceManager4Mica.sol";
import {BLSSignatureChecker} from "eigenlayer-middleware/src/BLSSignatureChecker.sol";
import {IBLSSignatureChecker} from "eigenlayer-middleware/src/interfaces/IBLSSignatureChecker.sol";
import {IStakeRegistry} from "eigenlayer-middleware/src/interfaces/IStakeRegistry.sol";
import {IRegistryCoordinator} from "eigenlayer-middleware/src/interfaces/IRegistryCoordinator.sol";
import {ServiceManagerBase, IAVSDirectory} from "eigenlayer-middleware/src/ServiceManagerBase.sol";
import {IRewardsCoordinator} from "eigenlayer-contracts/src/contracts/interfaces/IRewardsCoordinator.sol";
import {ISlashingRegistryCoordinator} from "eigenlayer-middleware/src/interfaces/ISlashingRegistryCoordinator.sol";
import {IPermissionController} from "eigenlayer-contracts/src/contracts/interfaces/IPermissionController.sol";
import {IAllocationManager} from "eigenlayer-contracts/src/contracts/interfaces/IAllocationManager.sol";
import {Pausable} from "eigenlayer-core/contracts/permissions/Pausable.sol";
import {IPauserRegistry} from "@eigenlayer/contracts/interfaces/IPauserRegistry.sol";


/**
 * @title Service Manager of 4Mica operators
 */
contract ServiceManager4Mica is IServiceManager4Mica, ServiceManagerBase, BLSSignatureChecker, Pausable {
    // Storage
    uint64 public latestTaskNum;
    mapping(uint64 => bytes32) public taskList;
    mapping(bytes32 => Task) public taskStateByHash;
    mapping(address => bool) public operatorRegistered;
    mapping(uint32 => bytes32) public taskResponses;
    mapping(uint32 => bytes32) public allTaskResponses;
    address public aggregator;

    uint256 internal constant THRESHOLD_DENOMINATOR = 100;
    uint8 internal constant QUORUM_THRESHOLD_PERCENTAGE = 67;

    // Modifiers
    modifier onlyAggregator() {
        require(msg.sender == aggregator, "Aggregator must be the caller");
        _;
    }

    constructor(
        IAVSDirectory __avsDirectory,
        IRewardsCoordinator __rewardsCoordinator,
        IRegistryCoordinator __registryCoordinator,
        IStakeRegistry __stakeRegistry
    )
        // IPermissionController __permissionController,
        // IAllocationManager __allocationManager
        BLSSignatureChecker(__registryCoordinator)
        ServiceManagerBase(__avsDirectory, __rewardsCoordinator, __registryCoordinator, __stakeRegistry)
    {
        if (
            address(__avsDirectory) == address(0) || address(__rewardsCoordinator) == address(0)
                || address(__registryCoordinator) == address(0) || address(__stakeRegistry) == address(0)
        ) {
            revert InvalidAddress("One or more constructor arguments are zero address");
        }
        _disableInitializers();
    }

    function initialize(
        address _initialOwner,
        address _rewardsInitiator,
        address _aggregator,
        IPauserRegistry _pauserRegistry
    ) public initializer {
        if (_initialOwner == address(0)) {
            revert InvalidAddress("initialOwner");
        }
        if (_rewardsInitiator == address(0)) {
            revert InvalidAddress("rewardsInitiator");
        }
        _initializePauser(_pauserRegistry, UNPAUSE_ALL);
        __ServiceManagerBase_init(_initialOwner, _rewardsInitiator);
        _transferOwnership(_initialOwner);
        aggregator = _aggregator;
    }

    function createNewTask(bytes32 transactionHash, bytes calldata quorumNumbers) external {
        bytes32 hash = keccak256(abi.encode(transactionHash, block.number, quorumNumbers));
        if (taskStateByHash[transactionHash].taskCreatedBlock != 0) {
            revert TaskAlreadyExists(transactionHash);
        }

        Task memory newTask = Task({
            transactionHash: transactionHash,
            taskCreatedBlock: uint32(block.number),
            quorumNumbers: quorumNumbers
        });

        taskList[latestTaskNum] = keccak256(abi.encode(newTask));
        taskStateByHash[transactionHash] = newTask;

        emit NewTask(msg.sender, newTask);
        latestTaskNum++;
    }

    function taskNumber() external view returns (uint32) {
        return latestTaskNum;
    }

    function respondToTask(
        Task calldata task,
        TaskResponse calldata taskResponse,
        IBLSSignatureChecker.NonSignerStakesAndSignature memory nonSignerStakesAndSignature
    ) external {
        uint32 taskCreatedBlock = task.taskCreatedBlock;
        bytes calldata quorumNumbers = task.quorumNumbers;

        require(
            keccak256(abi.encode(task)) == taskList[taskResponse.referenceTaskIndex],
            "supplied task does not match the one recorded in the contract"
        );

        require(
            allTaskResponses[taskResponse.referenceTaskIndex] == bytes32(0),
            "Aggregator has already responded to the task"
        );

        bytes32 messageHash = keccak256(abi.encode(taskResponse));

        // Validate aggregated BLS signature
        (QuorumStakeTotals memory quorumStakeTotals, bytes32 hashOfNonSigners) =
            checkSignatures(messageHash, quorumNumbers, taskCreatedBlock, nonSignerStakesAndSignature);

        for (uint256 i = 0; i < quorumNumbers.length; i++) {
            if (
                quorumStakeTotals.signedStakeForQuorum[i] * THRESHOLD_DENOMINATOR
                    < quorumStakeTotals.totalStakeForQuorum[i] * QUORUM_THRESHOLD_PERCENTAGE
            ) {
                revert InvalidQuorumThreshold(
                    quorumStakeTotals.signedStakeForQuorum[i] * THRESHOLD_DENOMINATOR,
                    quorumStakeTotals.totalStakeForQuorum[i] * QUORUM_THRESHOLD_PERCENTAGE
                );
            }
        }

        TaskResponseMetadata memory metadata = TaskResponseMetadata(uint32(block.number), hashOfNonSigners);

        allTaskResponses[taskResponse.referenceTaskIndex] = keccak256(abi.encode(taskResponse, metadata));
        emit TaskCompleted(taskResponse, metadata);
    }
}
