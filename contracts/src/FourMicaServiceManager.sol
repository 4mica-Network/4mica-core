// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.9;

import "@eigenlayer/contracts/libraries/BytesLib.sol";
import "./IFourMicaTaskManager.sol";
import "@eigenlayer-middleware/src/ServiceManagerBase.sol";

import {IRewardsCoordinator} from "@eigenlayer/contracts/interfaces/IRewardsCoordinator.sol";

/**
 * @title Primary entrypoint for procuring services from FourMica.
 * @author Layr Labs, Inc.
 */
contract FourMicaServiceManager is ServiceManagerBase {
    using BytesLib for bytes;

    IFourMicaTaskManager public immutable fourMicaTaskManager;

    /// @notice when applied to a function, ensures that the function is only callable by the `registryCoordinator`.
    modifier onlyFourMicaTaskManager() {
        require(
            msg.sender == address(fourMicaTaskManager),
            "onlyFourMicaTaskManager: not from credible squaring task manager"
        );
        _;
    }

    constructor(
        IAVSDirectory _avsDirectory,
        IRegistryCoordinator _registryCoordinator,
        IStakeRegistry _stakeRegistry,
        address rewards_coordinator,
        IFourMicaTaskManager _fourMicaTaskManager
    )
        ServiceManagerBase(_avsDirectory, IRewardsCoordinator(rewards_coordinator), _registryCoordinator, _stakeRegistry)
    {
        fourMicaTaskManager = _fourMicaTaskManager;
    }

    function initialize(address initialOwner, address rewardsInitiator) public initializer {
        __ServiceManagerBase_init(initialOwner, rewardsInitiator);
    }

    /// @notice Called in the event of challenge resolution, in order to forward a call to the Slasher, which 'freezes' the `operator`.
    /// @dev The Slasher contract is under active development and its interface expected to change.
    ///      We recommend writing slashing logic without integrating with the Slasher at this point in time.
    function freezeOperator(address operatorAddr) external onlyFourMicaTaskManager {
        // slasher.freezeOperator(operatorAddr);
    }
}
