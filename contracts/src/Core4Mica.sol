// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {AccessManaged} from "@openzeppelin/contracts/access/manager/AccessManaged.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/// @title Core4Mica
/// @notice Manages user collateral: deposits, locks by operators, withdrawals, and make-whole payouts.
/// @dev Manager-only functions use {AccessManaged.restricted}. External calls follow CEI + ReentrancyGuard.
contract Core4Mica is AccessManaged, ReentrancyGuard {
    // ========= Errors =========
    error AlreadyRegistered();
    error NotRegistered();
    error AmountZero();
    error InsufficientFunds();
    error InsufficientAvailable();
    error InsufficientCollateral();
    error LockedCollateralNonZero();
    error TransferFailed();
    error GracePeriodNotElapsed();
    error NoDeregistrationRequested();
    error DoubleSpendDetected();

    // ========= Storage =========
    uint256 public minCollateralAmount = 1 gwei;
    uint256 public gracePeriod = 1 days;

    struct User {
        uint256 totalCollateral; // total deposited (available)
        uint256 lockedCollateral; // portion locked by operators
    }

    mapping(address => User) public users;
    mapping(address => uint256) public deregistrationRequestedAt;

    // ========= Events =========
    event UserRegistered(address indexed user, uint256 initialCollateral);
    event CollateralDeposited(address indexed user, uint256 amount);
    event CollateralLocked(address indexed user, uint256 amount);
    event CollateralUnlocked(address indexed user, uint256 amount);
    event RecipientMadeWhole(
        address indexed user,
        address indexed recipient,
        uint256 amount
    );
    event CollateralWithdrawn(address indexed user, uint256 amount);
    event DeregistrationRequested(address indexed user, uint256 when);
    event DeregistrationCanceled(address indexed user);
    event UserDeregistered(address indexed user, uint256 refundedAmount);
    event MinDepositUpdated(uint256 newMinDeposit);
    event GracePeriodUpdated(uint256 newGracePeriod);

    // ========= Constructor =========
    constructor(address manager) AccessManaged(manager) {}

    // ========= Admin / Manager configuration =========

    /// @notice Set the minimum deposit amount required for register/addDeposit.
    function setMinCollateralAmount(
        uint256 _minCollateralAmount
    ) external restricted {
        if (_minCollateralAmount == 0) revert AmountZero();
        minCollateralAmount = _minCollateralAmount;
        emit MinDepositUpdated(_minCollateralAmount);
    }

    /// @notice Set the deregistration grace period.
    function setGracePeriod(uint256 _gracePeriod) external restricted {
        if (_gracePeriod == 0) revert AmountZero();
        gracePeriod = _gracePeriod;
        emit GracePeriodUpdated(_gracePeriod);
    }

    // ========= User flows =========
    //TODO: do we need to keep track of registered users?
    /// @notice Register a new user by depositing ETH >= minCollateralAmount.
    function registerUser() external payable nonReentrant {
        if (msg.value < minCollateralAmount) revert InsufficientFunds();
        if (users[msg.sender].totalCollateral != 0) revert AlreadyRegistered();
        users[msg.sender] = User({
            totalCollateral: msg.value,
            lockedCollateral: 0
        });
        emit UserRegistered(msg.sender, msg.value);
    }

    /// @notice Add more collateral to an existing account.
    function addDeposit() external payable nonReentrant {
        if (msg.value == 0) revert AmountZero();
        User storage user = users[msg.sender];
        user.totalCollateral += msg.value;
        emit CollateralDeposited(msg.sender, msg.value);
    }

    /// @notice Withdraw from available collateral.
    /// @dev Only affects the caller's available & total; cannot withdraw locked amounts.
    function withdrawCollateral(
        uint256 amount
    ) external nonReentrant restricted {
        if (amount == 0) revert AmountZero();
        User storage user = users[msg.sender];
        if (user.totalCollateral == 0) revert NotRegistered();
        if (user.totalCollateral - user.lockedCollateral < amount)
            revert InsufficientAvailable();

        // Effects
        user.totalCollateral -= amount;

        // Interaction
        (bool ok, ) = payable(msg.sender).call{value: amount}("");
        if (!ok) revert TransferFailed();

        emit CollateralWithdrawn(msg.sender, amount);
    }

    /// @notice Request deregistration; must finalize after `gracePeriod` if no collateral is locked.
    function requestDeregistration() external restricted {
        User storage user = users[msg.sender];
        if (user.totalCollateral == 0) revert NotRegistered();
        deregistrationRequestedAt[msg.sender] = block.timestamp;
        emit DeregistrationRequested(msg.sender, block.timestamp);
    }

    /// @notice Cancel a pending deregistration request.
    function cancelDeregistration() external restricted {
        if (deregistrationRequestedAt[msg.sender] == 0)
            revert NoDeregistrationRequested();
        delete deregistrationRequestedAt[msg.sender];
        emit DeregistrationCanceled(msg.sender);
    }

    /// @notice Finalize deregistration after the grace period; requires no locked collateral.
    function finalizeDeregistration() external nonReentrant restricted {
        uint256 requestedAt = deregistrationRequestedAt[msg.sender];
        if (requestedAt == 0) revert NoDeregistrationRequested();
        if (block.timestamp < requestedAt + gracePeriod)
            revert GracePeriodNotElapsed();

        User storage user = users[msg.sender];
        if (user.lockedCollateral != 0) revert LockedCollateralNonZero();
        uint256 amount = user.totalCollateral;
        if (amount == 0) revert NotRegistered();

        // Effects
        delete users[msg.sender];
        delete deregistrationRequestedAt[msg.sender];

        // Interaction
        (bool ok, ) = payable(msg.sender).call{value: amount}("");
        if (!ok) revert TransferFailed();

        emit UserDeregistered(msg.sender, amount);
    }

    // ========= Operator / Manager flows =========

    /// @notice Lock a user's available collateral (e.g., after generating a certificate).
    /// @dev Manager/Operator-only. Does not transfer ETH; only internal accounting.
    function lockCollateral(
        address userAddr,
        uint256 amount
    ) external restricted {
        if (amount == 0) revert AmountZero();
        User storage user = users[userAddr];
        if (user.totalCollateral == 0) revert NotRegistered();
        if (user.totalCollateral - user.lockedCollateral < amount)
            revert InsufficientAvailable();
        user.lockedCollateral += amount;

        emit CollateralLocked(userAddr, amount);
    }

    /// @notice Unlock a user's locked collateral (e.g., if no longer needed).
    /// @dev Manager/Operator-only. Returns locked -> available.
    function unlockCollateral(
        address userAddr,
        uint256 amount
    ) external restricted {
        if (amount == 0) revert AmountZero();
        User storage user = users[userAddr];
        if (user.totalCollateral == 0) revert NotRegistered();
        if (user.lockedCollateral < amount) revert InsufficientCollateral();
        user.lockedCollateral -= amount;
        emit CollateralUnlocked(userAddr, amount);
    }

    /// @notice Pay a recipient from a user's locked collateral and reduce user's total collateral accordingly.
    /// @dev Manager-only. Performs ETH transfer. Uses CEI + nonReentrant.
    function makeWhole(
        address client,
        address recipient,
        uint256 amount
    ) external restricted nonReentrant {
        if (amount == 0) revert AmountZero();
        if (recipient == address(0)) revert TransferFailed();

        User storage user = users[client];
        if (user.totalCollateral == 0) revert DoubleSpendDetected();
        if (user.lockedCollateral < amount) revert DoubleSpendDetected();

        // Effects: locked decreases; total collateral decreases (funds leave the system)
        user.lockedCollateral -= amount;
        user.totalCollateral -= amount;
        (bool ok, ) = payable(recipient).call{value: amount}("");
        if (!ok) revert TransferFailed();

        emit RecipientMadeWhole(client, recipient, amount);
    }

    // ========= Views / Helpers =========

    /// @notice Returns the breakdown for a user.
    function getUser(
        address userAddr
    )
        external
        view
        returns (
            uint256 collateral,
            uint256 locked,
            uint256 available,
            uint256 deregRequestedAt
        )
    {
        User memory u = users[userAddr];
        collateral = u.totalCollateral;
        locked = u.lockedCollateral;
        available = u.totalCollateral - u.lockedCollateral;
        deregRequestedAt = deregistrationTimestamp(userAddr);
    }

    /// @notice Returns 0 if not requested.
    function deregistrationTimestamp(
        address userAddr
    ) public view returns (uint256) {
        return deregistrationRequestedAt[userAddr];
    }

    // ========= Fallbacks =========

    /// @dev Prevent accidental ETH sends; deposits must go through functions.
    receive() external payable {
        revert InsufficientFunds();
    }

    fallback() external payable {
        revert InsufficientFunds();
    }
}
