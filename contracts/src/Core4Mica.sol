// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {AccessManaged} from "@openzeppelin/contracts/access/manager/AccessManaged.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/// @title Core4Mica
/// @notice Manages user collateral: deposits, locks by operators, withdrawals, and make-whole payouts.
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
    error DirectTransferNotAllowed();
    error DeregistrationPending();

    // ========= Storage =========
    uint256 public minCollateralAmount = 1 gwei;
    uint256 public gracePeriod = 1 days;

    struct User {
        uint256 totalCollateral;
        uint256 lockedCollateral;
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

    // ========= Modifiers =========
    modifier isRegistered(address userAddr) {
        if (users[userAddr].totalCollateral == 0) revert NotRegistered();
        _;
    }

    modifier nonZero(uint256 amount) {
        if (amount == 0) revert AmountZero();
        _;
    }

    modifier validRecipient(address recipient) {
        if (recipient == address(0)) revert TransferFailed();
        _;
    }

    modifier minCollateral(uint256 amount) {
        if (amount < minCollateralAmount) revert InsufficientFunds();
        _;
    }

    // ========= Admin / Manager configuration =========
    function setMinCollateralAmount(
        uint256 _minCollateralAmount
    ) external restricted {
        if (_minCollateralAmount == 0) revert AmountZero();
        minCollateralAmount = _minCollateralAmount;
        emit MinDepositUpdated(_minCollateralAmount);
    }

    function setGracePeriod(uint256 _gracePeriod) external restricted {
        if (_gracePeriod == 0) revert AmountZero();
        gracePeriod = _gracePeriod;
        emit GracePeriodUpdated(_gracePeriod);
    }

    // ========= User flows =========
    function registerUser()
        external
        payable
        nonReentrant
        minCollateral(msg.value)
    {
        if (users[msg.sender].totalCollateral != 0) revert AlreadyRegistered();
        users[msg.sender] = User({
            totalCollateral: msg.value,
            lockedCollateral: 0
        });
        emit UserRegistered(msg.sender, msg.value);
    }

    function addDeposit()
        external
        payable
        nonReentrant
        isRegistered(msg.sender)
        nonZero(msg.value)
        minCollateral(msg.value)
    {
        User storage user = users[msg.sender];
        user.totalCollateral += msg.value;
        emit CollateralDeposited(msg.sender, msg.value);
    }

    function withdrawCollateral(
        uint256 amount
    )
        external
        nonReentrant
        restricted
        nonZero(amount)
        isRegistered(msg.sender)
    {
        User storage user = users[msg.sender];
        if (user.totalCollateral - user.lockedCollateral < amount)
            revert InsufficientAvailable();

        user.totalCollateral -= amount;

        (bool ok, ) = payable(msg.sender).call{value: amount}("");
        if (!ok) revert TransferFailed();

        emit CollateralWithdrawn(msg.sender, amount);
    }

    function requestDeregistration()
        external
        restricted
        isRegistered(msg.sender)
    {
        deregistrationRequestedAt[msg.sender] = block.timestamp;
        emit DeregistrationRequested(msg.sender, block.timestamp);
    }

    function cancelDeregistration() external restricted {
        if (deregistrationRequestedAt[msg.sender] == 0)
            revert NoDeregistrationRequested();
        delete deregistrationRequestedAt[msg.sender];
        emit DeregistrationCanceled(msg.sender);
    }

    function finalizeDeregistration()
        external
        nonReentrant
        restricted
        isRegistered(msg.sender)
    {
        uint256 requestedAt = deregistrationRequestedAt[msg.sender];
        if (requestedAt == 0) revert NoDeregistrationRequested();
        if (block.timestamp < requestedAt + gracePeriod)
            revert GracePeriodNotElapsed();

        User storage user = users[msg.sender];
        if (user.lockedCollateral != 0) revert LockedCollateralNonZero();

        uint256 amount = user.totalCollateral;
        delete users[msg.sender];
        delete deregistrationRequestedAt[msg.sender];

        (bool ok, ) = payable(msg.sender).call{value: amount}("");
        if (!ok) revert TransferFailed();

        emit UserDeregistered(msg.sender, amount);
    }

    // ========= Operator / Manager flows =========
    function lockCollateral(
        address userAddr,
        uint256 amount
    ) external restricted nonZero(amount) isRegistered(userAddr) {
        if (deregistrationRequestedAt[userAddr] != 0) {
            revert DeregistrationPending();
        }
        User storage user = users[userAddr];
        if (user.totalCollateral - user.lockedCollateral < amount)
            revert InsufficientAvailable();
        user.lockedCollateral += amount;

        emit CollateralLocked(userAddr, amount);
    }

    function unlockCollateral(
        address userAddr,
        uint256 amount
    ) external restricted nonZero(amount) isRegistered(userAddr) {
        User storage user = users[userAddr];
        if (user.lockedCollateral < amount) revert InsufficientCollateral();
        user.lockedCollateral -= amount;

        emit CollateralUnlocked(userAddr, amount);
    }

    function makeWhole(
        address client,
        address recipient,
        uint256 amount
    )
        external
        restricted
        nonZero(amount)
        validRecipient(recipient)
        nonReentrant
        isRegistered(client)
    {
        User storage user = users[client];
        if (user.lockedCollateral < amount) revert DoubleSpendDetected();

        user.lockedCollateral -= amount;
        user.totalCollateral -= amount;

        (bool ok, ) = payable(recipient).call{value: amount}("");
        if (!ok) revert TransferFailed();

        emit RecipientMadeWhole(client, recipient, amount);
    }

    // ========= Views / Helpers =========
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

    function deregistrationTimestamp(
        address userAddr
    ) public view returns (uint256) {
        return deregistrationRequestedAt[userAddr];
    }

    // ========= Fallbacks =========
    receive() external payable {
        revert DirectTransferNotAllowed();
    }

    fallback() external payable {
        revert DirectTransferNotAllowed();
    }
}
