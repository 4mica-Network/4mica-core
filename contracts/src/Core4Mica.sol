// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {AccessManaged} from "@openzeppelin/contracts/access/manager/AccessManaged.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/// @title Core4Mica
/// @notice Manages user collateral: deposits, locks by operators, withdrawals, and make-whole payouts.
contract Core4Mica is AccessManaged, ReentrancyGuard {
    // ========= Errors =========
    error NotRegistered();
    error AmountZero();
    error InsufficientAvailable();
    error TransferFailed();
    error GracePeriodNotElapsed();
    error NoDeregistrationRequested();
    error DirectTransferNotAllowed();

    // ========= Storage =========
    uint256 public gracePeriod = 1 days;

    struct User {
        uint256 totalCollateral;
    }

    mapping(address => User) public users;
    mapping(address => uint256) public deregistrationRequestedAt;

    // ========= Events =========
    event UserRegistered(address indexed user, uint256 initialCollateral);
    event CollateralDeposited(address indexed user, uint256 amount);
    event RecipientMadeWhole(
        address indexed user,
        address indexed recipient,
        uint256 amount
    );
    event CollateralWithdrawn(address indexed user, uint256 amount);
    event DeregistrationRequested(address indexed user, uint256 when);
    event DeregistrationCanceled(address indexed user);
    event UserDeregistered(address indexed user, uint256 refundedAmount);
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

    // ========= Admin / Manager configuration =========
    function setGracePeriod(uint256 _gracePeriod) external restricted {
        if (_gracePeriod == 0) revert AmountZero();
        gracePeriod = _gracePeriod;
        emit GracePeriodUpdated(_gracePeriod);
    }

    // ========= User flows =========
    function addDeposit()
        external
        payable
        nonReentrant
        nonZero(msg.value)
    {
        User storage user = users[msg.sender];
        uint256 prev_collateral = user.totalCollateral;
        user.totalCollateral += msg.value;

        emit CollateralDeposited(msg.sender, msg.value);
        if (prev_collateral == 0 && user.totalCollateral > 0) {
            emit UserRegistered(msg.sender, msg.value);
        }
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
        if (user.totalCollateral < amount)
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

        uint256 amount = users[msg.sender].totalCollateral;
        delete users[msg.sender];
        delete deregistrationRequestedAt[msg.sender];

        (bool ok, ) = payable(msg.sender).call{value: amount}("");
        if (!ok) revert TransferFailed();

        emit UserDeregistered(msg.sender, amount);
    }

    // ========= Operator / Manager flows =========
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
            uint256 deregRequestedAt
        )
    {
        User memory u = users[userAddr];
        collateral = u.totalCollateral;
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
