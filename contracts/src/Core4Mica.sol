// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {AccessManaged} from "@openzeppelin/contracts/access/manager/AccessManaged.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";

/// @title Core4Mica
/// @notice Manages user collateral: deposits, locks by operators, withdrawals, and make-whole payouts.
contract Core4Mica is AccessManaged, ReentrancyGuard {
    // ========= Errors =========
    error NotRegistered();
    error AmountZero();
    error InsufficientAvailable();
    error TransferFailed();
    error GracePeriodNotElapsed();
    error NoUnlockRequested();
    error DirectTransferNotAllowed();
    error DoubleSpendingDetected();
    error TabNotYetOverdue();
    error TabExpired();
    error TabPreviouslyRemunerated();
    error TabAlreadyPaid();
    error InvalidSignature();

    // ========= Storage =========
    uint256 public remunerationGracePeriod = 14 days;
    uint256 public unlockGracePeriod = 21 days;
    uint256 public tabExpirationTime = 20.5 days;

    struct UserBalance {
        uint256 available;
        uint256 locked;
    }

    struct UnlockRequest {
        uint256 timestamp;
        uint256 amount;
    }

    struct PaymentStatus {
        uint256 paid;
        bool remunerated;
    }

    mapping(address => UserBalance) public balances;
    mapping(address => UnlockRequest) public unlockRequests;
    mapping(uint256 => PaymentStatus) public payments;

    // ========= Events =========
    event BalanceDeposited(address indexed user, uint256 amount);
    event LockedBalance(address indexed user, uint256 amount);
    event RecipientRemunerated(uint256 indexed tab_id, uint256 req_id, uint256 amount);
    event UnlockedBalance(address indexed user, uint256 amount);
    event UnlockRequested(address indexed user, uint256 when);
    event UnlockCanceled(address indexed user);
    event UnlockGracePeriodUpdated(uint256 newGracePeriod);
    event RemunerationGracePeriodUpdated(uint256 newGracePeriod);
    event TabExpirationTimeUpdated(uint256 newExpirationTime);
    event RecordedPayment(uint256 indexed tab_id, uint256 amount);

    // ========= Helper structs =========
    struct Guarantee {
        uint256 tab_id;
        uint256 tab_timestamp;
        address client;
        address recipient;
        uint256 req_id;
        uint256 amount;
    }

    // ========= Constructor =========
    constructor(address manager) AccessManaged(manager) {}

    // ========= Modifiers =========
    modifier nonZero(uint256 amount) {
        if (amount == 0) revert AmountZero();
        _;
    }

    modifier validRecipient(address recipient) {
        if (recipient == address(0)) revert TransferFailed();
        _;
    }

    // ========= Admin / Manager configuration =========
    function setRemunerationGracePeriod(uint256 _gracePeriod) external restricted nonZero(_gracePeriod) {
        remunerationGracePeriod = _gracePeriod;
        emit RemunerationGracePeriodUpdated(_gracePeriod);
    }

    function setUnlockGracePeriod(uint256 _gracePeriod) external restricted nonZero(_gracePeriod) {
        unlockGracePeriod = _gracePeriod;
        emit UnlockGracePeriodUpdated(_gracePeriod);
    }

    function setTabExpirationTime(uint256 _expirationTime) external restricted nonZero(_expirationTime) {
        tabExpirationTime = _expirationTime;
        emit TabExpirationTimeUpdated(_expirationTime);
    }

    // ========= User flows =========
    function deposit() external payable nonReentrant nonZero(msg.value) {
        balances[msg.sender].available += msg.value;
        emit BalanceDeposited(msg.sender, msg.value);
    }

    function lock(uint256 amount) external nonReentrant nonZero(amount) {
        if (amount > balances[msg.sender].available)
            revert InsufficientAvailable();

        balances[msg.sender].available -= amount;
        balances[msg.sender].locked += amount;

        emit LockedBalance(msg.sender, amount);
    }

    function requestUnlock(uint256 amount) external nonZero(amount) {
        if (amount > balances[msg.sender].locked)
            revert InsufficientAvailable();

        unlockRequests[msg.sender] = UnlockRequest(block.timestamp, amount);
        emit UnlockRequested(msg.sender, block.timestamp);
    }

    function cancelUnlock() external {
        if (unlockRequests[msg.sender].timestamp == 0)
            revert NoUnlockRequested();
        delete unlockRequests[msg.sender];
        emit UnlockCanceled(msg.sender);
    }

    function unlock() external nonReentrant {
        UnlockRequest memory request = unlockRequests[msg.sender];
        if (request.timestamp == 0) revert NoUnlockRequested();
        if (block.timestamp < request.timestamp + unlockGracePeriod)
            revert GracePeriodNotElapsed();

        /// The user's collateral may have been reduced since the withdrawal was requested.
        /// As such, take the minimum of the two, making sure we never overdraw the account.
        uint256 unlock_amount = Math.min(balances[msg.sender].locked, request.amount);

        balances[msg.sender].locked -= unlock_amount;
        balances[msg.sender].available += unlock_amount;
        delete unlockRequests[msg.sender];

        emit UnlockedBalance(msg.sender, unlock_amount);
    }

    function remunerate(
        Guarantee calldata g,
        uint256 signature
    )
        external
        nonReentrant
        nonZero(g.amount)
        validRecipient(g.recipient)
    {
        // 1. Tab must be overdue
        if (block.timestamp < g.tab_timestamp + remunerationGracePeriod)
            revert TabNotYetOverdue();

        // 2. Tab must not be expired
        if (g.tab_timestamp + tabExpirationTime < block.timestamp)
            revert TabExpired();

        // 3. Tab must not previously be remunerated
        if (payments[g.tab_id].remunerated)
            revert TabPreviouslyRemunerated();

        // 4. Tab must not be paid
        if (payments[g.tab_id].paid >= g.amount)
            revert TabAlreadyPaid();

        // 5. Verify signature
        // TODO(#16): verify signature
        if (signature != 0)
            revert InvalidSignature();

        // 6. Client must have sufficient funds
        if (balances[g.client].locked < g.amount)
            revert DoubleSpendingDetected();

        balances[g.client].locked -= g.amount;
        payments[g.tab_id].remunerated = true;

        (bool ok, ) = payable(g.recipient).call{value: g.amount}("");
        if (!ok) revert TransferFailed();

        emit RecipientRemunerated(g.tab_id, g.req_id, g.amount);
    }

    // ========= Operator / Manager flows =========
    function recordPayment(
        uint256 tab_id,
        uint256 amount
    )
        external
        restricted
        nonZero(amount)
        nonReentrant
    {
        payments[tab_id].paid += amount;
        emit RecordedPayment(tab_id, amount);
    }

    // ========= Views / Helpers =========
    function getUser(
        address userAddr
    )
        external
        view
        returns (
            uint256 balance_available,
            uint256 balance_locked,
            uint256 unlock_request_timestamp,
            uint256 unlock_request_amount
        )
    {
        balance_available = balances[userAddr].available;
        balance_locked = balances[userAddr].locked;
        unlock_request_timestamp = unlockRequests[userAddr].timestamp;
        unlock_request_amount = unlockRequests[userAddr].amount;
    }

    function getPaymentStatus(
        uint256 tab_id
    )
        external
        view
        returns (
            uint256 paid,
            bool remunerated
        )
    {
        paid = payments[tab_id].paid;
        remunerated = payments[tab_id].remunerated;
    }

    // ========= Fallbacks =========
    receive() external payable {
        revert DirectTransferNotAllowed();
    }

    fallback() external payable {
        revert DirectTransferNotAllowed();
    }
}
