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
    error NoWithdrawalRequested();
    error DirectTransferNotAllowed();
    error DoubleSpendingDetected();
    error TabNotYetOverdue();
    error TabExpired();
    error TabPreviouslyRemunerated();
    error TabAlreadyPaid();
    error InvalidSignature();

    // ========= Storage =========
    uint256 public remunerationGracePeriod = 14 days;
    uint256 public withdrawalGracePeriod = 21 days;
    uint256 public tabExpirationTime = 20.5 days;

    struct WithdrawalRequest {
        uint256 timestamp;
        uint256 amount;
    }

    struct PaymentStatus {
        uint256 paid;
        bool remunerated;
    }

    mapping(address => uint256) public collateral;
    mapping(address => WithdrawalRequest) public withdrawalRequests;
    mapping(uint256 => PaymentStatus) public payments;

    // ========= Events =========
    event UserRegistered(address indexed user, uint256 initialCollateral);
    event CollateralDeposited(address indexed user, uint256 amount);
    event RecipientRemunerated(uint256 indexed tab_id, uint256 req_id, uint256 amount);
    event CollateralWithdrawn(address indexed user, uint256 amount);
    event WithdrawalRequested(address indexed user, uint256 when);
    event WithdrawalCanceled(address indexed user);
    event WithdrawalGracePeriodUpdated(uint256 newGracePeriod);
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
    modifier isRegistered(address userAddr) {
        if (collateral[userAddr] == 0) revert NotRegistered();
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
    function setRemunerationGracePeriod(uint256 _gracePeriod) external restricted nonZero(_gracePeriod) {
        remunerationGracePeriod = _gracePeriod;
        emit RemunerationGracePeriodUpdated(_gracePeriod);
    }

    function setWithdrawalGracePeriod(uint256 _gracePeriod) external restricted nonZero(_gracePeriod) {
        withdrawalGracePeriod = _gracePeriod;
        emit WithdrawalGracePeriodUpdated(_gracePeriod);
    }

    function setTabExpirationTime(uint256 _expirationTime) external restricted nonZero(_expirationTime) {
        tabExpirationTime = _expirationTime;
        emit TabExpirationTimeUpdated(_expirationTime);
    }

    // ========= User flows =========
    function deposit()
        external
        payable
        nonReentrant
        nonZero(msg.value)
    {
        uint256 prev_collateral = collateral[msg.sender];
        collateral[msg.sender] += msg.value;

        if (prev_collateral == 0) {
            emit UserRegistered(msg.sender, msg.value);
        } else {
            emit CollateralDeposited(msg.sender, msg.value);
        }
    }

    function requestWithdrawal(
        uint256 amount
    )
        external
        restricted
        isRegistered(msg.sender)
        nonZero(amount)
    {
        if (amount > collateral[msg.sender])
            revert InsufficientAvailable();

        withdrawalRequests[msg.sender] = WithdrawalRequest(block.timestamp, amount);
        emit WithdrawalRequested(msg.sender, block.timestamp);
    }

    function cancelWithdrawal() external restricted {
        if (withdrawalRequests[msg.sender].timestamp == 0)
            revert NoWithdrawalRequested();
        delete withdrawalRequests[msg.sender];
        emit WithdrawalCanceled(msg.sender);
    }

    function finalizeWithdrawal()
        external
        nonReentrant
        restricted
    {
        WithdrawalRequest memory request = withdrawalRequests[msg.sender];
        if (request.timestamp == 0) revert NoWithdrawalRequested();
        if (block.timestamp < request.timestamp + withdrawalGracePeriod)
            revert GracePeriodNotElapsed();

        /// The user's collateral may have been reduced since the withdrawal was requested.
        /// As such, take the minimum of the two, making sure we never overdraw the account.
        uint256 withdrawal_amount = Math.min(collateral[msg.sender], request.amount);

        if (withdrawal_amount == collateral[msg.sender]) {
            delete collateral[msg.sender];
        } else {
            collateral[msg.sender] -= withdrawal_amount;
        }
        delete withdrawalRequests[msg.sender];

        (bool ok, ) = payable(msg.sender).call{value: withdrawal_amount}("");
        if (!ok) revert TransferFailed();

        emit CollateralWithdrawn(msg.sender, withdrawal_amount);
    }

    function remunerate(
        Guarantee calldata g,
        uint256 signature
    )
        external
        restricted
        nonZero(g.amount)
        validRecipient(g.recipient)
        nonReentrant
        isRegistered(g.client)
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
        if (collateral[g.client] < g.amount)
            revert DoubleSpendingDetected();

        collateral[g.client] -= g.amount;
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
            uint256 _collateral,
            uint256 withdrawal_request_timestamp,
            uint256 withdrawal_request_amount
        )
    {
        _collateral = collateral[userAddr];
        withdrawal_request_timestamp = withdrawalRequests[userAddr].timestamp;
        withdrawal_request_amount = withdrawalRequests[userAddr].amount;
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
