// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {AccessManaged} from "@openzeppelin/contracts/access/manager/AccessManaged.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {BLS} from "@solady/src/utils/ext/ithaca/BLS.sol";

/// @title Core4Mica
/// @notice Manages user collateral: deposits, locks by operators, withdrawals, and make-whole payouts.
contract Core4Mica is AccessManaged, ReentrancyGuard {
    // ========= Errors =========
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
    error InvalidRecipient();
    error IllegalValue();

    // ========= Storage =========
    uint256 public remunerationGracePeriod = 14 days;
    uint256 public withdrawalGracePeriod = 22 days;
    uint256 public tabExpirationTime = 21 days;
    uint256 public synchronizationDelay = 6 hours;

    /// TODO(#22): move key to registry
    BLS.G1Point public GUARANTEE_VERIFICATION_KEY = BLS.G1Point(
        bytes32(0x000000000000000000000000000000000fffffffffffffffffffffffffffffff),
        bytes32(0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff),
        bytes32(0x000000000000000000000000000000000fffffffffffffffffffffffffffffff),
        bytes32(0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff)
    );

    /// @notice The negated generator point in G1 (-G1), derived from EIP-2537's standard G1 generator.
    BLS.G1Point internal NEGATED_G1_GENERATOR = BLS.G1Point(
        bytes32(0x0000000000000000000000000000000017F1D3A73197D7942695638C4FA9AC0F),
        bytes32(0xC3688C4F9774B905A14E3A3F171BAC586C55E83FF97A1AEFFB3AF00ADB22C6BB),
        bytes32(0x00000000000000000000000000000000114D1D6855D545A8AA7D76C8CF2E21F2),
        bytes32(0x67816AEF1DB507C96655B9D5CAAC42364E6F38BA0ECB751BAD54DCD6B939C2CA)
    );

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
    event CollateralDeposited(address indexed user, uint256 amount);
    event RecipientRemunerated(uint256 indexed tab_id, uint256 amount);
    event CollateralWithdrawn(address indexed user, uint256 amount);
    event WithdrawalRequested(address indexed user, uint256 when, uint256 amount);
    event WithdrawalCanceled(address indexed user);
    event WithdrawalGracePeriodUpdated(uint256 newGracePeriod);
    event RemunerationGracePeriodUpdated(uint256 newGracePeriod);
    event TabExpirationTimeUpdated(uint256 newExpirationTime);
    event SynchronizationDelayUpdated(uint256 newExpirationTime);
    event VerificationKeyUpdated(BLS.G1Point newVerificationKey);

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
        if (recipient == address(0)) revert InvalidRecipient();
        _;
    }

    // ========= Admin / Manager configuration =========
    function setRemunerationGracePeriod(uint256 _gracePeriod) external restricted nonZero(_gracePeriod) {
        if (_gracePeriod >= tabExpirationTime)
            revert IllegalValue();
        remunerationGracePeriod = _gracePeriod;
        emit RemunerationGracePeriodUpdated(_gracePeriod);
    }

    function setWithdrawalGracePeriod(uint256 _gracePeriod) external restricted nonZero(_gracePeriod) {
        if (synchronizationDelay + tabExpirationTime >= _gracePeriod)
            revert IllegalValue();
        withdrawalGracePeriod = _gracePeriod;
        emit WithdrawalGracePeriodUpdated(_gracePeriod);
    }

    function setTabExpirationTime(uint256 _expirationTime) external restricted nonZero(_expirationTime) {
        if (synchronizationDelay + _expirationTime >= withdrawalGracePeriod || remunerationGracePeriod >= _expirationTime)
            revert IllegalValue();
        tabExpirationTime = _expirationTime;
        emit TabExpirationTimeUpdated(_expirationTime);
    }

    function setSynchronizationDelay(uint256 _synchronizationDelay) external restricted nonZero(_synchronizationDelay) {
        if (_synchronizationDelay + tabExpirationTime >= withdrawalGracePeriod)
            revert IllegalValue();
        synchronizationDelay = _synchronizationDelay;
        emit SynchronizationDelayUpdated(_synchronizationDelay);
    }

    function setGuaranteeVerificationKey(BLS.G1Point calldata verificationKey) external restricted {
        GUARANTEE_VERIFICATION_KEY = verificationKey;
        emit VerificationKeyUpdated(verificationKey);
    }

    // ========= User flows =========
    function deposit() external payable nonReentrant nonZero(msg.value) {
        collateral[msg.sender] += msg.value;
        emit CollateralDeposited(msg.sender, msg.value);
    }

    function requestWithdrawal(uint256 amount) external nonZero(amount) {
        if (amount > collateral[msg.sender])
            revert InsufficientAvailable();

        withdrawalRequests[msg.sender] = WithdrawalRequest(block.timestamp, amount);
        emit WithdrawalRequested(msg.sender, block.timestamp, amount);
    }

    function cancelWithdrawal() external {
        if (withdrawalRequests[msg.sender].timestamp == 0)
            revert NoWithdrawalRequested();
        delete withdrawalRequests[msg.sender];
        emit WithdrawalCanceled(msg.sender);
    }

    function finalizeWithdrawal() external nonReentrant {
        WithdrawalRequest memory request = withdrawalRequests[msg.sender];
        if (request.timestamp == 0) revert NoWithdrawalRequested();
        if (block.timestamp < request.timestamp + withdrawalGracePeriod)
            revert GracePeriodNotElapsed();

        /// The user's collateral may have been reduced since the withdrawal was requested.
        /// As such, take the minimum of the two, making sure we never overdraw the account.
        uint256 withdrawal_amount = Math.min(collateral[msg.sender], request.amount);

        collateral[msg.sender] -= withdrawal_amount;
        delete withdrawalRequests[msg.sender];

        (bool ok, ) = payable(msg.sender).call{value: withdrawal_amount}("");
        if (!ok) revert TransferFailed();

        emit CollateralWithdrawn(msg.sender, withdrawal_amount);
    }

    /// TODO(#20): compress signature
    /// TODO(#21): permit batch verification
    function remunerate(
        Guarantee calldata g,
        BLS.G2Point calldata signature
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
        if (!verifyGuaranteeSignature(g, signature))
            revert InvalidSignature();

        // 6. Client must have sufficient funds
        if (collateral[g.client] < g.amount)
            revert DoubleSpendingDetected();

        collateral[g.client] -= g.amount;
        payments[g.tab_id].remunerated = true;

        // Subtract the remunerated value from the withdrawal request
        // whenever the tab was opened BEFORE the withdrawal request
        // was synchronized.
        WithdrawalRequest storage wr = withdrawalRequests[g.client];
        if (g.tab_timestamp < wr.timestamp + synchronizationDelay) {
            uint256 deduction = Math.min(wr.amount, g.amount);
            wr.amount -= deduction;
        }

        (bool ok, ) = payable(g.recipient).call{value: g.amount}("");
        if (!ok) revert TransferFailed();

        emit RecipientRemunerated(g.tab_id, g.amount);
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

    // === Signature verification ===
    function encodeGuarantee(Guarantee memory g) public pure returns (bytes memory) {
        return abi.encodePacked(g.tab_id, g.req_id, g.client, g.recipient, g.amount, g.tab_timestamp);
    }

    function verifyGuaranteeSignature(Guarantee memory guarantee, BLS.G2Point memory signature)
        public
        view
        returns (bool)
    {
        BLS.G1Point[] memory g1Points = new BLS.G1Point[](2);
        g1Points[0] = NEGATED_G1_GENERATOR;
        g1Points[1] = GUARANTEE_VERIFICATION_KEY;

        BLS.G2Point[] memory g2Points = new BLS.G2Point[](2);
        g2Points[0] = signature;
        g2Points[1] = BLS.hashToG2(encodeGuarantee(guarantee));

        return BLS.pairing(g1Points, g2Points);
    }

    // ========= Fallbacks =========
    receive() external payable {
        revert DirectTransferNotAllowed();
    }

    fallback() external payable {
        revert DirectTransferNotAllowed();
    }
}
