// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {AccessManaged} from "@openzeppelin/contracts/access/manager/AccessManaged.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/// @title ClearingHouse
/// @notice Cycle-level settlement contract for net debtor payments, creditor claims, and default coverage.
contract ClearingHouse is AccessManaged, ReentrancyGuard {
    using SafeERC20 for IERC20;

    enum CycleStatus {
        Committed,
        PaymentWindowOpen,
        Finalized,
        Defaulted
    }

    enum ParticipantRole {
        NetDebtor,
        NetCreditor
    }

    struct OnchainCycle {
        address asset;
        bytes32 merkleRoot;
        uint256 totalNetDebit;
        uint256 totalNetCredit;
        uint256 totalPaidIn;
        uint256 totalClaimedOut;
        uint256 totalDefaultCovered;
        uint256 totalResolvedDebit;
        uint64 paymentSubmissionDeadline;
        uint64 paymentFinalityDeadline;
        CycleStatus status;
        bool exists;
    }

    struct ParticipantState {
        uint256 netDebit;
        uint256 netCredit;
        bool paid;
        bool claimed;
        bool defaulted;
    }

    error AmountZero();
    error CycleAlreadyCommitted(bytes32 cycleId);
    error CycleNotFound(bytes32 cycleId);
    error InvalidCycleStatus(bytes32 cycleId, CycleStatus status);
    error InvalidDeadline();
    error InvalidProof();
    error ExactPaymentRequired(uint256 expected, uint256 actual);
    error AlreadyPaid(bytes32 cycleId, address debtor);
    error AlreadyClaimed(bytes32 cycleId, address creditor);
    error AlreadyDefaulted(bytes32 cycleId, address debtor);
    error PaymentFinalityPending(uint64 deadline);
    error PaymentWindowElapsed(uint64 deadline);
    error ClaimExceedsFundedLiquidity(uint256 available, uint256 requested);
    error CycleDebtUnresolved(uint256 resolved, uint256 required);
    error CycleUnderfunded(uint256 available, uint256 required);
    error CycleClaimsUnresolved(uint256 claimed, uint256 required);
    error NativeTransferFailed(address recipient, uint256 amount);

    mapping(bytes32 => OnchainCycle) private cycles;
    mapping(bytes32 => mapping(address => ParticipantState)) private participantStates;

    event CycleCommitted(
        bytes32 indexed cycleId,
        address indexed asset,
        bytes32 merkleRoot,
        uint256 totalNetDebit,
        uint256 totalNetCredit,
        uint64 paymentSubmissionDeadline,
        uint64 paymentFinalityDeadline
    );
    event DebtorPaid(bytes32 indexed cycleId, address indexed debtor, uint256 amount);
    event CreditorClaimed(bytes32 indexed cycleId, address indexed creditor, uint256 amount);
    event DebtorDefaulted(bytes32 indexed cycleId, address indexed debtor, uint256 amount);
    event DefaultCovered(bytes32 indexed cycleId, address indexed debtor, uint256 amount);
    event CycleFinalized(bytes32 indexed cycleId);

    constructor(address manager) AccessManaged(manager) {}

    function commitCycle(
        bytes32 cycleId,
        address asset,
        bytes32 merkleRoot,
        uint256 totalNetDebit,
        uint256 totalNetCredit,
        uint64 paymentSubmissionDeadline,
        uint64 paymentFinalityDeadline
    ) external restricted {
        if (cycles[cycleId].exists) revert CycleAlreadyCommitted(cycleId);
        if (cycleId == bytes32(0) || merkleRoot == bytes32(0) || totalNetDebit == 0 || totalNetCredit == 0) {
            revert AmountZero();
        }
        if (paymentSubmissionDeadline == 0 || paymentFinalityDeadline < paymentSubmissionDeadline) {
            revert InvalidDeadline();
        }

        cycles[cycleId] = OnchainCycle({
            asset: asset,
            merkleRoot: merkleRoot,
            totalNetDebit: totalNetDebit,
            totalNetCredit: totalNetCredit,
            totalPaidIn: 0,
            totalClaimedOut: 0,
            totalDefaultCovered: 0,
            totalResolvedDebit: 0,
            paymentSubmissionDeadline: paymentSubmissionDeadline,
            paymentFinalityDeadline: paymentFinalityDeadline,
            status: CycleStatus.PaymentWindowOpen,
            exists: true
        });

        emit CycleCommitted(
            cycleId,
            asset,
            merkleRoot,
            totalNetDebit,
            totalNetCredit,
            paymentSubmissionDeadline,
            paymentFinalityDeadline
        );
    }

    function payNetDebit(bytes32 cycleId, uint256 netDebit, bytes32[] calldata proof) external payable nonReentrant {
        OnchainCycle storage cycle = _requireCycle(cycleId);
        _requirePaymentWindowOpen(cycleId, cycle);
        if (block.timestamp > cycle.paymentSubmissionDeadline) {
            revert PaymentWindowElapsed(cycle.paymentSubmissionDeadline);
        }
        if (netDebit == 0) revert AmountZero();
        if (participantStates[cycleId][msg.sender].paid) revert AlreadyPaid(cycleId, msg.sender);
        _verifyParticipant(cycle, cycleId, msg.sender, netDebit, ParticipantRole.NetDebtor, proof);

        _collect(cycle.asset, netDebit);

        ParticipantState storage participant = participantStates[cycleId][msg.sender];
        participant.netDebit = netDebit;
        participant.paid = true;
        cycle.totalPaidIn += netDebit;
        cycle.totalResolvedDebit += netDebit;

        emit DebtorPaid(cycleId, msg.sender, netDebit);
    }

    function claimNetCredit(bytes32 cycleId, uint256 netCredit, bytes32[] calldata proof) external nonReentrant {
        OnchainCycle storage cycle = _requireCycle(cycleId);
        _requireClaimableStatus(cycleId, cycle);
        if (netCredit == 0) revert AmountZero();
        if (participantStates[cycleId][msg.sender].claimed) revert AlreadyClaimed(cycleId, msg.sender);
        _verifyParticipant(cycle, cycleId, msg.sender, netCredit, ParticipantRole.NetCreditor, proof);

        uint256 available = cycle.totalPaidIn + cycle.totalDefaultCovered - cycle.totalClaimedOut;
        if (available < netCredit) revert ClaimExceedsFundedLiquidity(available, netCredit);

        ParticipantState storage participant = participantStates[cycleId][msg.sender];
        participant.netCredit = netCredit;
        participant.claimed = true;
        cycle.totalClaimedOut += netCredit;

        _pay(cycle.asset, msg.sender, netCredit);

        emit CreditorClaimed(cycleId, msg.sender, netCredit);
    }

    function markDefaulted(bytes32 cycleId, address debtor, uint256 netDebit, bytes32[] calldata proof) external {
        OnchainCycle storage cycle = _requireCycle(cycleId);
        _requirePaymentWindowOpen(cycleId, cycle);
        if (block.timestamp <= cycle.paymentFinalityDeadline) {
            revert PaymentFinalityPending(cycle.paymentFinalityDeadline);
        }
        if (netDebit == 0) revert AmountZero();

        ParticipantState storage participant = participantStates[cycleId][debtor];
        if (participant.paid) revert AlreadyPaid(cycleId, debtor);
        if (participant.defaulted) revert AlreadyDefaulted(cycleId, debtor);
        _verifyParticipant(cycle, cycleId, debtor, netDebit, ParticipantRole.NetDebtor, proof);

        participant.netDebit = netDebit;
        participant.defaulted = true;
        cycle.totalResolvedDebit += netDebit;
        cycle.status = CycleStatus.Defaulted;

        emit DebtorDefaulted(cycleId, debtor, netDebit);
    }

    function settleDefaultFromCollateral(bytes32 cycleId, address debtor, uint256 amount, bytes calldata authorization)
        external
        payable
        restricted
        nonReentrant
    {
        authorization;
        OnchainCycle storage cycle = _requireCycle(cycleId);
        if (cycle.status != CycleStatus.Defaulted) revert InvalidCycleStatus(cycleId, cycle.status);
        if (!participantStates[cycleId][debtor].defaulted) revert InvalidProof();
        if (amount == 0) revert AmountZero();

        _collect(cycle.asset, amount);
        cycle.totalDefaultCovered += amount;

        emit DefaultCovered(cycleId, debtor, amount);
    }

    function finalizeCycle(bytes32 cycleId) external {
        OnchainCycle storage cycle = _requireCycle(cycleId);
        _requireClaimableStatus(cycleId, cycle);
        if (block.timestamp <= cycle.paymentFinalityDeadline) {
            revert PaymentFinalityPending(cycle.paymentFinalityDeadline);
        }
        if (cycle.totalResolvedDebit != cycle.totalNetDebit) {
            revert CycleDebtUnresolved(cycle.totalResolvedDebit, cycle.totalNetDebit);
        }

        uint256 funded = cycle.totalPaidIn + cycle.totalDefaultCovered;
        if (funded < cycle.totalNetCredit) revert CycleUnderfunded(funded, cycle.totalNetCredit);
        if (cycle.totalClaimedOut != cycle.totalNetCredit) {
            revert CycleClaimsUnresolved(cycle.totalClaimedOut, cycle.totalNetCredit);
        }

        cycle.status = CycleStatus.Finalized;
        emit CycleFinalized(cycleId);
    }

    function getCycle(bytes32 cycleId) external view returns (OnchainCycle memory) {
        return _requireCycleView(cycleId);
    }

    function getParticipantState(bytes32 cycleId, address participant) external view returns (ParticipantState memory) {
        _requireCycleView(cycleId);
        return participantStates[cycleId][participant];
    }

    function participantLeaf(bytes32 cycleId, address asset, address participant, uint256 amount, ParticipantRole role)
        public
        view
        returns (bytes32 leaf)
    {
        uint256 chainId = block.chainid;
        uint256 roleValue = uint256(role);
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(ptr, chainId)
            mstore(add(ptr, 0x20), address())
            mstore(add(ptr, 0x40), cycleId)
            mstore(add(ptr, 0x60), asset)
            mstore(add(ptr, 0x80), participant)
            mstore(add(ptr, 0xa0), amount)
            mstore(add(ptr, 0xc0), roleValue)
            mstore(0x40, add(ptr, 0xe0))
            leaf := keccak256(ptr, 0xe0)
        }
    }

    function _requireCycle(bytes32 cycleId) private view returns (OnchainCycle storage cycle) {
        cycle = cycles[cycleId];
        if (!cycle.exists) revert CycleNotFound(cycleId);
    }

    function _requireCycleView(bytes32 cycleId) private view returns (OnchainCycle memory cycle) {
        cycle = cycles[cycleId];
        if (!cycle.exists) revert CycleNotFound(cycleId);
    }

    function _requirePaymentWindowOpen(bytes32 cycleId, OnchainCycle storage cycle) private view {
        if (cycle.status != CycleStatus.PaymentWindowOpen) revert InvalidCycleStatus(cycleId, cycle.status);
    }

    function _requireClaimableStatus(bytes32 cycleId, OnchainCycle storage cycle) private view {
        if (cycle.status != CycleStatus.PaymentWindowOpen && cycle.status != CycleStatus.Defaulted) {
            revert InvalidCycleStatus(cycleId, cycle.status);
        }
    }

    function _verifyParticipant(
        OnchainCycle storage cycle,
        bytes32 cycleId,
        address participant,
        uint256 amount,
        ParticipantRole role,
        bytes32[] calldata proof
    ) private view {
        bytes32 leaf = participantLeaf(cycleId, cycle.asset, participant, amount, role);
        if (!MerkleProof.verifyCalldata(proof, cycle.merkleRoot, leaf)) revert InvalidProof();
    }

    function _collect(address asset, uint256 amount) private {
        if (asset == address(0)) {
            if (msg.value != amount) revert ExactPaymentRequired(amount, msg.value);
        } else {
            if (msg.value != 0) revert ExactPaymentRequired(0, msg.value);
            IERC20(asset).safeTransferFrom(msg.sender, address(this), amount);
        }
    }

    function _pay(address asset, address recipient, uint256 amount) private {
        if (asset == address(0)) {
            (bool ok,) = payable(recipient).call{value: amount}("");
            if (!ok) revert NativeTransferFailed(recipient, amount);
        } else {
            IERC20(asset).safeTransfer(recipient, amount);
        }
    }
}
