// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {AccessManaged} from "@openzeppelin/contracts/access/manager/AccessManaged.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/// Minimal view of Core4Mica used by the settlement pool to move collateral.
interface ICore4MicaSettlement {
    function seizeCollateral(address debtor, address asset, uint256 amount) external returns (uint256 seized);
    function creditCollateral(address creditor, address asset, uint256 amount) external payable;
}

/// @title ClearingHouse
/// @notice Cycle-level settlement contract for net debtor payments, creditor claims, and default coverage.
contract ClearingHouse is AccessManaged, ReentrancyGuard {
    using SafeERC20 for IERC20;

    /// Core4Mica collateral vault. Seized debtor collateral flows in here and
    /// creditor funding flows back out to it.
    ICore4MicaSettlement public immutable core4Mica;

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

    struct DebtorEntry {
        address debtor;
        uint256 netDebit;
        bytes32[] proof;
    }

    struct CreditorEntry {
        address creditor;
        uint256 netCredit;
        bytes32[] proof;
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
    error CycleNotZeroSum(uint256 totalNetDebit, uint256 totalNetCredit);
    error CycleAlreadyCommitted(bytes32 cycleId);
    error CycleNotFound(bytes32 cycleId);
    error InvalidCycleStatus(bytes32 cycleId, CycleStatus status);
    error InvalidDeadline();
    error InvalidProof();
    error ExactPaymentRequired(uint256 expected, uint256 actual);
    error AlreadyPaid(bytes32 cycleId, address debtor);
    error AlreadyClaimed(bytes32 cycleId, address creditor);
    error PaymentFinalityPending(uint64 deadline);
    error PaymentWindowElapsed(uint64 deadline);
    error ClaimExceedsFundedLiquidity(uint256 available, uint256 requested);
    error CycleDebtUnresolved(uint256 resolved, uint256 required);
    error CycleUnderfunded(uint256 available, uint256 required);
    error CycleClaimsUnresolved(uint256 claimed, uint256 required);
    error NativeTransferFailed(address recipient, uint256 amount);
    error ZeroAddress();
    error UnauthorizedEthSender(address sender);

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
    event CreditorClaimed(bytes32 indexed cycleId, address indexed creditor, address indexed asset, uint256 amount);
    /// Emitted when an unpaid debtor's collateral is seized into the pool at finality.
    /// `amount` is both the resolved net debit and the seized collateral (they are always equal).
    event DebtorDefaulted(bytes32 indexed cycleId, address indexed debtor, address indexed asset, uint256 amount);
    event CycleFinalized(bytes32 indexed cycleId);
    event SettlementSkipped(bytes32 indexed cycleId, address indexed participant, string reason);

    constructor(address manager, address core4Mica_) AccessManaged(manager) {
        if (core4Mica_ == address(0)) revert ZeroAddress();
        core4Mica = ICore4MicaSettlement(core4Mica_);
    }

    /// Accept ETH only from Core4Mica. All other direct transfers are rejected.
    receive() external payable {
        if (msg.sender != address(core4Mica)) revert UnauthorizedEthSender(msg.sender);
    }

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
        if (totalNetDebit != totalNetCredit) revert CycleNotZeroSum(totalNetDebit, totalNetCredit);
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
        // Only pay out once the cycle is fully funded
        uint256 funded = cycle.totalPaidIn + cycle.totalDefaultCovered;
        if (funded < cycle.totalNetCredit) revert CycleUnderfunded(funded, cycle.totalNetCredit);
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

        emit CreditorClaimed(cycleId, msg.sender, cycle.asset, netCredit);
    }

    /// Operator batch: seize collateral for unpaid debtors after finality.
    function settleDefaultsFromCollateralBatch(bytes32 cycleId, DebtorEntry[] calldata entries)
        external
        restricted
        nonReentrant
    {
        OnchainCycle storage cycle = _requireCycle(cycleId);
        if (cycle.status != CycleStatus.PaymentWindowOpen && cycle.status != CycleStatus.Defaulted) {
            revert InvalidCycleStatus(cycleId, cycle.status);
        }
        if (block.timestamp <= cycle.paymentFinalityDeadline) {
            revert PaymentFinalityPending(cycle.paymentFinalityDeadline);
        }
        if (cycle.status != CycleStatus.Defaulted) {
            cycle.status = CycleStatus.Defaulted;
        }

        for (uint256 i = 0; i < entries.length; i++) {
            DebtorEntry calldata entry = entries[i];
            ParticipantState storage participant = participantStates[cycleId][entry.debtor];
            if (entry.netDebit == 0 || participant.paid || participant.defaulted) {
                emit SettlementSkipped(cycleId, entry.debtor, "already resolved");
                continue;
            }
            if (!_isValidParticipant(
                    cycle, cycleId, entry.debtor, entry.netDebit, ParticipantRole.NetDebtor, entry.proof
                )) {
                emit SettlementSkipped(cycleId, entry.debtor, "invalid proof");
                continue;
            }

            // Shouldn't happen: each debtor locks its net debit at guarantee issuance, so
            // collateral should always cover the seize.
            // TODO: but if it doesn't, the skip leaves the cycle underfunded and unable to
            // finalize, wedged in Settling forever. Needs an explicit loss policy (socialize
            // pro-rata, partial-credit creditors, or a terminal Shortfall state) to terminate.
            try core4Mica.seizeCollateral(entry.debtor, cycle.asset, entry.netDebit) returns (uint256 seized) {
                participant.netDebit = entry.netDebit;
                participant.defaulted = true;
                cycle.totalResolvedDebit += entry.netDebit;
                cycle.totalDefaultCovered += seized;
                emit DebtorDefaulted(cycleId, entry.debtor, cycle.asset, seized);
            } catch {
                emit SettlementSkipped(cycleId, entry.debtor, "seize failed");
            }
        }
    }

    /// Operator batch: fund unclaimed net creditors out of the pool, crediting the
    /// proceeds back into their Core4Mica collateral.
    /// Requires the cycle to be fully funded.
    function fundCreditorsFromPoolBatch(bytes32 cycleId, CreditorEntry[] calldata entries)
        external
        restricted
        nonReentrant
    {
        OnchainCycle storage cycle = _requireCycle(cycleId);
        _requireClaimableStatus(cycleId, cycle);
        uint256 funded = cycle.totalPaidIn + cycle.totalDefaultCovered;
        if (funded < cycle.totalNetCredit) revert CycleUnderfunded(funded, cycle.totalNetCredit);

        for (uint256 i = 0; i < entries.length; i++) {
            CreditorEntry calldata entry = entries[i];
            ParticipantState storage participant = participantStates[cycleId][entry.creditor];
            if (entry.netCredit == 0 || participant.claimed) {
                emit SettlementSkipped(cycleId, entry.creditor, "already resolved");
                continue;
            }
            if (!_isValidParticipant(
                    cycle, cycleId, entry.creditor, entry.netCredit, ParticipantRole.NetCreditor, entry.proof
                )) {
                emit SettlementSkipped(cycleId, entry.creditor, "invalid proof");
                continue;
            }
            uint256 available = cycle.totalPaidIn + cycle.totalDefaultCovered - cycle.totalClaimedOut;
            if (available < entry.netCredit) {
                emit SettlementSkipped(cycleId, entry.creditor, "insufficient liquidity");
                continue;
            }

            bool credited;
            if (cycle.asset == address(0)) {
                try core4Mica.creditCollateral{value: entry.netCredit}(entry.creditor, cycle.asset, entry.netCredit) {
                    credited = true;
                } catch {
                    credited = false;
                }
            } else {
                IERC20(cycle.asset).forceApprove(address(core4Mica), entry.netCredit);
                try core4Mica.creditCollateral(entry.creditor, cycle.asset, entry.netCredit) {
                    credited = true;
                } catch {
                    credited = false;
                }
            }
            if (!credited) {
                emit SettlementSkipped(cycleId, entry.creditor, "credit failed");
                continue;
            }

            participant.netCredit = entry.netCredit;
            participant.claimed = true;
            cycle.totalClaimedOut += entry.netCredit;
            emit CreditorClaimed(cycleId, entry.creditor, cycle.asset, entry.netCredit);
        }
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
        if (!_isValidParticipant(cycle, cycleId, participant, amount, role, proof)) {
            revert InvalidProof();
        }
    }

    function _isValidParticipant(
        OnchainCycle storage cycle,
        bytes32 cycleId,
        address participant,
        uint256 amount,
        ParticipantRole role,
        bytes32[] calldata proof
    ) private view returns (bool) {
        bytes32 leaf = participantLeaf(cycleId, cycle.asset, participant, amount, role);
        return MerkleProof.verifyCalldata(proof, cycle.merkleRoot, leaf);
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
