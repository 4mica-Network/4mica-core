// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {AccessManaged} from "@openzeppelin/contracts/access/manager/AccessManaged.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";

/// Minimal view of Core4Mica used by the settlement pool to move collateral.
interface ICore4MicaSettlement {
    function seizeCollateral(address debtor, address asset, uint256 amount) external returns (uint256 seized);
    /// Partial-tolerant seizure: recovers up to `amount`, returning what was actually taken, so
    /// an under-collateralised debtor still resolves and the cycle can terminate.
    function seizeUpTo(address debtor, address asset, uint256 amount) external returns (uint256 seized);
    function creditCollateral(address creditor, address asset, uint256 amount) external payable;
    /// Stablecoin settlement escrow: paid-in and seized value is held as
    /// scaled aTokens inside Core4Mica so settlement never depends on Aave liquidity.
    function depositToEscrow(address asset, uint256 amount) external;
    function creditFromEscrowScaled(address creditor, address asset, uint256 amount) external;
    function withdrawFromEscrow(address asset, uint256 amount, address recipient)
        external
        returns (uint256 actualWithdrawn);
}

/// @title ClearingHouse
/// @notice Cycle-level settlement contract for net debtor payments, creditor claims, and default coverage.
contract ClearingHouse is AccessManaged, ReentrancyGuard {
    using SafeERC20 for IERC20;

    /// Core4Mica collateral vault. Seized debtor collateral flows in here and
    /// creditor funding flows back out to it.
    // Public immutable getter is part of the ABI; keep camelCase per this codebase's
    // public-variable convention rather than SCREAMING_SNAKE_CASE.
    // forge-lint: disable-next-line(screaming-snake-case-immutable)
    ICore4MicaSettlement public immutable core4Mica;

    enum CycleStatus {
        Committed,
        PaymentWindowOpen,
        Finalized,
        Defaulted,
        // Terminal state for a cycle whose recovered collateral cannot fully cover creditor
        // claims; creditors withdraw a pro-rata share of the funded pool.
        Shortfall
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
    error ClaimConversionShortfall(uint256 requested, uint256 got);
    error CycleFullyFunded(uint256 funded, uint256 required);
    error ResolvedDebitExceedsCommitted(uint256 attempted, uint256 total);
    error ClaimedCreditExceedsCommitted(uint256 attempted, uint256 total);

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
    /// Emitted when a cycle is driven to the terminal Shortfall state because recovered
    /// collateral cannot fully fund creditor claims.
    event CycleShortfall(bytes32 indexed cycleId, uint256 funded, uint256 totalNetCredit);

    constructor(address manager, address core4Mica_) AccessManaged(manager) {
        if (core4Mica_ == address(0)) revert ZeroAddress();
        core4Mica = ICore4MicaSettlement(core4Mica_);
    }

    /// Accept ETH only from Core4Mica. All other direct transfers are rejected.
    receive() external payable {
        if (msg.sender != address(core4Mica)) {
            revert UnauthorizedEthSender(msg.sender);
        }
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
        if (totalNetDebit != totalNetCredit) {
            revert CycleNotZeroSum(totalNetDebit, totalNetCredit);
        }
        // forge-lint: disable-next-line(block-timestamp)
        if (paymentSubmissionDeadline <= block.timestamp || paymentFinalityDeadline < paymentSubmissionDeadline) {
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
        // forge-lint: disable-next-line(block-timestamp)
        if (block.timestamp > cycle.paymentSubmissionDeadline) {
            revert PaymentWindowElapsed(cycle.paymentSubmissionDeadline);
        }
        if (netDebit == 0) revert AmountZero();
        if (participantStates[cycleId][msg.sender].paid) {
            revert AlreadyPaid(cycleId, msg.sender);
        }
        _verifyParticipant(cycle, cycleId, msg.sender, netDebit, ParticipantRole.NetDebtor, proof);
        if (cycle.totalResolvedDebit + netDebit > cycle.totalNetDebit) {
            revert ResolvedDebitExceedsCommitted(cycle.totalResolvedDebit + netDebit, cycle.totalNetDebit);
        }

        _collect(cycle.asset, netDebit);
        if (cycle.asset != address(0)) {
            IERC20(cycle.asset).forceApprove(address(core4Mica), netDebit);
            core4Mica.depositToEscrow(cycle.asset, netDebit);
        }

        ParticipantState storage participant = participantStates[cycleId][msg.sender];
        participant.netDebit = netDebit;
        participant.paid = true;
        cycle.totalPaidIn += netDebit;
        cycle.totalResolvedDebit += netDebit;

        emit DebtorPaid(cycleId, msg.sender, netDebit);
    }

    function claimNetCredit(bytes32 cycleId, uint256 netCredit, bytes32[] calldata proof) external nonReentrant {
        _claimNetCredit(msg.sender, cycleId, netCredit, proof);
    }

    /// @notice Pay out `creditor`'s committed net credit for `cycleId`, whoever submits it.
    /// @dev Permissionless by design: the payout goes to `creditor` and the amount is fixed by the
    /// committed Merkle leaf, so a submitter can neither redirect it nor inflate it — the worst it
    /// can do is not submit. That lets a relayer sponsor the gas without the creditor holding
    /// native balance or signing anything. A successful claim also marks the creditor resolved, so
    /// a later `fundCreditorsFromPoolBatch` skips them: whoever submits first decides whether the
    /// payout lands in the creditor's wallet or back in their Core4Mica collateral.
    function claimNetCreditFor(address creditor, bytes32 cycleId, uint256 netCredit, bytes32[] calldata proof)
        external
        nonReentrant
    {
        _claimNetCredit(creditor, cycleId, netCredit, proof);
    }

    function _claimNetCredit(address creditor, bytes32 cycleId, uint256 netCredit, bytes32[] calldata proof) private {
        OnchainCycle storage cycle = _requireCycle(cycleId);
        _requireClaimableStatus(cycleId, cycle);
        if (netCredit == 0) revert AmountZero();
        ParticipantState storage participant = participantStates[cycleId][creditor];
        if (participant.claimed) {
            revert AlreadyClaimed(cycleId, creditor);
        }
        _verifyParticipant(cycle, cycleId, creditor, netCredit, ParticipantRole.NetCreditor, proof);

        // Full amount when fully funded; pro-rata share of the pool in a Shortfall cycle.
        uint256 payout = _creditorPayout(cycle, netCredit);
        if (payout == 0) {
            participant.netCredit = netCredit;
            participant.claimed = true;
            emit CreditorClaimed(cycleId, creditor, cycle.asset, 0);
            return;
        }
        if (cycle.totalClaimedOut + payout > cycle.totalNetCredit) {
            revert ClaimedCreditExceedsCommitted(cycle.totalClaimedOut + payout, cycle.totalNetCredit);
        }
        uint256 available = _available(cycle);
        if (available < payout) {
            revert ClaimExceedsFundedLiquidity(available, payout);
        }

        participant.netCredit = netCredit;
        participant.claimed = true;
        cycle.totalClaimedOut += payout;

        if (cycle.asset == address(0)) {
            _pay(cycle.asset, creditor, payout);
        } else {
            uint256 got = core4Mica.withdrawFromEscrow(cycle.asset, payout, creditor);
            if (got < payout) revert ClaimConversionShortfall(payout, got);
        }

        emit CreditorClaimed(cycleId, creditor, cycle.asset, payout);
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
        // forge-lint: disable-next-line(block-timestamp)
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
            if (cycle.totalResolvedDebit + entry.netDebit > cycle.totalNetDebit) {
                emit SettlementSkipped(cycleId, entry.debtor, "exceeds committed debit");
                continue;
            }
            try core4Mica.seizeUpTo(entry.debtor, cycle.asset, entry.netDebit) returns (uint256 seized) {
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
        // A fully-funded cycle pays each creditor in full; a Shortfall cycle pays pro-rata.
        // Outside Shortfall, funding before the pool is complete is rejected.
        if (cycle.status != CycleStatus.Shortfall) {
            uint256 funded = _funded(cycle);
            if (funded < cycle.totalNetCredit) {
                revert CycleUnderfunded(funded, cycle.totalNetCredit);
            }
        }

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
            // Full amount when funded; pro-rata share in Shortfall (may round to zero for a
            // tiny claim under a severe shortfall, in which case the creditor is simply resolved).
            uint256 payout = _creditorPayout(cycle, entry.netCredit);
            if (payout == 0) {
                participant.netCredit = entry.netCredit;
                participant.claimed = true;
                emit CreditorClaimed(cycleId, entry.creditor, cycle.asset, 0);
                continue;
            }
            if (cycle.totalClaimedOut + payout > cycle.totalNetCredit) {
                emit SettlementSkipped(cycleId, entry.creditor, "exceeds committed credit");
                continue;
            }
            uint256 available = _available(cycle);
            if (available < payout) {
                emit SettlementSkipped(cycleId, entry.creditor, "insufficient liquidity");
                continue;
            }

            bool credited;
            if (cycle.asset == address(0)) {
                try core4Mica.creditCollateral{value: payout}(entry.creditor, cycle.asset, payout) {
                    credited = true;
                } catch {
                    credited = false;
                }
            } else {
                // Re-attribute escrowed scaled aTokens directly to the creditor's collateral —
                // no withdraw/supply round trip, no Aave liquidity needed.
                try core4Mica.creditFromEscrowScaled(entry.creditor, cycle.asset, payout) {
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
            cycle.totalClaimedOut += payout;
            emit CreditorClaimed(cycleId, entry.creditor, cycle.asset, payout);
        }
    }

    /// Drive an under-funded cycle to the terminal Shortfall state once payment finality has
    /// passed and every debtor is resolved (paid or seized to exhaustion) but recovered
    /// collateral still cannot cover creditor claims. Creditors then withdraw a pro-rata share.
    /// Restricted to the operator.
    ///
    /// Only valid from `Defaulted`: an under-funded cycle necessarily had a defaulting debtor, so
    /// `settleDefaultsFromCollateralBatch` (which sets `Defaulted`) must have run first. In
    /// `PaymentWindowOpen` a shortfall is impossible — by zero-sum, `totalResolvedDebit ==
    /// totalNetDebit` implies `funded >= totalNetCredit`, which would revert `CycleFullyFunded`.
    function markCycleShortfall(bytes32 cycleId) external restricted {
        OnchainCycle storage cycle = _requireCycle(cycleId);
        if (cycle.status != CycleStatus.Defaulted) {
            revert InvalidCycleStatus(cycleId, cycle.status);
        }
        // forge-lint: disable-next-line(block-timestamp)
        if (block.timestamp <= cycle.paymentFinalityDeadline) {
            revert PaymentFinalityPending(cycle.paymentFinalityDeadline);
        }
        if (cycle.totalResolvedDebit != cycle.totalNetDebit) {
            revert CycleDebtUnresolved(cycle.totalResolvedDebit, cycle.totalNetDebit);
        }
        uint256 funded = _funded(cycle);
        if (funded >= cycle.totalNetCredit) {
            revert CycleFullyFunded(funded, cycle.totalNetCredit);
        }

        cycle.status = CycleStatus.Shortfall;
        emit CycleShortfall(cycleId, funded, cycle.totalNetCredit);
    }

    function finalizeCycle(bytes32 cycleId) external {
        OnchainCycle storage cycle = _requireCycle(cycleId);
        _requireClaimableStatus(cycleId, cycle);
        // forge-lint: disable-next-line(block-timestamp)
        if (block.timestamp <= cycle.paymentFinalityDeadline) {
            revert PaymentFinalityPending(cycle.paymentFinalityDeadline);
        }
        if (cycle.totalResolvedDebit != cycle.totalNetDebit) {
            revert CycleDebtUnresolved(cycle.totalResolvedDebit, cycle.totalNetDebit);
        }

        uint256 funded = _funded(cycle);
        if (funded < cycle.totalNetCredit) {
            revert CycleUnderfunded(funded, cycle.totalNetCredit);
        }
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

    /// @dev The leaf is double-hashed — keccak256(keccak256(preimage)), the
    /// OpenZeppelin StandardMerkleTree construction. The outer hash consumes a
    /// 32-byte digest while internal nodes hash 64-byte (left || right) inputs, so
    /// the two domains are disjoint and no internal node can be replayed as a leaf
    /// (second-preimage safety). Must stay byte-identical to Rust
    /// `hash_participant_leaf`.
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
            mstore(0x00, keccak256(ptr, 0xe0))
            leaf := keccak256(0x00, 0x20)
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
        if (cycle.status != CycleStatus.PaymentWindowOpen) {
            revert InvalidCycleStatus(cycleId, cycle.status);
        }
    }

    function _requireClaimableStatus(bytes32 cycleId, OnchainCycle storage cycle) private view {
        if (
            cycle.status != CycleStatus.PaymentWindowOpen && cycle.status != CycleStatus.Defaulted
                && cycle.status != CycleStatus.Shortfall
        ) {
            revert InvalidCycleStatus(cycleId, cycle.status);
        }
    }

    /// Total value available to a cycle's creditors: debtor payments plus collateral recovered
    /// via seizure.
    function _funded(OnchainCycle storage cycle) private view returns (uint256) {
        return cycle.totalPaidIn + cycle.totalDefaultCovered;
    }

    /// Funded value not yet paid out to creditors.
    function _available(OnchainCycle storage cycle) private view returns (uint256) {
        return _funded(cycle) - cycle.totalClaimedOut;
    }

    /// The underlying a creditor owed `netCredit` receives: the full amount once the cycle is
    /// fully funded, or a pro-rata share of the funded pool in the terminal Shortfall state.
    /// Reverts in non-shortfall states if the cycle is not yet fully funded.
    function _creditorPayout(OnchainCycle storage cycle, uint256 netCredit) private view returns (uint256) {
        uint256 funded = _funded(cycle);
        if (cycle.status == CycleStatus.Shortfall) {
            return Math.mulDiv(netCredit, funded, cycle.totalNetCredit);
        }
        if (funded < cycle.totalNetCredit) {
            revert CycleUnderfunded(funded, cycle.totalNetCredit);
        }
        return netCredit;
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
            if (msg.value != amount) {
                revert ExactPaymentRequired(amount, msg.value);
            }
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
