// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {ISampraanAccessControl} from "./interfaces/ISampraanAccessControl.sol";
import {ISampraanGovernanceTarget} from "./interfaces/ISampraanGovernanceTarget.sol";

/**
 * @title SampraanGovernance
 * @notice On-chain 2-of-3 (configurable quorum) multisig with a timelock for
 *         SAMPRAAN's high-risk administrative operations:
 *
 *   - grant/revoke platform roles (via SampraanAccessControl)
 *   - burnNFT / forceTransfer on the asset registry (emergency recovery)
 *   - pause/unpause the registries
 *   - deactivate an identity (terminal lifecycle)
 *
 * Security model:
 *  - Only signers may propose/approve/cancel/execute. The signer set is fixed
 *    at deployment (configurable by redeployment); quorum and timelock delay
 *    are adjustable by the governance admin — changes are themselves events.
 *  - A proposal binds its EXACT operation parameters (kind, target contract,
 *    role, account, tokenId, recipient, reason) at creation; approvals are
 *    attached to the proposal id, so approval substitution/replay of a
 *    different operation is impossible.
 *  - One approval per signer per proposal (approvedBy mapping).
 *  - Execution requires quorum AND (createdAt + delay) elapsed — the timelock
 *    cannot be bypassed; a proposal cannot execute twice; cancellation is
 *    supported while unexecuted.
 *  - The executor can be any signer once quorum + delay are satisfied
 *    (standard multisig semantics; approvals are the authority, not the
 *    execution key).
 *
 * Off-chain reasons travel inside the proposal and are emitted in every event
 * so the audit trail is self-contained.
 */
contract SampraanGovernance {
    // ---------------- operation kinds ----------------
    enum OpKind {
        NONE, // 0
        GRANT_ROLE, // 1
        REVOKE_ROLE, // 2
        BURN_NFT, // 3
        FORCE_TRANSFER, // 4
        PAUSE_REGISTRY, // 5
        UNPAUSE_REGISTRY, // 6
        DEACTIVATE_IDENTITY // 7
    }

    // ---------------- errors ----------------
    error NotSigner();
    error NotGovernanceAdmin();
    error ZeroAddress();
    error ZeroSigners();
    error QuorumOutOfRange();
    error AlreadyApproved();
    error AlreadyExecuted();
    error AlreadyCancelled();
    error NotApprovedEnough();
    error TimelockNotElapsed();
    error ProposalNotPending();
    error InvalidKind();
    error InvalidTarget();

    // ---------------- immutable configuration ----------------
    ISampraanAccessControl public immutable accessControl;
    address[] private _signers;
    mapping(address => bool) private _isSigner;
    address public immutable governanceAdmin; // quorum/delay administration

    // ---------------- configurable governance parameters ----------------
    uint256 public quorumPercent; // 1..100 — % of signers required
    uint256 public timelockDelaySeconds;

    // ---------------- proposals ----------------
    uint256 public proposalCount;
    mapping(uint256 => OpKind) public proposalKind;
    mapping(uint256 => address) public proposalTarget; // contract to call
    mapping(uint256 => bytes32) public proposalRole; // GRANT/REVOKE_ROLE
    mapping(uint256 => address) public proposalAccount; // role account / recipient / identity wallet
    mapping(uint256 => uint256) public proposalTokenId; // BURN_NFT / FORCE_TRANSFER
    mapping(uint256 => string) public proposalReason;
    mapping(uint256 => uint64) public proposalCreatedAt;
    mapping(uint256 => uint256) public proposalApprovals;
    mapping(uint256 => bool) public proposalExecuted;
    mapping(uint256 => bool) public proposalCancelled;
    mapping(uint256 => mapping(address => bool)) public proposalApprovedBy;

    // ---------------- events ----------------
    event ProposalCreated(
        uint256 indexed proposalId,
        OpKind kind,
        address indexed target,
        bytes32 role,
        address indexed account,
        uint256 tokenId,
        string reason,
        uint64 createdAt,
        address proposer
    );
    event ProposalApproved(uint256 indexed proposalId, address indexed signer, uint256 approvals);
    event ProposalCancelled(uint256 indexed proposalId, address indexed signer, string reason);
    event ProposalExecuted(uint256 indexed proposalId, OpKind kind, address indexed executor, uint64 executedAt);
    event QuorumChanged(uint256 oldQuorumPercent, uint256 newQuorumPercent);
    event TimelockDelayChanged(uint256 oldDelaySeconds, uint256 newDelaySeconds);

    modifier onlySigner() {
        if (!_isSigner[msg.sender]) revert NotSigner();
        _;
    }

    modifier onlyGovernanceAdmin() {
        if (msg.sender != governanceAdmin) revert NotGovernanceAdmin();
        _;
    }

    /**
     * @param accessControlAddress SampraanAccessControl (must hold DEFAULT_ADMIN_ROLE
     *        on itself FOR this contract — granted by the deployer after deployment —
     *        so GRANT_ROLE/REVOKE_ROLE proposals can manage platform roles).
     * @param signers        Multisig signer set (>= quorum members).
     * @param quorumPercent_ Percentage of signers required to execute (e.g. 67 for 2-of-3).
     * @param delaySeconds   Timelock delay between quorum and execution eligibility.
     */
    constructor(
        address accessControlAddress,
        address[] memory signers,
        uint256 quorumPercent_,
        uint256 delaySeconds,
        address admin
    ) {
        if (accessControlAddress == address(0)) revert ZeroAddress();
        if (signers.length == 0) revert ZeroSigners();
        if (admin == address(0)) revert ZeroAddress();
        accessControl = ISampraanAccessControl(accessControlAddress);
        governanceAdmin = admin;
        for (uint256 i = 0; i < signers.length; i++) {
            if (signers[i] == address(0)) revert ZeroAddress();
            if (_isSigner[signers[i]]) revert ZeroSigners(); // duplicate signer rejected
            _isSigner[signers[i]] = true;
            _signers.push(signers[i]);
        }
        _setQuorum(quorumPercent_);
        _setDelay(delaySeconds);
    }

    // ---------------- view helpers ----------------

    function signerCount() external view returns (uint256) {
        return _signers.length;
    }

    function isSigner(address account) external view returns (bool) {
        return _isSigner[account];
    }

    function quorumRequired() external view returns (uint256) {
        return (_signers.length * quorumPercent + 99) / 100;
    }

    function proposalExecutableAt(uint256 proposalId) external view returns (uint256) {
        return uint256(proposalCreatedAt[proposalId]) + timelockDelaySeconds;
    }

    // Split into two views (a single 10-tuple exceeded the EVM stack limit
    // without --via-ir). proposalCore returns WHAT is proposed; proposalState
    // returns WHERE it stands in the lifecycle.
    function proposalCore(
        uint256 proposalId
    )
        external
        view
        returns (
            OpKind kind,
            address target,
            bytes32 role,
            address account,
            uint256 tokenId,
            string memory reason
        )
    {
        return (
            proposalKind[proposalId],
            proposalTarget[proposalId],
            proposalRole[proposalId],
            proposalAccount[proposalId],
            proposalTokenId[proposalId],
            proposalReason[proposalId]
        );
    }

    function proposalState(
        uint256 proposalId
    )
        external
        view
        returns (
            uint64 createdAt,
            uint256 approvals,
            uint256 requiredApprovals,
            uint256 executableAt,
            bool executed,
            bool cancelled
        )
    {
        return (
            proposalCreatedAt[proposalId],
            proposalApprovals[proposalId],
            this.quorumRequired(),
            uint256(proposalCreatedAt[proposalId]) + timelockDelaySeconds,
            proposalExecuted[proposalId],
            proposalCancelled[proposalId]
        );
    }

    function proposalHasApproval(uint256 proposalId, address signer) external view returns (bool) {
        return proposalApprovedBy[proposalId][signer];
    }

    // ---------------- administration (audited, event-emitting) ----------------

    function setQuorum(uint256 quorumPercent_) external onlyGovernanceAdmin {
        _setQuorum(quorumPercent_);
    }

    function setTimelockDelay(uint256 delaySeconds) external onlyGovernanceAdmin {
        _setDelay(delaySeconds);
    }

    function _setQuorum(uint256 quorumPercent_) private {
        if (quorumPercent_ == 0 || quorumPercent_ > 100) revert QuorumOutOfRange();
        emit QuorumChanged(quorumPercent, quorumPercent_);
        quorumPercent = quorumPercent_;
    }

    function _setDelay(uint256 delaySeconds) private {
        emit TimelockDelayChanged(timelockDelaySeconds, delaySeconds);
        timelockDelaySeconds = delaySeconds;
    }

    // ---------------- proposal lifecycle ----------------

    function propose(
        OpKind kind,
        address target,
        bytes32 role,
        address account,
        uint256 tokenId,
        string calldata reason
    ) external onlySigner returns (uint256 proposalId) {
        if (kind == OpKind.NONE || kind > OpKind.DEACTIVATE_IDENTITY) revert InvalidKind();
        if (target == address(0)) revert ZeroAddress();
        // The target must be a SAMPRAAN registry that implemented the governance
        // target interface — arbitrary call targets are rejected by design.
        try ISampraanGovernanceTarget(target).sampraanGovernanceTargetVersion() returns (uint256 v) {
            if (v != 1) revert InvalidTarget();
        } catch {
            revert InvalidTarget();
        }

        proposalId = ++proposalCount;
        proposalKind[proposalId] = kind;
        proposalTarget[proposalId] = target;
        proposalRole[proposalId] = role;
        proposalAccount[proposalId] = account;
        proposalTokenId[proposalId] = tokenId;
        proposalReason[proposalId] = reason;
        proposalCreatedAt[proposalId] = uint64(block.timestamp);

        emit ProposalCreated(proposalId, kind, target, role, account, tokenId, reason, uint64(block.timestamp), msg.sender);
    }

    function approve(uint256 proposalId, string calldata reason) external onlySigner {
        if (proposalExecuted[proposalId] || proposalCancelled[proposalId]) revert ProposalNotPending();
        if (proposalApprovedBy[proposalId][msg.sender]) revert AlreadyApproved();
        proposalApprovedBy[proposalId][msg.sender] = true;
        proposalApprovals[proposalId] += 1;
        emit ProposalApproved(proposalId, msg.sender, proposalApprovals[proposalId]);
        if (bytes(reason).length > 0) {
            // Approval rationale rides on the generic approval event data via
            // a dedicated zero-topic event (keeps the approve() signature simple).
            emit ApprovalReason(proposalId, msg.sender, reason);
        }
    }

    event ApprovalReason(uint256 indexed proposalId, address indexed signer, string reason);

    function cancel(uint256 proposalId, string calldata reason) external onlySigner {
        if (proposalExecuted[proposalId]) revert AlreadyExecuted();
        if (proposalCancelled[proposalId]) revert AlreadyCancelled();
        proposalCancelled[proposalId] = true;
        emit ProposalCancelled(proposalId, msg.sender, reason);
    }

    /**
     * Execute a proposal that has reached quorum AND whose timelock elapsed.
     * The operation parameters were bound at propose() time; the target
     * contract INDEPENDENTLY re-verifies authorization (this contract holds
     * the GOVERNANCE_ROLE / platform admin role needed for the dispatch).
     */
    function execute(uint256 proposalId) external onlySigner {
        if (proposalExecuted[proposalId]) revert AlreadyExecuted();
        if (proposalCancelled[proposalId]) revert ProposalNotPending();
        if (proposalApprovals[proposalId] < this.quorumRequired()) revert NotApprovedEnough();
        if (block.timestamp < uint256(proposalCreatedAt[proposalId]) + timelockDelaySeconds) {
            revert TimelockNotElapsed();
        }

        proposalExecuted[proposalId] = true;
        OpKind kind = proposalKind[proposalId];
        address target = proposalTarget[proposalId];
        ISampraanGovernanceTarget governed = ISampraanGovernanceTarget(target);

        if (kind == OpKind.GRANT_ROLE) {
            governed.governanceGrantRole(proposalRole[proposalId], proposalAccount[proposalId]);
        } else if (kind == OpKind.REVOKE_ROLE) {
            governed.governanceRevokeRole(proposalRole[proposalId], proposalAccount[proposalId]);
        } else if (kind == OpKind.BURN_NFT) {
            governed.governanceBurnNFT(proposalTokenId[proposalId], proposalReason[proposalId]);
        } else if (kind == OpKind.FORCE_TRANSFER) {
            governed.governanceForceTransfer(proposalTokenId[proposalId], proposalAccount[proposalId], proposalReason[proposalId]);
        } else if (kind == OpKind.PAUSE_REGISTRY) {
            governed.governancePause();
        } else if (kind == OpKind.UNPAUSE_REGISTRY) {
            governed.governanceUnpause();
        } else if (kind == OpKind.DEACTIVATE_IDENTITY) {
            governed.governanceDeactivateIdentity(proposalAccount[proposalId], proposalReason[proposalId]);
        } else {
            revert InvalidKind();
        }

        emit ProposalExecuted(proposalId, kind, msg.sender, uint64(block.timestamp));
    }
}
