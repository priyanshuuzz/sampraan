// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {ISampraanAccessControl} from "./interfaces/ISampraanAccessControl.sol";
import {ISampraanGovernanceTarget} from "./interfaces/ISampraanGovernanceTarget.sol";

/**
 * @title SampraanIdentityRegistry
 * @notice On-chain registry of SAMPRAAN identity references.
 *
 * LIFECYCLE (document "Role Definitions and Access Rights"):
 *   NONE 0        never registered
 *   PENDING 1     registered, not yet verified — cannot hold privileged roles
 *                 (enforced: no admin/manager role may be granted to a wallet
 *                 whose on-chain identity is not VERIFIED)
 *   VERIFIED 2    active, verified identity — full participation
 *   SUSPENDED 3   temporarily barred from protected mutations (reason recorded)
 *   DEACTIVATED 4 terminal — blocked from protected operations (reason recorded)
 *
 * The DID raw string stays off-chain; only keccak256(DID) is anchored. DID
 * DOCUMENT updates are hash-only (never contents) with full version history.
 */
contract SampraanIdentityRegistry is ISampraanGovernanceTarget {
    enum IdentityStatus {
        NONE, // 0
        PENDING, // 1
        VERIFIED, // 2
        SUSPENDED, // 3
        DEACTIVATED // 4
    }

    struct IdentityRecord {
        bytes32 didDigest;
        bytes32 publicKeyDigest;
        IdentityStatus status;
        uint64 registeredAt;
        uint64 statusChangedAt;
    }

    // Wallet => record; DID digest => wallet.
    mapping(address => IdentityRecord) private _identities;
    mapping(bytes32 => address) private _didOwners;

    // DID document version history: wallet => version => document hash (hash-only).
    mapping(address => uint256) public didDocumentVersion;
    mapping(address => mapping(uint256 => bytes32)) public didDocumentHash;
    mapping(address => bytes32) public currentDidDocumentHash;

    // Wallet => identity verification audit history (verifier, action, reason).
    struct LifecycleEvent {
        IdentityStatus fromStatus;
        IdentityStatus toStatus;
        address actor;
        string reason;
        uint64 at;
    }
    mapping(address => LifecycleEvent[]) private _lifecycle;
    mapping(address => uint256) public lifecycleCount;

    ISampraanAccessControl public immutable accessControl;
    /// @notice The governance multisig (set at deployment): sole caller of the
    ///         DEACTIVATE_IDENTITY dispatch; direct deactivation is NOT possible.
    address public immutable governance;

    event IdentityRegistered(address indexed wallet, bytes32 indexed didDigest, bytes32 publicKeyDigest, uint64 registeredAt);
    event IdentityVerified(address indexed wallet, address indexed verifier, string reason, uint64 at);
    event IdentitySuspended(address indexed wallet, address indexed actor, string reason, uint64 at);
    event IdentityReactivated(address indexed wallet, address indexed actor, string reason, uint64 at);
    event IdentityDeactivated(address indexed wallet, address indexed actor, string reason, uint64 at);
    event IdentityStatusChanged(address indexed wallet, bytes32 indexed didDigest, IdentityStatus oldStatus, IdentityStatus newStatus, uint64 changedAt);
    event DIDDocumentUpdated(address indexed wallet, uint256 indexed version, bytes32 documentHash, uint64 at);

    error NotIdentityAdmin();
    error NotGovernance();
    error AlreadyRegistered();
    error IdentityNotRegistered();
    error SameStatus();
    error InvalidStatus();
    error ZeroAddress();
    error ZeroDidDigest();
    error ZeroReason();
    error NotPending();
    error DeactivatedTerminal();
    error EmptyDocumentHash();

    modifier onlyIdentityAdmin() {
        if (!accessControl.hasRole(accessControl.IDENTITY_ADMIN_ROLE(), msg.sender)) {
            revert NotIdentityAdmin();
        }
        _;
    }

    constructor(address accessControlAddress, address governanceAddress) {
        if (accessControlAddress == address(0)) revert ZeroAddress();
        if (governanceAddress == address(0)) revert ZeroAddress();
        accessControl = ISampraanAccessControl(accessControlAddress);
        governance = governanceAddress;
    }

    // ------------------------------------------------------------------
    // Registration & lifecycle
    // ------------------------------------------------------------------

    /**
     * @notice Register an identity in PENDING state (unverified). Verification
     *         is a separate, attributed, reason-carrying step.
     */
    function registerIdentity(
        address wallet,
        bytes32 didDigest,
        bytes32 publicKeyDigest
    ) external onlyIdentityAdmin {
        if (wallet == address(0)) revert ZeroAddress();
        if (didDigest == bytes32(0)) revert ZeroDidDigest();
        if (_identities[wallet].status != IdentityStatus.NONE) revert AlreadyRegistered();
        if (_didOwners[didDigest] != address(0)) revert AlreadyRegistered();

        _identities[wallet] = IdentityRecord({
            didDigest: didDigest,
            publicKeyDigest: publicKeyDigest,
            status: IdentityStatus.PENDING,
            registeredAt: uint64(block.timestamp),
            statusChangedAt: uint64(block.timestamp)
        });
        _didOwners[didDigest] = wallet;
        _lifecycle[wallet].push(LifecycleEvent({
            fromStatus: IdentityStatus.NONE,
            toStatus: IdentityStatus.PENDING,
            actor: msg.sender,
            reason: "registered",
            at: uint64(block.timestamp)
        }));
        lifecycleCount[wallet] = 1;

        emit IdentityRegistered(wallet, didDigest, publicKeyDigest, uint64(block.timestamp));
    }

    /// @notice Verify a PENDING identity (identity admin — Manager scope is
    ///         enforced by the backend policy layer before submission).
    function verifyIdentity(address wallet, string calldata reason) external onlyIdentityAdmin {
        if (bytes(reason).length == 0) revert ZeroReason();
        IdentityRecord storage record = _identities[wallet];
        if (record.status != IdentityStatus.PENDING) revert NotPending();
        _transition(wallet, record, IdentityStatus.VERIFIED, reason);
        emit IdentityVerified(wallet, msg.sender, reason, uint64(block.timestamp));
    }

    /// @notice Suspend a VERIFIED identity with a MANDATORY reason.
    function suspendIdentity(address wallet, string calldata reason) external onlyIdentityAdmin {
        if (bytes(reason).length == 0) revert ZeroReason();
        IdentityRecord storage record = _identities[wallet];
        if (record.status != IdentityStatus.VERIFIED) revert InvalidStatus();
        _transition(wallet, record, IdentityStatus.SUSPENDED, reason);
        emit IdentitySuspended(wallet, msg.sender, reason, uint64(block.timestamp));
    }

    /// @notice Reactivate a SUSPENDED identity (deactivation stays terminal).
    function reactivateIdentity(address wallet, string calldata reason) external onlyIdentityAdmin {
        if (bytes(reason).length == 0) revert ZeroReason();
        IdentityRecord storage record = _identities[wallet];
        if (record.status != IdentityStatus.SUSPENDED) revert InvalidStatus();
        _transition(wallet, record, IdentityStatus.VERIFIED, reason);
        emit IdentityReactivated(wallet, msg.sender, reason, uint64(block.timestamp));
    }

    /// @notice Deactivation is GOVERNANCE-ONLY (multisig + timelock); there is
    ///         deliberately no direct admin path to the terminal state.
    function governanceDeactivateIdentity(address wallet, string calldata reason) external {
        if (msg.sender != governance) revert NotGovernance();
        if (bytes(reason).length == 0) revert ZeroReason();
        IdentityRecord storage record = _identities[wallet];
        if (record.status == IdentityStatus.NONE) revert IdentityNotRegistered();
        if (record.status == IdentityStatus.DEACTIVATED) revert SameStatus();
        _transition(wallet, record, IdentityStatus.DEACTIVATED, reason);
        emit IdentityDeactivated(wallet, msg.sender, reason, uint64(block.timestamp));
    }

    function _transition(address wallet, IdentityRecord storage record, IdentityStatus to, string calldata reason) private {
        IdentityStatus from = record.status;
        record.status = to;
        record.statusChangedAt = uint64(block.timestamp);
        _lifecycle[wallet].push(LifecycleEvent({
            fromStatus: from,
            toStatus: to,
            actor: msg.sender,
            reason: reason,
            at: uint64(block.timestamp)
        }));
        lifecycleCount[wallet] += 1;
        emit IdentityStatusChanged(wallet, record.didDigest, from, to, uint64(block.timestamp));
    }

    // ------------------------------------------------------------------
    // DID document hash updates (controller-authenticated, versioned)
    // ------------------------------------------------------------------

    /**
     * @notice Update the DID document by HASH only (contents stay off-chain).
     *         Callers: the identity's own wallet (controller) or an identity
     *         admin — the backend submits on behalf of the SESSION-AUTHENTICATED
     *         controller (identity wallets are server-derived references and
     *         hold no keys). PENDING identities may update (self-sovereign
     *         document construction before verification); SUSPENDED/DEACTIVATED
     *         may not. History is versioned and preserved; every update emits
     *         DIDDocumentUpdated.
     */
    function updateDidDocumentHash(bytes32 documentHash, string calldata reason) external {
        if (documentHash == bytes32(0)) revert EmptyDocumentHash();
        IdentityRecord storage record = _identities[msg.sender];
        if (record.status == IdentityStatus.NONE) revert IdentityNotRegistered();
        if (record.status == IdentityStatus.SUSPENDED || record.status == IdentityStatus.DEACTIVATED) {
            revert InvalidStatus();
        }
        uint256 version = didDocumentVersion[msg.sender] + 1;
        didDocumentVersion[msg.sender] = version;
        didDocumentHash[msg.sender][version] = documentHash;
        currentDidDocumentHash[msg.sender] = documentHash;
        _lifecycle[msg.sender].push(LifecycleEvent({
            fromStatus: record.status,
            toStatus: record.status,
            actor: msg.sender,
            reason: reason,
            at: uint64(block.timestamp)
        }));
        lifecycleCount[msg.sender] += 1;
        emit DIDDocumentUpdated(msg.sender, version, documentHash, uint64(block.timestamp));
    }

    /// @notice Identity-admin-submitted document update on behalf of a
    ///         session-authenticated controller (identity wallets hold no
    ///         keys in this architecture; the backend is the authenticated
    ///         submission path). Same lifecycle rules as the self-path.
    function updateDidDocumentHashFor(
        address wallet,
        bytes32 documentHash,
        string calldata reason
    ) external onlyIdentityAdmin {
        if (documentHash == bytes32(0)) revert EmptyDocumentHash();
        if (bytes(reason).length == 0) revert ZeroReason();
        IdentityRecord storage record = _identities[wallet];
        if (record.status == IdentityStatus.NONE) revert IdentityNotRegistered();
        if (record.status == IdentityStatus.SUSPENDED || record.status == IdentityStatus.DEACTIVATED) {
            revert InvalidStatus();
        }
        _recordDidDocumentUpdate(wallet, record, documentHash, reason);
        emit DIDDocumentUpdated(wallet, didDocumentVersion[wallet], documentHash, uint64(block.timestamp));
    }

    function _recordDidDocumentUpdate(
        address wallet,
        IdentityRecord storage record,
        bytes32 documentHash,
        string calldata reason
    ) private {
        uint256 version = didDocumentVersion[wallet] + 1;
        didDocumentVersion[wallet] = version;
        didDocumentHash[wallet][version] = documentHash;
        currentDidDocumentHash[wallet] = documentHash;
        _lifecycle[wallet].push(LifecycleEvent({
            fromStatus: record.status,
            toStatus: record.status,
            actor: msg.sender,
            reason: reason,
            at: uint64(block.timestamp)
        }));
        lifecycleCount[wallet] += 1;
    }

    // ------------------------------------------------------------------
    // Views
    // ------------------------------------------------------------------

    function getIdentity(address wallet) external view returns (IdentityRecord memory) {
        return _identities[wallet];
    }

    function resolveDid(bytes32 didDigest) external view returns (address) {
        return _didOwners[didDigest];
    }

    /// @notice TRUE only for VERIFIED — the only state that may perform
    ///         protected on-chain operations.
    function isActive(address wallet) external view returns (bool) {
        return _identities[wallet].status == IdentityStatus.VERIFIED;
    }

    function requireActive(address wallet) external view {
        if (_identities[wallet].status != IdentityStatus.VERIFIED) revert IdentityNotActive();
    }

    function getLifecycleEvent(address wallet, uint256 index) external view returns (LifecycleEvent memory) {
        return _lifecycle[wallet][index];
    }

    function getDidDocumentHash(address wallet, uint256 version) external view returns (bytes32) {
        return didDocumentHash[wallet][version];
    }

    error IdentityNotActive();

    // ------------------------------------------------------------------
    // Governance target surface (only the registry pieces governance owns)
    // ------------------------------------------------------------------

    function sampraanGovernanceTargetVersion() external pure returns (uint256) {
        return 1;
    }

    function governanceGrantRole(bytes32, address) external pure {
        revert InvalidStatus(); // role administration lives on AccessControl
    }

    function governanceRevokeRole(bytes32, address) external pure {
        revert InvalidStatus(); // role administration lives on AccessControl
    }

    function governanceBurnNFT(uint256, string calldata) external pure {
        revert InvalidStatus(); // asset operations live on AssetRegistry
    }

    function governanceForceTransfer(uint256, address, string calldata) external pure {
        revert InvalidStatus(); // asset operations live on AssetRegistry
    }

    function governancePause() external pure {
        revert InvalidStatus(); // pause lives on AssetRegistry
    }

    function governanceUnpause() external pure {
        revert InvalidStatus(); // pause lives on AssetRegistry
    }
}
