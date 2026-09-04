// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {ISampraanAccessControl} from "./interfaces/ISampraanAccessControl.sol";

/**
 * @title SampraanIdentityRegistry
 * @notice On-chain registry of SAMPRAAN identity references.
 *
 * SAMPRAAN identities are W3C DIDs managed off-chain (see drizzle/schema.ts
 * did_records). This contract stores only the *minimum on-chain reference*:
 * a keccak256 digest of the DID string, the wallet address acting for the
 * identity, an optional public-key/reference digest, and a lifecycle status.
 *
 * No PII, no private keys, no DID documents are stored on-chain. The chain is
 * the tamper-evident *anchor* for identity lifecycle state; PostgreSQL remains
 * the application/read model.
 */
contract SampraanIdentityRegistry {
    enum IdentityStatus {
        NONE, // 0 - never registered
        ACTIVE, // 1
        SUSPENDED, // 2
        REVOKED // 3
    }

    struct IdentityRecord {
        bytes32 didDigest; // keccak256 of the DID string (e.g. did:ethr:0x...)
        bytes32 publicKeyDigest; // keccak256 of the associated public key/reference
        IdentityStatus status;
        uint64 registeredAt;
        uint64 statusChangedAt;
    }

    // Wallet address => identity record.
    mapping(address => IdentityRecord) private _identities;
    // keccak256(DID) => wallet address (deterministic lookup by DID).
    mapping(bytes32 => address) private _didOwners;

    ISampraanAccessControl public immutable accessControl;

    event IdentityRegistered(
        address indexed wallet,
        bytes32 indexed didDigest,
        bytes32 publicKeyDigest,
        uint64 registeredAt
    );
    event IdentityStatusChanged(
        address indexed wallet,
        bytes32 indexed didDigest,
        IdentityStatus oldStatus,
        IdentityStatus newStatus,
        uint64 changedAt
    );

    error NotIdentityAdmin();
    error AlreadyRegistered();
    error IdentityNotRegistered();
    error SameStatus();
    error InvalidStatus();
    error ZeroAddress();
    error ZeroDidDigest();
    error NotAuthorizedOperator();
    error IdentityNotActive();
    error InvalidPublicKeyDigest();

    modifier onlyIdentityAdmin() {
        if (!accessControl.hasRole(accessControl.IDENTITY_ADMIN_ROLE(), msg.sender)) {
            revert NotIdentityAdmin();
        }
        _;
    }

    modifier onlyAuthorizedOperator() {
        // Identity state changes are performed by identity admins only.
        if (!accessControl.hasRole(accessControl.IDENTITY_ADMIN_ROLE(), msg.sender)) {
            revert NotAuthorizedOperator();
        }
        _;
    }

    constructor(address accessControlAddress) {
        if (accessControlAddress == address(0)) revert ZeroAddress();
        accessControl = ISampraanAccessControl(accessControlAddress);
    }

    /**
     * @notice Register a SAMPRAAN identity reference on-chain.
     * @param wallet Address authorized to act for this identity.
     * @param didDigest keccak256 of the DID string. The raw DID stays off-chain.
     * @param publicKeyDigest keccak256 of the public key / verification material.
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
            status: IdentityStatus.ACTIVE,
            registeredAt: uint64(block.timestamp),
            statusChangedAt: uint64(block.timestamp)
        });
        _didOwners[didDigest] = wallet;

        emit IdentityRegistered(wallet, didDigest, publicKeyDigest, uint64(block.timestamp));
    }

    /**
     * @notice Change identity lifecycle status (activate/suspend/revoke).
     * @dev Revocation is terminal in this prototype: a REVOKED identity can be
     *      re-activated only by an explicit administrative action, which is
     *      itself an audited event.
     */
    function setStatus(address wallet, IdentityStatus newStatus) external onlyAuthorizedOperator {
        IdentityRecord storage record = _identities[wallet];
        if (record.status == IdentityStatus.NONE) revert IdentityNotRegistered();
        if (newStatus == IdentityStatus.NONE) revert InvalidStatus();
        if (record.status == newStatus) revert SameStatus();

        IdentityStatus oldStatus = record.status;
        record.status = newStatus;
        record.statusChangedAt = uint64(block.timestamp);

        emit IdentityStatusChanged(wallet, record.didDigest, oldStatus, newStatus, uint64(block.timestamp));
    }

    /// @notice Read the full identity record for a wallet.
    function getIdentity(address wallet) external view returns (IdentityRecord memory) {
        return _identities[wallet];
    }

    /// @notice Resolve a DID digest to its wallet address.
    function resolveDid(bytes32 didDigest) external view returns (address) {
        return _didOwners[didDigest];
    }

    /// @notice True when the wallet is registered and ACTIVE.
    function isActive(address wallet) external view returns (bool) {
        return _identities[wallet].status == IdentityStatus.ACTIVE;
    }

    /// @notice Guard used by other SAMPRAAN contracts: reverts unless the
    ///         wallet is a registered, ACTIVE identity.
    function requireActive(address wallet) external view {
        if (_identities[wallet].status != IdentityStatus.ACTIVE) revert IdentityNotActive();
    }
}
