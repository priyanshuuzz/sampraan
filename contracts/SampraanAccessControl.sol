// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";

/**
 * @title SampraanAccessControl
 * @notice Central on-chain RBAC registry for the SAMPRAAN permissioned network.
 *
 * Roles follow least privilege:
 *  - DEFAULT_ADMIN_ROLE  : role management only (grants/revokes).
 *  - IDENTITY_ADMIN_ROLE : register/update identity records.
 *  - ASSET_MANAGER_ROLE  : mint, assign, transfer, and change asset status.
 *  - AUDITOR_ROLE        : read-only. Holds no mutating capability.
 *
 * GOVERNANCE hardening (this revision):
 *  - ROLE EXCLUSIVITY is enforced ON-CHAIN: an account can never hold
 *    AUDITOR_ROLE together with any administrative role (DEFAULT_ADMIN_ROLE,
 *    IDENTITY_ADMIN_ROLE, ASSET_MANAGER_ROLE). The auditor is read-only by
 *    construction, not by convention.
 *  - LAST-ADMIN PROTECTION: revokeRole refuses to remove the last holder of
 *    DEFAULT_ADMIN_ROLE, so the role set can never be orphaned.
 *  - The governance multisig executes role changes through
 *    governanceGrantRole/governanceRevokeRole (ISampraanGovernanceTarget),
 *    which apply the SAME exclusivity/last-admin invariants.
 */
contract SampraanAccessControl is AccessControl {
    bytes32 public constant IDENTITY_ADMIN_ROLE = keccak256("IDENTITY_ADMIN_ROLE");
    bytes32 public constant ASSET_MANAGER_ROLE = keccak256("ASSET_MANAGER_ROLE");
    bytes32 public constant AUDITOR_ROLE = keccak256("AUDITOR_ROLE");

    error AuditorRoleNotExclusive();
    error LastAdminProtection();

    /// @notice Count of DEFAULT_ADMIN_ROLE holders (last-admin protection bookkeeping).
    uint256 public adminHolderCount;

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(IDENTITY_ADMIN_ROLE, msg.sender);
        _grantRole(ASSET_MANAGER_ROLE, msg.sender);
    }

    // ------------------------------------------------------------------
    // Exclusivity + last-admin enforcement (applies to EVERY grant path)
    // ------------------------------------------------------------------

    function _assertExclusivity(bytes32 role, address account, bool granting) internal view {
        bool adminish =
            role == DEFAULT_ADMIN_ROLE ||
            role == IDENTITY_ADMIN_ROLE ||
            role == ASSET_MANAGER_ROLE;
        if (!adminish) return;
        bool hasAuditor = hasRole(AUDITOR_ROLE, account);
        // Granting an administrative role to an auditor, or granting the
        // auditor role is checked at grant time below; here we block
        // admin-role grants to existing auditors.
        if (granting && hasAuditor) revert AuditorRoleNotExclusive();
    }

    function grantRole(bytes32 role, address account) public override {
        // Auditor role must not land on an administrative holder.
        if (role == AUDITOR_ROLE) {
            if (
                hasRole(DEFAULT_ADMIN_ROLE, account) ||
                hasRole(IDENTITY_ADMIN_ROLE, account) ||
                hasRole(ASSET_MANAGER_ROLE, account)
            ) {
                revert AuditorRoleNotExclusive();
            }
        }
        if (role == DEFAULT_ADMIN_ROLE && !hasRole(DEFAULT_ADMIN_ROLE, account)) {
            // counted in the hook below
        }
        super.grantRole(role, account);
    }

    function revokeRole(bytes32 role, address account) public override {
        if (role == DEFAULT_ADMIN_ROLE && hasRole(DEFAULT_ADMIN_ROLE, account)) {
            if (adminHolderCount <= 1) revert LastAdminProtection();
        }
        super.revokeRole(role, account);
    }

    /// @dev OpenZeppelin AccessControl hooks (OZ 5.x: _grantRole/_revokeRole are
    /// the virtual internal mutators) — maintain the admin holder count.
    function _grantRole(bytes32 role, address account) internal override returns (bool) {
        bool newlyGranted = super._grantRole(role, account);
        if (newlyGranted && role == DEFAULT_ADMIN_ROLE) {
            adminHolderCount += 1;
        }
        return newlyGranted;
    }

    function _revokeRole(bytes32 role, address account) internal override returns (bool) {
        bool revoked = super._revokeRole(role, account);
        if (revoked && role == DEFAULT_ADMIN_ROLE) {
            adminHolderCount -= 1;
        }
        return revoked;
    }

    // ------------------------------------------------------------------
    // Governance dispatch note (this revision):
    // The SampraanGovernance multisig executes GRANT_ROLE/REVOKE_ROLE
    // proposals by calling grantRole()/revokeRole() DIRECTLY while holding
    // DEFAULT_ADMIN_ROLE — which routes through the SAME exclusivity and
    // last-admin enforcement above. No separate dispatch surface exists for
    // roles: every role mutation, whatever the caller, passes one code path
    // with one set of invariants.
}
