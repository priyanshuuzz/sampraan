// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";

/**
 * @title SampraanAccessControl
 * @notice Central on-chain RBAC registry for the SAMPRAAN permissioned network.
 *
 * This contract is the on-chain authority for the four SAMPRAAN enterprise
 * roles. Every protected state transition performed by SAMPRAAN contracts MUST
 * be validated here (or against a role defined here) by the smart-contract
 * layer itself. The backend policy engine is advisory: it decides *whether* a
 * request should be submitted, but this contract independently re-verifies the
 * caller's role and account status before any state transition executes.
 *
 * Roles follow least privilege:
 *  - DEFAULT_ADMIN_ROLE  : role management only (grants/revokes). Not a data operator.
 *  - IDENTITY_ADMIN_ROLE: register/update identity records.
 *  - ASSET_MANAGER_ROLE  : mint, assign, transfer, and change asset status.
 *  - AUDITOR_ROLE        : read-only. Holds no mutating capability.
 *
 * There is deliberately no "USER" role with mutating power here: enterprise
 * end users act through the backend, and any action they trigger is executed
 * by an explicitly authorized operator address (see docs/blockchain.md).
 */
contract SampraanAccessControl is AccessControl {
    bytes32 public constant IDENTITY_ADMIN_ROLE = keccak256("IDENTITY_ADMIN_ROLE");
    bytes32 public constant ASSET_MANAGER_ROLE = keccak256("ASSET_MANAGER_ROLE");
    bytes32 public constant AUDITOR_ROLE = keccak256("AUDITOR_ROLE");

    /**
     * @notice The deployer receives DEFAULT_ADMIN_ROLE (role administration)
     * and IDENTITY_ADMIN_ROLE + ASSET_MANAGER_ROLE so a single operator can
     * bootstrap the network. AUDITOR_ROLE is granted separately to the auditor
     * address(es) by the deployment script. Additional operators are added
     * with grantRole by admins only.
     */
    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(IDENTITY_ADMIN_ROLE, msg.sender);
        _grantRole(ASSET_MANAGER_ROLE, msg.sender);
    }
}
