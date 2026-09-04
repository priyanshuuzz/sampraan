// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

/**
 * @title ISampraanAccessControl
 * @notice Read-only view of the SAMPRAAN on-chain RBAC roles consumed by the
 *         identity and asset registries. Keeping this an interface means the
 *         registries never depend on a concrete AccessControl implementation.
 */
interface ISampraanAccessControl {
    function DEFAULT_ADMIN_ROLE() external view returns (bytes32);
    function IDENTITY_ADMIN_ROLE() external view returns (bytes32);
    function ASSET_MANAGER_ROLE() external view returns (bytes32);
    function AUDITOR_ROLE() external view returns (bytes32);
    function hasRole(bytes32 role, address account) external view returns (bool);
}
