// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

/**
 * @title ISampraanGovernanceTarget
 * @notice Dispatch surface the SampraanGovernance multisig calls to execute
 *         approved high-risk operations on SAMPRAAN registries. Implementing
 *         contracts MUST re-verify that the caller is the governance contract
 *         before applying any state change.
 */
interface ISampraanGovernanceTarget {
    /// @notice Interface marker (returned version); used by propose() to reject arbitrary targets.
    function sampraanGovernanceTargetVersion() external view returns (uint256);

    function governanceGrantRole(bytes32 role, address account) external;
    function governanceRevokeRole(bytes32 role, address account) external;
    function governanceBurnNFT(uint256 tokenId, string calldata reason) external;
    function governanceForceTransfer(uint256 tokenId, address toCustodian, string calldata reason) external;
    function governancePause() external;
    function governanceUnpause() external;
    function governanceDeactivateIdentity(address wallet, string calldata reason) external;
}
