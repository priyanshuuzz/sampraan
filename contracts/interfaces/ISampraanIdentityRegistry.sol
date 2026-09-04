// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

/**
 * @title ISampraanIdentityRegistry
 * @notice View surface of the SAMPRAAN identity registry consumed by the asset
 *         registry. Only the status-check needed for authorization decisions.
 */
interface ISampraanIdentityRegistry {
    function isActive(address wallet) external view returns (bool);
}
