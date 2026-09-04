// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {ERC721} from "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import {ISampraanAccessControl} from "./interfaces/ISampraanAccessControl.sol";
import {ISampraanIdentityRegistry} from "./interfaces/ISampraanIdentityRegistry.sol";

/**
 * @title SampraanAssetRegistry
 * @notice Controlled, permissioned enterprise asset registry (ERC-721 semantics
 *         without marketplace behavior).
 *
 * Each enterprise digital asset (firmware package, test instrument, design
 * document, cryptographic material reference, technical specification) is a
 * unique token. Only the metadata *reference hash* is stored on-chain:
 * classification digest, status digest, and integrity/reference digest.
 * Sensitive files, PII, and document contents remain OFF-CHAIN.
 *
 * Security model (defense in depth):
 *  1. The backend authorization engine decides whether to submit a request.
 *  2. This contract INDEPENDENTLY re-verifies caller role, actor identity
 *     status, asset status, and target identity status before any transition.
 * The chain is the final authority on state transitions; it never trusts the
 * backend decision.
 *
 * ERC-721 marketplace primitives (approve, setApprovalForAll, transferFrom,
 * safeTransferFrom) are deliberately disabled: enterprise custody transfers
 * MUST go through transferCustody(), which enforces SAMPRAAN rules.
 */
contract SampraanAssetRegistry is ERC721 {
    enum AssetStatus {
        NONE, // 0 - never registered
        PENDING, // 1 - registered, not yet activated
        ACTIVE, // 2
        SUSPENDED, // 3
        REVOKED // 4 - terminal
    }

    struct AssetRecord {
        bytes32 assetIdDigest; // keccak256 of the off-chain asset identifier
        bytes32 classificationDigest; // keccak256 of classification (e.g. HIGHLY_SENSITIVE)
        bytes32 metadataDigest; // keccak256 of the off-chain metadata/content reference or integrity hash
        AssetStatus status;
        address custodian; // current custodian wallet (identity reference)
        uint64 registeredAt;
        uint64 statusChangedAt;
    }

    ISampraanAccessControl public immutable accessControl;
    ISampraanIdentityRegistry public immutable identityRegistry;

    // tokenId => asset record
    mapping(uint256 => AssetRecord) private _assets;
    // keccak256(assetId) => tokenId (deterministic idempotent registration)
    mapping(bytes32 => uint256) private _assetIdToToken;
    uint256 private _nextTokenId = 1;

    event AssetRegistered(
        uint256 indexed tokenId,
        bytes32 indexed assetIdDigest,
        address indexed custodian,
        bytes32 classificationDigest,
        bytes32 metadataDigest,
        uint64 registeredAt
    );
    event AssetAssigned(
        uint256 indexed tokenId,
        bytes32 indexed assetIdDigest,
        address indexed custodian,
        address operator,
        uint64 assignedAt
    );
    event AssetTransferred(
        uint256 indexed tokenId,
        bytes32 indexed assetIdDigest,
        address indexed fromCustodian,
        address toCustodian,
        address operator,
        uint64 transferredAt
    );
    event AssetStatusChanged(
        uint256 indexed tokenId,
        bytes32 indexed assetIdDigest,
        AssetStatus oldStatus,
        AssetStatus newStatus,
        address indexed operator,
        uint64 changedAt
    );

    error NotAssetManager();
    error NotAuthorizedOperator();
    error ZeroAddress();
    error ZeroDigest();
    error AssetAlreadyRegistered();
    error AssetNotRegistered();
    error InvalidAssetStatus();
    error SameAssetStatus();
    error AssetNotActive();
    error CustodianNotActive();
    error RecipientNotActive();
    error OperatorNotAuthorized();
    error CustodyTransferForbidden();

    modifier onlyAssetManager() {
        if (!accessControl.hasRole(accessControl.ASSET_MANAGER_ROLE(), msg.sender)) {
            revert NotAssetManager();
        }
        _;
    }

    modifier onlyAuthorizedOperator() {
        if (!accessControl.hasRole(accessControl.ASSET_MANAGER_ROLE(), msg.sender)) {
            revert NotAuthorizedOperator();
        }
        _;
    }

    constructor(
        address accessControlAddress,
        address identityRegistryAddress
    ) ERC721("SAMPRAAN Enterprise Asset", "SMPRA") {
        if (accessControlAddress == address(0)) revert ZeroAddress();
        if (identityRegistryAddress == address(0)) revert ZeroAddress();
        accessControl = ISampraanAccessControl(accessControlAddress);
        identityRegistry = ISampraanIdentityRegistry(identityRegistryAddress);
    }

    // ------------------------------------------------------------------
    // Registration / mint
    // ------------------------------------------------------------------

    /**
     * @notice Register (mint) an enterprise asset as a controlled token.
     * @param assetIdDigest keccak256 of the off-chain asset identifier.
     * @param custodian Initial custodian wallet (must be an ACTIVE identity).
     * @param classificationDigest keccak256 of the asset classification.
     * @param metadataDigest keccak256 of the off-chain metadata/content reference.
     */
    function registerAsset(
        bytes32 assetIdDigest,
        address custodian,
        bytes32 classificationDigest,
        bytes32 metadataDigest
    ) external onlyAssetManager returns (uint256 tokenId) {
        if (assetIdDigest == bytes32(0)) revert ZeroDigest();
        if (custodian == address(0)) revert ZeroAddress();
        if (_assetIdToToken[assetIdDigest] != 0) revert AssetAlreadyRegistered();
        if (!identityRegistry.isActive(custodian)) revert CustodianNotActive();

        tokenId = _nextTokenId++;
        _assets[tokenId] = AssetRecord({
            assetIdDigest: assetIdDigest,
            classificationDigest: classificationDigest,
            metadataDigest: metadataDigest,
            status: AssetStatus.PENDING,
            custodian: custodian,
            registeredAt: uint64(block.timestamp),
            statusChangedAt: uint64(block.timestamp)
        });
        _assetIdToToken[assetIdDigest] = tokenId;

        // Enterprise custodians are externally-owned operator wallets, so the
        // plain mint is intentional: no onERC721Received receiver hook is
        // required and no uncontrolled contract callback is invoked.
        _mint(custodian, tokenId);

        emit AssetRegistered(
            tokenId,
            assetIdDigest,
            custodian,
            classificationDigest,
            metadataDigest,
            uint64(block.timestamp)
        );
    }

    // ------------------------------------------------------------------
    // Assignment / custody transfer (controlled, non-marketplace)
    // ------------------------------------------------------------------

    /**
     * @notice Assign an asset to a custodian. Allowed while the asset is in a
     *         registrable state; enforced per status rules.
     */
    function assignAsset(uint256 tokenId, address custodian) external onlyAuthorizedOperator {
        AssetRecord storage asset = _assets[tokenId];
        if (asset.status == AssetStatus.NONE) revert AssetNotRegistered();
        if (custodian == address(0)) revert ZeroAddress();
        if (custodian == asset.custodian) revert SameAssetStatus();
        if (!identityRegistry.isActive(custodian)) revert RecipientNotActive();
        // Assignment allowed for PENDING and ACTIVE assets only.
        if (asset.status == AssetStatus.SUSPENDED || asset.status == AssetStatus.REVOKED) {
            revert AssetNotActive();
        }

        address previous = asset.custodian;
        asset.custodian = custodian;

        emit AssetAssigned(tokenId, asset.assetIdDigest, custodian, msg.sender, uint64(block.timestamp));

        // Keep ERC-721 internal ownership aligned with custodian state.
        if (ownerOf(tokenId) != custodian) {
            _transfer(previous, custodian, tokenId);
        }
    }

    /**
     * @notice Controlled custody transfer. The heart of SAMPRAAN authorization-
     *         enforced transfers.
     *
     * Requirements enforced ON-CHAIN (independent of any backend decision):
     *  - caller holds ASSET_MANAGER_ROLE
     *  - asset is registered and ACTIVE (suspended/revoked assets are frozen)
     *  - current custodian identity is still ACTIVE
     *  - recipient identity is registered and ACTIVE
     */
    function transferCustody(uint256 tokenId, address toCustodian) external onlyAuthorizedOperator {
        AssetRecord storage asset = _assets[tokenId];
        if (asset.status == AssetStatus.NONE) revert AssetNotRegistered();
        if (asset.status != AssetStatus.ACTIVE) revert AssetNotActive();
        if (toCustodian == address(0)) revert ZeroAddress();
        if (toCustodian == asset.custodian) revert SameAssetStatus();
        if (!identityRegistry.isActive(asset.custodian)) revert CustodianNotActive();
        if (!identityRegistry.isActive(toCustodian)) revert RecipientNotActive();

        address fromCustodian = asset.custodian;
        asset.custodian = toCustodian;
        asset.statusChangedAt = uint64(block.timestamp);

        _transfer(fromCustodian, toCustodian, tokenId);

        emit AssetTransferred(
            tokenId,
            asset.assetIdDigest,
            fromCustodian,
            toCustodian,
            msg.sender,
            uint64(block.timestamp)
        );
    }

    // ------------------------------------------------------------------
    // Asset status controls
    // ------------------------------------------------------------------

    /// @notice Activate a PENDING asset.
    function activateAsset(uint256 tokenId) external onlyAuthorizedOperator {
        _changeStatus(tokenId, AssetStatus.ACTIVE);
    }

    /// @notice Suspend an ACTIVE asset (freezes transfers/assignments).
    function suspendAsset(uint256 tokenId) external onlyAuthorizedOperator {
        _changeStatus(tokenId, AssetStatus.SUSPENDED);
    }

    /// @notice Restore a SUSPENDED asset back to ACTIVE.
    function restoreAsset(uint256 tokenId) external onlyAuthorizedOperator {
        _changeStatus(tokenId, AssetStatus.ACTIVE);
    }

    /// @notice Revoke an asset permanently (terminal state).
    function revokeAsset(uint256 tokenId) external onlyAuthorizedOperator {
        _changeStatus(tokenId, AssetStatus.REVOKED);
    }

    function _changeStatus(uint256 tokenId, AssetStatus newStatus) private {
        AssetRecord storage asset = _assets[tokenId];
        if (asset.status == AssetStatus.NONE) revert AssetNotRegistered();
        if (asset.status == newStatus) revert SameAssetStatus();
        // Revocation is terminal.
        if (asset.status == AssetStatus.REVOKED) revert InvalidAssetStatus();
        // Transitions allowed: PENDING->ACTIVE, ACTIVE->SUSPENDED/REVOKED, SUSPENDED->ACTIVE/REVOKED.
        if (
            (asset.status == AssetStatus.PENDING && newStatus != AssetStatus.ACTIVE) ||
            (asset.status == AssetStatus.ACTIVE &&
                newStatus != AssetStatus.SUSPENDED &&
                newStatus != AssetStatus.REVOKED) ||
            (asset.status == AssetStatus.SUSPENDED &&
                newStatus != AssetStatus.ACTIVE &&
                newStatus != AssetStatus.REVOKED)
        ) {
            revert InvalidAssetStatus();
        }

        AssetStatus oldStatus = asset.status;
        asset.status = newStatus;
        asset.statusChangedAt = uint64(block.timestamp);

        emit AssetStatusChanged(
            tokenId,
            asset.assetIdDigest,
            oldStatus,
            newStatus,
            msg.sender,
            uint64(block.timestamp)
        );
    }

    // ------------------------------------------------------------------
    // Views
    // ------------------------------------------------------------------

    function getAsset(uint256 tokenId) external view returns (AssetRecord memory) {
        if (_assets[tokenId].status == AssetStatus.NONE) revert AssetNotRegistered();
        return _assets[tokenId];
    }

    function resolveAssetId(bytes32 assetIdDigest) external view returns (uint256) {
        return _assetIdToToken[assetIdDigest];
    }

    function assetStatus(uint256 tokenId) external view returns (AssetStatus) {
        if (_assets[tokenId].status == AssetStatus.NONE) revert AssetNotRegistered();
        return _assets[tokenId].status;
    }

    function custodianOf(uint256 tokenId) external view returns (address) {
        if (_assets[tokenId].status == AssetStatus.NONE) revert AssetNotRegistered();
        return _assets[tokenId].custodian;
    }

    function totalAssets() external view returns (uint256) {
        return _nextTokenId - 1;
    }

    /**
     * @notice Off-chain metadata reference. Returns a descriptive string built
     *         from the on-chain digests; the actual document/metadata stays
     *         off-chain (S3/PostgreSQL) and is resolved by the backend.
     */
    function tokenURI(uint256 tokenId) public view override returns (string memory) {
        AssetRecord memory asset = _assets[tokenId];
        if (asset.status == AssetStatus.NONE) revert AssetNotRegistered();
        return string(
            abi.encodePacked(
                "sampraan://asset/",
                _toHexString(asset.assetIdDigest),
                "/metadata/",
                _toHexString(asset.metadataDigest)
            )
        );
    }

    // ------------------------------------------------------------------
    // Marketplace primitives are DISABLED by design
    // ------------------------------------------------------------------

    /// @dev SAMPRAAN assets cannot be approved for arbitrary transfer.
    function approve(address, uint256) public pure override {
        revert CustodyTransferForbidden();
    }

    /// @dev SAMPRAAN assets cannot be delegated to operators.
    function setApprovalForAll(address, bool) public pure override {
        revert CustodyTransferForbidden();
    }

    /// @dev Raw ERC-721 transfer is disabled; use transferCustody().
    function transferFrom(address, address, uint256) public pure override {
        revert CustodyTransferForbidden();
    }

    /// @dev Raw ERC-721 safe transfer is disabled; use transferCustody().
    ///      The 3-argument form in OpenZeppelin v5 is non-virtual and simply
    ///      forwards to this 4-argument virtual function, so it is blocked too.
    function safeTransferFrom(address, address, uint256, bytes memory) public pure override {
        revert CustodyTransferForbidden();
    }

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    function _toHexString(bytes32 value) private pure returns (string memory) {
        bytes memory alphabet = "0123456789abcdef";
        bytes memory buffer = new bytes(66);
        buffer[0] = "0";
        buffer[1] = "x";
        for (uint256 i = 0; i < 32; i++) {
            buffer[2 + i * 2] = alphabet[uint8(value[i] >> 4)];
            buffer[3 + i * 2] = alphabet[uint8(value[i] & 0x0f)];
        }
        return string(buffer);
    }
}
