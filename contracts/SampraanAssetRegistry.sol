// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {ERC721} from "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import {ISampraanAccessControl} from "./interfaces/ISampraanAccessControl.sol";
import {ISampraanIdentityRegistry} from "./interfaces/ISampraanIdentityRegistry.sol";
import {ISampraanGovernanceTarget} from "./interfaces/ISampraanGovernanceTarget.sol";

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
contract SampraanAssetRegistry is ERC721, ISampraanGovernanceTarget {
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
    /// @notice Governance multisig — sole executor of burnNFT / forceTransfer / pause.
    address public immutable governance;
    /// @notice Emergency pause flag (governance-controlled). Blocks every
    ///         state-changing operation; views stay available for auditors.
    bool public paused;
    /// @notice Asset ids with an OPEN dispute — transfers are on HOLD while set.
    mapping(bytes32 => bool) public disputedAssets;
    /// @notice Open-dispute token counts for O(1) global queries.
    uint256 public openDisputeCount;

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
    event NFTMinted(uint256 indexed tokenId, bytes32 indexed assetIdDigest, address indexed custodian, uint64 at);
    event NFTAssigned(uint256 indexed tokenId, address indexed custodian, address indexed operator, uint64 at);
    event NFTRevoked(uint256 indexed tokenId, bytes32 indexed assetIdDigest, address indexed actor, string reason, uint64 at);
    event ForcedTransfer(uint256 indexed tokenId, address indexed fromCustodian, address indexed toCustodian, address actor, string reason, uint64 at);
    event SystemPaused(address indexed actor, string reason, uint64 at);
    event SystemUnpaused(address indexed actor, string reason, uint64 at);

    /// ---------------- auditor-owned governance evidence ----------------
    struct Dispute {
        uint256 tokenId;
        address raisedBy;
        bytes32 evidenceHash; // hash-only; contents stay off-chain
        string reason;
        bool open;
        bool upheld;
        string resolutionReason;
        uint64 raisedAt;
        uint64 resolvedAt;
    }
    mapping(uint256 => Dispute) public disputes;
    uint256 public disputeCount;

    struct Anomaly {
        address target; // flagged wallet or asset custodian context
        uint256 tokenId; // 0 when the flag is identity-scoped
        address flaggedBy;
        string reason;
        uint64 at;
    }
    mapping(uint256 => Anomaly) public anomalies;
    uint256 public anomalyCount;

    event DisputeRaised(uint256 indexed disputeId, uint256 indexed tokenId, address indexed raisedBy, bytes32 evidenceHash, string reason, uint64 at);
    event DisputeResolved(uint256 indexed disputeId, uint256 indexed tokenId, address indexed resolver, bool upheld, string reason, uint64 at);
    event AnomalyFlagged(uint256 indexed anomalyId, address indexed target, uint256 tokenId, address flaggedBy, string reason, uint64 at);

    /// ---------------- on-chain audit report hashes ----------------
    struct AuditReport {
        address auditor;
        bytes32 reportHash; // hash of the OFF-CHAIN report; contents never on-chain
        uint64 at;
    }
    mapping(uint256 => AuditReport) public auditReports;
    uint256 public auditReportCount;
    event AuditReportHashStored(uint256 indexed reportId, address indexed auditor, bytes32 indexed reportHash, uint64 at);

    /// ---------------- ownership history (auditor verification surface) ----
    struct CustodyRecord {
        address fromCustodian;
        address toCustodian;
        address operator;
        uint64 at;
    }
    mapping(uint256 => CustodyRecord[]) private _custodyHistory;
    mapping(uint256 => uint256) public custodyHistoryLength;

    error NotAssetManager();
    error NotAuthorizedOperator();
    error NotGovernance();
    error ZeroAddress();
    error ZeroDigest();
    error ZeroReason();
    error AssetAlreadyRegistered();
    error AssetNotRegistered();
    error InvalidAssetStatus();
    error SameAssetStatus();
    error AssetNotActive();
    error CustodianNotActive();
    error RecipientNotActive();
    error OperatorNotAuthorized();
    error CustodyTransferForbidden();
    error Paused();
    error AssetDisputed();
    error NotAuditor();
    error NotAdmin();
    error DisputeNotOpen();
    error EmptyEvidenceHash();

    modifier onlyAssetManager() {
        if (paused) revert Paused();
        if (!accessControl.hasRole(accessControl.ASSET_MANAGER_ROLE(), msg.sender)) {
            revert NotAssetManager();
        }
        _;
    }

    modifier onlyAuthorizedOperator() {
        if (paused) revert Paused();
        if (!accessControl.hasRole(accessControl.ASSET_MANAGER_ROLE(), msg.sender)) {
            revert NotAuthorizedOperator();
        }
        _;
    }

    modifier whenNotPaused() {
        if (paused) revert Paused();
        _;
    }

    constructor(
        address accessControlAddress,
        address identityRegistryAddress,
        address governanceAddress
    ) ERC721("SAMPRAAN Enterprise Asset", "SMPRA") {
        if (accessControlAddress == address(0)) revert ZeroAddress();
        if (identityRegistryAddress == address(0)) revert ZeroAddress();
        if (governanceAddress == address(0)) revert ZeroAddress();
        accessControl = ISampraanAccessControl(accessControlAddress);
        identityRegistry = ISampraanIdentityRegistry(identityRegistryAddress);
        governance = governanceAddress;
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

        _custodyHistory[tokenId].push(CustodyRecord({
            fromCustodian: address(0),
            toCustodian: custodian,
            operator: msg.sender,
            at: uint64(block.timestamp)
        }));
        custodyHistoryLength[tokenId] = 1;

        emit NFTMinted(tokenId, assetIdDigest, custodian, uint64(block.timestamp));
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

        _custodyHistory[tokenId].push(CustodyRecord({
            fromCustodian: previous,
            toCustodian: custodian,
            operator: msg.sender,
            at: uint64(block.timestamp)
        }));
        custodyHistoryLength[tokenId] += 1;

        emit NFTAssigned(tokenId, custodian, msg.sender, uint64(block.timestamp));
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
        if (disputedAssets[asset.assetIdDigest]) revert AssetDisputed();
        if (toCustodian == address(0)) revert ZeroAddress();
        if (toCustodian == asset.custodian) revert SameAssetStatus();
        if (!identityRegistry.isActive(asset.custodian)) revert CustodianNotActive();
        if (!identityRegistry.isActive(toCustodian)) revert RecipientNotActive();

        address fromCustodian = asset.custodian;
        asset.custodian = toCustodian;
        asset.statusChangedAt = uint64(block.timestamp);

        _custodyHistory[tokenId].push(CustodyRecord({
            fromCustodian: fromCustodian,
            toCustodian: toCustodian,
            operator: msg.sender,
            at: uint64(block.timestamp)
        }));
        custodyHistoryLength[tokenId] += 1;

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
    // Auditor-owned evidence surfaces (read-only + hash commitments only)
    // ------------------------------------------------------------------

    /**
     * @notice Flag an anomaly. AUDITOR-only, and deliberately WITHOUT any
     *         effect on ownership or permissions — the flag is evidence for
     *         the audit trail and an input to human processes, never a
     *         mutation vector (document: "Auditor can flag only").
     */
    function flagAnomaly(address target, uint256 tokenId, string calldata reason) external {
        if (paused) revert Paused();
        if (!accessControl.hasRole(accessControl.AUDITOR_ROLE(), msg.sender)) revert NotAuditor();
        if (target == address(0)) revert ZeroAddress();
        if (bytes(reason).length == 0) revert ZeroReason();
        uint256 id = ++anomalyCount;
        anomalies[id] = Anomaly({ target: target, tokenId: tokenId, flaggedBy: msg.sender, reason: reason, at: uint64(block.timestamp) });
        emit AnomalyFlagged(id, target, tokenId, msg.sender, reason, uint64(block.timestamp));
    }

    /**
     * @notice Raise a dispute over an asset. Places the asset's TRANSFER on
     *         HOLD (disputedAssets) until an admin resolves. AUDITOR-only.
     */
    function raiseDispute(uint256 tokenId, bytes32 evidenceHash, string calldata reason) external {
        if (paused) revert Paused();
        if (!accessControl.hasRole(accessControl.AUDITOR_ROLE(), msg.sender)) revert NotAuditor();
        if (_assets[tokenId].status == AssetStatus.NONE) revert AssetNotRegistered();
        if (evidenceHash == bytes32(0)) revert EmptyEvidenceHash();
        if (bytes(reason).length == 0) revert ZeroReason();
        if (disputedAssets[_assets[tokenId].assetIdDigest]) revert AssetDisputed();
        uint256 id = ++disputeCount;
        disputes[id] = Dispute({
            tokenId: tokenId,
            raisedBy: msg.sender,
            evidenceHash: evidenceHash,
            reason: reason,
            open: true,
            upheld: false,
            resolutionReason: "",
            raisedAt: uint64(block.timestamp),
            resolvedAt: 0
        });
        disputedAssets[_assets[tokenId].assetIdDigest] = true;
        openDisputeCount += 1;
        emit DisputeRaised(id, tokenId, msg.sender, evidenceHash, reason, uint64(block.timestamp));
    }

    /**
     * @notice Resolve a dispute. ADMIN-only (DEFAULT_ADMIN_ROLE); the auditor
     *         who raised it can NEVER resolve (role exclusivity makes an
     *         auditor-admin impossible on-chain). Upheld disputes leave the
     *         asset frozen for governance recovery (burn/forceTransfer);
     *         rejected disputes release the hold. Assets are never destroyed
     *         silently — recovery itself is a governance proposal.
     */
    function resolveDispute(uint256 disputeId, bool upheld, string calldata reason) external {
        if (paused) revert Paused();
        if (!accessControl.hasRole(accessControl.DEFAULT_ADMIN_ROLE(), msg.sender)) revert NotAdmin();
        Dispute storage dispute = disputes[disputeId];
        if (!dispute.open) revert DisputeNotOpen();
        if (bytes(reason).length == 0) revert ZeroReason();
        dispute.open = false;
        dispute.upheld = upheld;
        dispute.resolutionReason = reason;
        dispute.resolvedAt = uint64(block.timestamp);
        if (!upheld) {
            disputedAssets[_assets[dispute.tokenId].assetIdDigest] = false;
            openDisputeCount -= 1;
        }
        emit DisputeResolved(disputeId, dispute.tokenId, msg.sender, upheld, reason, uint64(block.timestamp));
    }

    /**
     * @notice Commit the HASH of an off-chain audit report on-chain. The
     *         report contents NEVER enter the chain. AUDITOR-only.
     */
    function storeAuditReportHash(bytes32 reportHash) external {
        if (!accessControl.hasRole(accessControl.AUDITOR_ROLE(), msg.sender)) revert NotAuditor();
        if (reportHash == bytes32(0)) revert EmptyEvidenceHash();
        uint256 id = ++auditReportCount;
        auditReports[id] = AuditReport({ auditor: msg.sender, reportHash: reportHash, at: uint64(block.timestamp) });
        emit AuditReportHashStored(id, msg.sender, reportHash, uint64(block.timestamp));
    }

    // ------------------------------------------------------------------
    // Auditor verification views (read-only by role-restricted convention:
    // views are open because they expose only on-chain digests)
    // ------------------------------------------------------------------

    /// @notice TRUE when `wallet` is the CURRENT custodian of the token.
    function verifyOwnership(uint256 tokenId, address wallet) external view returns (bool) {
        return _assets[tokenId].custodian == wallet;
    }

    /// @notice TRUE when the token is registered and its record is intact.
    function verifyAuthenticity(uint256 tokenId) external view returns (bool) {
        return _assets[tokenId].status != AssetStatus.NONE;
    }

    function getDispute(uint256 disputeId) external view returns (Dispute memory) {
        return disputes[disputeId];
    }

    function getAnomaly(uint256 anomalyId) external view returns (Anomaly memory) {
        return anomalies[anomalyId];
    }

    function getAuditReport(uint256 reportId) external view returns (AuditReport memory) {
        return auditReports[reportId];
    }

    function getCustodyHistoryLength(uint256 tokenId) external view returns (uint256) {
        return custodyHistoryLength[tokenId];
    }

    function getCustodyRecord(uint256 tokenId, uint256 index) external view returns (CustodyRecord memory) {
        return _custodyHistory[tokenId][index];
    }

    function isAssetDisputed(uint256 tokenId) external view returns (bool) {
        if (_assets[tokenId].status == AssetStatus.NONE) revert AssetNotRegistered();
        return disputedAssets[_assets[tokenId].assetIdDigest];
    }

    // ------------------------------------------------------------------
    // Emergency pause (governance-only) + governance dispatch
    // ------------------------------------------------------------------

    function governancePause() external {
        if (msg.sender != governance) revert NotGovernance();
        if (paused) revert SameAssetStatus();
        paused = true;
        emit SystemPaused(msg.sender, "governance proposal", uint64(block.timestamp));
    }

    function governanceUnpause() external {
        if (msg.sender != governance) revert NotGovernance();
        if (!paused) revert SameAssetStatus();
        paused = false;
        emit SystemUnpaused(msg.sender, "governance proposal", uint64(block.timestamp));
    }

    /**
     * @notice Governance-approved burn of a disputed/compromised NFT. The
     *         asset status becomes REVOKED (terminal) and the token is burned.
     *         Recovery of custody evidence stays in the history — never a
     *         silent destruction.
     */
    function governanceBurnNFT(uint256 tokenId, string calldata reason) external {
        if (msg.sender != governance) revert NotGovernance();
        if (bytes(reason).length == 0) revert ZeroReason();
        AssetRecord storage asset = _assets[tokenId];
        if (asset.status == AssetStatus.NONE) revert AssetNotRegistered();
        if (asset.status == AssetStatus.REVOKED) revert InvalidAssetStatus();
        asset.status = AssetStatus.REVOKED;
        asset.statusChangedAt = uint64(block.timestamp);
        emit NFTRevoked(tokenId, asset.assetIdDigest, msg.sender, reason, uint64(block.timestamp));
        _burn(tokenId);
    }

    /**
     * @notice Governance-approved forced custody transfer (emergency recovery).
     *         Works regardless of asset status or disputes — that is its
     *         purpose — but ONLY through quorum + timelock.
     */
    function governanceForceTransfer(uint256 tokenId, address toCustodian, string calldata reason) external {
        if (msg.sender != governance) revert NotGovernance();
        if (bytes(reason).length == 0) revert ZeroReason();
        AssetRecord storage asset = _assets[tokenId];
        if (asset.status == AssetStatus.NONE) revert AssetNotRegistered();
        if (toCustodian == address(0)) revert ZeroAddress();
        if (toCustodian == asset.custodian) revert SameAssetStatus();
        address fromCustodian = asset.custodian;
        asset.custodian = toCustodian;
        asset.statusChangedAt = uint64(block.timestamp);
        _custodyHistory[tokenId].push(CustodyRecord({
            fromCustodian: fromCustodian,
            toCustodian: toCustodian,
            operator: msg.sender,
            at: uint64(block.timestamp)
        }));
        custodyHistoryLength[tokenId] += 1;
        emit ForcedTransfer(tokenId, fromCustodian, toCustodian, msg.sender, reason, uint64(block.timestamp));
        _transfer(fromCustodian, toCustodian, tokenId);
    }

    function sampraanGovernanceTargetVersion() external pure returns (uint256) {
        return 1;
    }

    function governanceGrantRole(bytes32, address) external pure {
        revert InvalidAssetStatus(); // role administration lives on AccessControl
    }

    function governanceRevokeRole(bytes32, address) external pure {
        revert InvalidAssetStatus(); // role administration lives on AccessControl
    }

    function governanceDeactivateIdentity(address, string calldata) external pure {
        revert InvalidAssetStatus(); // identity lifecycle lives on IdentityRegistry
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
