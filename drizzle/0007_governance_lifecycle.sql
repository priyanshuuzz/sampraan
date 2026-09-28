CREATE TABLE `asset_disputes` (
	`id` varchar(36) NOT NULL,
	`assetId` varchar(36) NOT NULL,
	`raisedByIdentityId` varchar(36) NOT NULL,
	`evidenceHash` varchar(64) NOT NULL,
	`reason` varchar(300) NOT NULL,
	`onChainDisputeId` int,
	`status` enum('OPEN','UPHELD','REJECTED') NOT NULL DEFAULT 'OPEN',
	`resolvedByIdentityId` varchar(36),
	`resolutionReason` varchar(300),
	`resolvedAt` timestamp,
	`transactionHash` varchar(255),
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `asset_disputes_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `asset_transfer_requests` (
	`id` varchar(36) NOT NULL,
	`assetId` varchar(36) NOT NULL,
	`tokenId` varchar(160),
	`fromIdentityId` varchar(36) NOT NULL,
	`toIdentityId` varchar(36) NOT NULL,
	`requestedByIdentityId` varchar(36) NOT NULL,
	`acceptedAt` timestamp,
	`status` enum('PENDING','ACCEPTED','APPROVED','REJECTED','EXECUTED','CANCELLED') NOT NULL DEFAULT 'PENDING',
	`approverIdentityId` varchar(36),
	`decisionReason` varchar(300),
	`decidedAt` timestamp,
	`executedAt` timestamp,
	`transactionHash` varchar(255),
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `asset_transfer_requests_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `audit_report_hashes` (
	`id` varchar(36) NOT NULL,
	`auditorIdentityId` varchar(36) NOT NULL,
	`reportHash` varchar(64) NOT NULL,
	`onChainReportId` int,
	`transactionHash` varchar(255),
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `audit_report_hashes_id` PRIMARY KEY(`id`),
	CONSTRAINT `audit_report_hashes_reportHash_unique` UNIQUE(`reportHash`)
);
--> statement-breakpoint
CREATE TABLE `consent_grants` (
	`id` varchar(36) NOT NULL,
	`subjectIdentityId` varchar(36) NOT NULL,
	`verifierDid` varchar(255) NOT NULL,
	`scope` varchar(180) NOT NULL,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	`expiresAt` timestamp NOT NULL,
	`revokedAt` timestamp,
	CONSTRAINT `consent_grants_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `did_document_versions` (
	`id` varchar(36) NOT NULL,
	`identityId` varchar(36) NOT NULL,
	`versionNumber` int NOT NULL,
	`documentHash` varchar(64) NOT NULL,
	`reason` varchar(300),
	`createdByIdentityId` varchar(36) NOT NULL,
	`onChainVersion` int,
	`transactionHash` varchar(255),
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `did_document_versions_id` PRIMARY KEY(`id`),
	CONSTRAINT `did_document_versions_identity_version_idx` UNIQUE(`identityId`,`versionNumber`)
);
--> statement-breakpoint
CREATE TABLE `identity_anomalies` (
	`id` varchar(36) NOT NULL,
	`targetIdentityId` varchar(36),
	`assetId` varchar(36),
	`flaggedByIdentityId` varchar(36) NOT NULL,
	`reason` varchar(300) NOT NULL,
	`onChainAnomalyId` int,
	`transactionHash` varchar(255),
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `identity_anomalies_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `key_recovery_requests` (
	`id` varchar(36) NOT NULL,
	`subjectIdentityId` varchar(36) NOT NULL,
	`requestedByIdentityId` varchar(36) NOT NULL,
	`newKeyDigest` varchar(64) NOT NULL,
	`status` enum('PENDING','AWAITING_ADMIN','APPROVED','REJECTED','EXECUTED') NOT NULL DEFAULT 'PENDING',
	`guardianApprovals` json,
	`decidedByIdentityId` varchar(36),
	`decisionReason` varchar(300),
	`executedAt` timestamp,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `key_recovery_requests_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `mint_requests` (
	`id` varchar(36) NOT NULL,
	`assetId` varchar(120) NOT NULL,
	`name` varchar(200) NOT NULL,
	`type` varchar(80) NOT NULL,
	`classification` enum('PUBLIC','CONTROLLED','SENSITIVE','HIGHLY_SENSITIVE','CRITICAL') NOT NULL,
	`description` text,
	`integrityHash` varchar(255),
	`ownerIdentityId` varchar(36) NOT NULL,
	`custodianIdentityId` varchar(36) NOT NULL,
	`requestedByIdentityId` varchar(36) NOT NULL,
	`requesterScope` varchar(180),
	`status` enum('PENDING','APPROVED','REJECTED','EXECUTED') NOT NULL DEFAULT 'PENDING',
	`decidedByIdentityId` varchar(36),
	`decisionReason` varchar(300),
	`decidedAt` timestamp,
	`executedAt` timestamp,
	`tokenId` varchar(160),
	`transactionHash` varchar(255),
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `mint_requests_id` PRIMARY KEY(`id`),
	CONSTRAINT `mint_requests_assetId_unique` UNIQUE(`assetId`)
);
--> statement-breakpoint
CREATE TABLE `ownership_presentations` (
	`id` varchar(36) NOT NULL,
	`subjectIdentityId` varchar(36) NOT NULL,
	`assetId` varchar(36) NOT NULL,
	`verifierDid` varchar(255) NOT NULL,
	`purpose` varchar(120) NOT NULL,
	`nonce` varchar(128) NOT NULL,
	`signature` text NOT NULL,
	`keyIdentifier` varchar(80) NOT NULL,
	`message` text NOT NULL,
	`expiresAt` timestamp NOT NULL,
	`consumedAt` timestamp,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `ownership_presentations_id` PRIMARY KEY(`id`),
	CONSTRAINT `ownership_presentations_nonce_unique` UNIQUE(`nonce`)
);
--> statement-breakpoint
ALTER TABLE `identities` ADD `lifecycleState` enum('PENDING','VERIFIED','SUSPENDED','DEACTIVATED') DEFAULT 'VERIFIED' NOT NULL;--> statement-breakpoint
ALTER TABLE `identities` ADD `statusReason` varchar(300);--> statement-breakpoint
ALTER TABLE `identities` ADD `scope` varchar(180);--> statement-breakpoint
ALTER TABLE `identities` ADD `deactivatedAt` timestamp;--> statement-breakpoint
ALTER TABLE `asset_disputes` ADD CONSTRAINT `asset_disputes_assetId_assets_id_fk` FOREIGN KEY (`assetId`) REFERENCES `assets`(`id`) ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `asset_disputes` ADD CONSTRAINT `asset_disputes_raisedByIdentityId_identities_id_fk` FOREIGN KEY (`raisedByIdentityId`) REFERENCES `identities`(`id`) ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `asset_disputes` ADD CONSTRAINT `asset_disputes_resolvedByIdentityId_identities_id_fk` FOREIGN KEY (`resolvedByIdentityId`) REFERENCES `identities`(`id`) ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `asset_transfer_requests` ADD CONSTRAINT `asset_transfer_requests_assetId_assets_id_fk` FOREIGN KEY (`assetId`) REFERENCES `assets`(`id`) ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `asset_transfer_requests` ADD CONSTRAINT `asset_transfer_requests_fromIdentityId_identities_id_fk` FOREIGN KEY (`fromIdentityId`) REFERENCES `identities`(`id`) ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `asset_transfer_requests` ADD CONSTRAINT `asset_transfer_requests_toIdentityId_identities_id_fk` FOREIGN KEY (`toIdentityId`) REFERENCES `identities`(`id`) ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `asset_transfer_requests` ADD CONSTRAINT `asset_transfer_requests_requestedByIdentityId_identities_id_fk` FOREIGN KEY (`requestedByIdentityId`) REFERENCES `identities`(`id`) ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `asset_transfer_requests` ADD CONSTRAINT `asset_transfer_requests_approverIdentityId_identities_id_fk` FOREIGN KEY (`approverIdentityId`) REFERENCES `identities`(`id`) ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `audit_report_hashes` ADD CONSTRAINT `audit_report_hashes_auditorIdentityId_identities_id_fk` FOREIGN KEY (`auditorIdentityId`) REFERENCES `identities`(`id`) ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `consent_grants` ADD CONSTRAINT `consent_grants_subjectIdentityId_identities_id_fk` FOREIGN KEY (`subjectIdentityId`) REFERENCES `identities`(`id`) ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `did_document_versions` ADD CONSTRAINT `did_document_versions_identityId_identities_id_fk` FOREIGN KEY (`identityId`) REFERENCES `identities`(`id`) ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `did_document_versions` ADD CONSTRAINT `did_document_versions_createdByIdentityId_identities_id_fk` FOREIGN KEY (`createdByIdentityId`) REFERENCES `identities`(`id`) ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `identity_anomalies` ADD CONSTRAINT `identity_anomalies_targetIdentityId_identities_id_fk` FOREIGN KEY (`targetIdentityId`) REFERENCES `identities`(`id`) ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `identity_anomalies` ADD CONSTRAINT `identity_anomalies_assetId_assets_id_fk` FOREIGN KEY (`assetId`) REFERENCES `assets`(`id`) ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `identity_anomalies` ADD CONSTRAINT `identity_anomalies_flaggedByIdentityId_identities_id_fk` FOREIGN KEY (`flaggedByIdentityId`) REFERENCES `identities`(`id`) ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `key_recovery_requests` ADD CONSTRAINT `key_recovery_requests_subjectIdentityId_identities_id_fk` FOREIGN KEY (`subjectIdentityId`) REFERENCES `identities`(`id`) ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `key_recovery_requests` ADD CONSTRAINT `key_recovery_requests_requestedByIdentityId_identities_id_fk` FOREIGN KEY (`requestedByIdentityId`) REFERENCES `identities`(`id`) ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `key_recovery_requests` ADD CONSTRAINT `key_recovery_requests_decidedByIdentityId_identities_id_fk` FOREIGN KEY (`decidedByIdentityId`) REFERENCES `identities`(`id`) ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `mint_requests` ADD CONSTRAINT `mint_requests_ownerIdentityId_identities_id_fk` FOREIGN KEY (`ownerIdentityId`) REFERENCES `identities`(`id`) ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `mint_requests` ADD CONSTRAINT `mint_requests_custodianIdentityId_identities_id_fk` FOREIGN KEY (`custodianIdentityId`) REFERENCES `identities`(`id`) ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `mint_requests` ADD CONSTRAINT `mint_requests_requestedByIdentityId_identities_id_fk` FOREIGN KEY (`requestedByIdentityId`) REFERENCES `identities`(`id`) ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `mint_requests` ADD CONSTRAINT `mint_requests_decidedByIdentityId_identities_id_fk` FOREIGN KEY (`decidedByIdentityId`) REFERENCES `identities`(`id`) ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `ownership_presentations` ADD CONSTRAINT `ownership_presentations_subjectIdentityId_identities_id_fk` FOREIGN KEY (`subjectIdentityId`) REFERENCES `identities`(`id`) ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `ownership_presentations` ADD CONSTRAINT `ownership_presentations_assetId_assets_id_fk` FOREIGN KEY (`assetId`) REFERENCES `assets`(`id`) ON DELETE no action ON UPDATE no action;--> statement-breakpoint
CREATE INDEX `consent_grants_subject_idx` ON `consent_grants` (`subjectIdentityId`,`verifierDid`);--> statement-breakpoint
-- SAMPRAAN DATA BACKFILL (hand-added; drizzle-kit generates DDL only).
-- The lifecycleState column is added with DEFAULT 'VERIFIED', so an EXISTING
-- database upgrading from 0006 would silently mark SUSPENDED identities as
-- VERIFIED. Re-map the pre-existing status enum onto the lifecycle enum so an
-- upgrade cannot widen anyone's authority.
UPDATE `identities` SET `lifecycleState` = 'SUSPENDED' WHERE `status` = 'SUSPENDED';--> statement-breakpoint
UPDATE `identities` SET `lifecycleState` = 'DEACTIVATED', `deactivatedAt` = COALESCE(`revokedAt`, NOW()) WHERE `status` = 'REVOKED';--> statement-breakpoint
UPDATE `identities` SET `scope` = `organization` WHERE `scope` IS NULL;