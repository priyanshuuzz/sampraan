CREATE TABLE `asset_access_grants` (
	`id` varchar(36) NOT NULL,
	`assetId` varchar(36) NOT NULL,
	`granteeIdentityId` varchar(36) NOT NULL,
	`permission` enum('VIEW','EDIT') NOT NULL,
	`grantedByIdentityId` varchar(36) NOT NULL,
	`reason` varchar(300),
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	`revokedAt` timestamp,
	CONSTRAINT `asset_access_grants_id` PRIMARY KEY(`id`),
	CONSTRAINT `asset_access_grants_asset_grantee_perm_idx` UNIQUE(`assetId`,`granteeIdentityId`,`permission`)
);
--> statement-breakpoint
CREATE TABLE `asset_content_versions` (
	`id` varchar(36) NOT NULL,
	`assetId` varchar(36) NOT NULL,
	`versionNumber` int NOT NULL,
	`filename` varchar(255) NOT NULL,
	`originalFilename` varchar(255) NOT NULL,
	`mimeType` varchar(127) NOT NULL,
	`sizeBytes` bigint NOT NULL,
	`contentHash` varchar(64) NOT NULL,
	`storageProvider` varchar(40) NOT NULL,
	`storageReference` varchar(512) NOT NULL,
	`encryption` json NOT NULL,
	`createdByIdentityId` varchar(36) NOT NULL,
	`changeNote` varchar(300),
	`createdTxHash` varchar(255),
	`createdBlockNumber` bigint,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `asset_content_versions_id` PRIMARY KEY(`id`),
	CONSTRAINT `asset_versions_asset_version_idx` UNIQUE(`assetId`,`versionNumber`)
);
--> statement-breakpoint
ALTER TABLE `asset_access_grants` ADD CONSTRAINT `asset_access_grants_assetId_assets_id_fk` FOREIGN KEY (`assetId`) REFERENCES `assets`(`id`) ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `asset_access_grants` ADD CONSTRAINT `asset_access_grants_granteeIdentityId_identities_id_fk` FOREIGN KEY (`granteeIdentityId`) REFERENCES `identities`(`id`) ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `asset_access_grants` ADD CONSTRAINT `asset_access_grants_grantedByIdentityId_identities_id_fk` FOREIGN KEY (`grantedByIdentityId`) REFERENCES `identities`(`id`) ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `asset_content_versions` ADD CONSTRAINT `asset_content_versions_assetId_assets_id_fk` FOREIGN KEY (`assetId`) REFERENCES `assets`(`id`) ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `asset_content_versions` ADD CONSTRAINT `asset_content_versions_createdByIdentityId_identities_id_fk` FOREIGN KEY (`createdByIdentityId`) REFERENCES `identities`(`id`) ON DELETE no action ON UPDATE no action;--> statement-breakpoint
CREATE INDEX `asset_access_grants_grantee_idx` ON `asset_access_grants` (`granteeIdentityId`);--> statement-breakpoint
CREATE INDEX `asset_versions_asset_idx` ON `asset_content_versions` (`assetId`);--> statement-breakpoint
CREATE INDEX `asset_versions_hash_idx` ON `asset_content_versions` (`contentHash`);