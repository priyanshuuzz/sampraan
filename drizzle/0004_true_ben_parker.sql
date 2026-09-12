CREATE TABLE `asset_approvals` (
	`id` varchar(36) NOT NULL,
	`assetId` varchar(36) NOT NULL,
	`requesterIdentityId` varchar(36) NOT NULL,
	`approverIdentityId` varchar(36),
	`action` varchar(100) NOT NULL,
	`targetIdentityId` varchar(36),
	`status` enum('PENDING','APPROVED','REJECTED','EXECUTED') NOT NULL DEFAULT 'PENDING',
	`reason` varchar(300),
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	`decidedAt` timestamp,
	`executedAt` timestamp,
	CONSTRAINT `asset_approvals_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `did_challenges` (
	`id` varchar(36) NOT NULL,
	`did` varchar(255) NOT NULL,
	`nonce` varchar(128) NOT NULL,
	`message` text NOT NULL,
	`expiresAt` timestamp NOT NULL,
	`consumedAt` timestamp,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `did_challenges_id` PRIMARY KEY(`id`),
	CONSTRAINT `did_challenges_nonce_unique` UNIQUE(`nonce`)
);
--> statement-breakpoint
CREATE TABLE `step_up_sessions` (
	`id` varchar(36) NOT NULL,
	`identityId` varchar(36) NOT NULL,
	`purpose` varchar(120) NOT NULL,
	`nonce` varchar(128) NOT NULL,
	`expiresAt` timestamp NOT NULL,
	`consumedAt` timestamp,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `step_up_sessions_id` PRIMARY KEY(`id`),
	CONSTRAINT `step_up_sessions_nonce_unique` UNIQUE(`nonce`)
);
--> statement-breakpoint
ALTER TABLE `did_records` ADD `keyStatus` enum('ACTIVE','ROTATED','REVOKED') DEFAULT 'ACTIVE' NOT NULL;--> statement-breakpoint
ALTER TABLE `did_records` ADD `rotatedAt` timestamp;--> statement-breakpoint
ALTER TABLE `asset_approvals` ADD CONSTRAINT `asset_approvals_assetId_assets_id_fk` FOREIGN KEY (`assetId`) REFERENCES `assets`(`id`) ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `asset_approvals` ADD CONSTRAINT `asset_approvals_requesterIdentityId_identities_id_fk` FOREIGN KEY (`requesterIdentityId`) REFERENCES `identities`(`id`) ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `asset_approvals` ADD CONSTRAINT `asset_approvals_approverIdentityId_identities_id_fk` FOREIGN KEY (`approverIdentityId`) REFERENCES `identities`(`id`) ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `asset_approvals` ADD CONSTRAINT `asset_approvals_targetIdentityId_identities_id_fk` FOREIGN KEY (`targetIdentityId`) REFERENCES `identities`(`id`) ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `step_up_sessions` ADD CONSTRAINT `step_up_sessions_identityId_identities_id_fk` FOREIGN KEY (`identityId`) REFERENCES `identities`(`id`) ON DELETE no action ON UPDATE no action;--> statement-breakpoint
CREATE INDEX `asset_approvals_asset_idx` ON `asset_approvals` (`assetId`);--> statement-breakpoint
CREATE INDEX `asset_approvals_status_idx` ON `asset_approvals` (`status`);--> statement-breakpoint
CREATE INDEX `did_challenges_did_idx` ON `did_challenges` (`did`);--> statement-breakpoint
CREATE INDEX `step_up_identity_idx` ON `step_up_sessions` (`identityId`);