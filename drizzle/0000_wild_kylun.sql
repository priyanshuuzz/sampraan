CREATE TABLE `asset_custody` (
	`id` varchar(36) NOT NULL,
	`assetId` varchar(36) NOT NULL,
	`custodianIdentityId` varchar(36) NOT NULL,
	`reason` varchar(200),
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	`endedAt` timestamp,
	CONSTRAINT `asset_custody_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `asset_ownership` (
	`id` varchar(36) NOT NULL,
	`assetId` varchar(36) NOT NULL,
	`ownerIdentityId` varchar(36) NOT NULL,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	`endedAt` timestamp,
	CONSTRAINT `asset_ownership_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `assets` (
	`id` varchar(36) NOT NULL,
	`assetId` varchar(120) NOT NULL,
	`name` varchar(200) NOT NULL,
	`type` varchar(80) NOT NULL,
	`classification` varchar(80) NOT NULL,
	`description` text,
	`ownerIdentityId` varchar(36) NOT NULL,
	`custodianIdentityId` varchar(36) NOT NULL,
	`integrityHash` varchar(255),
	`tokenId` varchar(160),
	`status` enum('ACTIVE','REVOKED','PENDING') NOT NULL DEFAULT 'PENDING',
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `assets_id` PRIMARY KEY(`id`),
	CONSTRAINT `assets_assetId_unique` UNIQUE(`assetId`)
);
--> statement-breakpoint
CREATE TABLE `audit_events` (
	`id` varchar(36) NOT NULL,
	`actorIdentityId` varchar(36),
	`action` varchar(100) NOT NULL,
	`resourceType` varchar(100) NOT NULL,
	`resourceId` varchar(160),
	`decision` enum('ALLOW','DENY','CHALLENGE'),
	`reason` text,
	`timestamp` timestamp NOT NULL DEFAULT (now()),
	`transactionHash` varchar(255),
	`blockNumber` bigint,
	`metadata` json,
	`source` enum('APPLICATION','CHAIN_READ_MODEL') NOT NULL DEFAULT 'APPLICATION',
	CONSTRAINT `audit_events_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `authorization_decisions` (
	`id` varchar(36) NOT NULL,
	`actorIdentityId` varchar(36) NOT NULL,
	`resourceType` varchar(100) NOT NULL,
	`resourceId` varchar(160) NOT NULL,
	`action` varchar(100) NOT NULL,
	`decision` enum('ALLOW','DENY','CHALLENGE') NOT NULL,
	`reason` text NOT NULL,
	`policyId` varchar(36),
	`timestamp` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `authorization_decisions_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `identities` (
	`id` varchar(36) NOT NULL,
	`linkedUserId` int,
	`displayName` varchar(160) NOT NULL,
	`organization` varchar(180) NOT NULL,
	`status` enum('ACTIVE','REVOKED','SUSPENDED') NOT NULL DEFAULT 'ACTIVE',
	`did` varchar(255) NOT NULL,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	`revokedAt` timestamp,
	CONSTRAINT `identities_id` PRIMARY KEY(`id`),
	CONSTRAINT `identities_did_unique` UNIQUE(`did`)
);
--> statement-breakpoint
CREATE TABLE `identity_roles` (
	`identityId` varchar(36) NOT NULL,
	`roleId` varchar(36) NOT NULL,
	`assignedByIdentityId` varchar(36),
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `identity_roles_identityId_roleId_pk` PRIMARY KEY(`identityId`,`roleId`)
);
--> statement-breakpoint
CREATE TABLE `permissions` (
	`id` varchar(36) NOT NULL,
	`key` varchar(100) NOT NULL,
	`description` text,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `permissions_id` PRIMARY KEY(`id`),
	CONSTRAINT `permissions_key_unique` UNIQUE(`key`)
);
--> statement-breakpoint
CREATE TABLE `policies` (
	`id` varchar(36) NOT NULL,
	`name` varchar(160) NOT NULL,
	`description` text,
	`subjectRole` varchar(40),
	`resourceType` varchar(100) NOT NULL,
	`action` varchar(100) NOT NULL,
	`assetClassification` varchar(80),
	`organization` varchar(180),
	`effect` enum('ALLOW','DENY','CHALLENGE') NOT NULL DEFAULT 'DENY',
	`active` boolean NOT NULL DEFAULT true,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `policies_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `public_keys` (
	`id` varchar(36) NOT NULL,
	`identityId` varchar(36) NOT NULL,
	`keyIdentifier` varchar(160) NOT NULL,
	`algorithm` varchar(64) NOT NULL,
	`publicKey` text NOT NULL,
	`status` enum('ACTIVE','REVOKED') NOT NULL DEFAULT 'ACTIVE',
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	`revokedAt` timestamp,
	CONSTRAINT `public_keys_id` PRIMARY KEY(`id`),
	CONSTRAINT `public_keys_identity_key_idx` UNIQUE(`identityId`,`keyIdentifier`)
);
--> statement-breakpoint
CREATE TABLE `role_permissions` (
	`roleId` varchar(36) NOT NULL,
	`permissionId` varchar(36) NOT NULL,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `role_permissions_roleId_permissionId_pk` PRIMARY KEY(`roleId`,`permissionId`)
);
--> statement-breakpoint
CREATE TABLE `roles` (
	`id` varchar(36) NOT NULL,
	`name` varchar(40) NOT NULL,
	`description` text,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `roles_id` PRIMARY KEY(`id`),
	CONSTRAINT `roles_name_unique` UNIQUE(`name`)
);
--> statement-breakpoint
CREATE TABLE `security_alerts` (
	`id` varchar(36) NOT NULL,
	`title` varchar(200) NOT NULL,
	`severity` enum('LOW','MEDIUM','HIGH','CRITICAL') NOT NULL DEFAULT 'MEDIUM',
	`status` enum('OPEN','INVESTIGATING','RESOLVED') NOT NULL DEFAULT 'OPEN',
	`identityId` varchar(36),
	`assetId` varchar(36),
	`description` text NOT NULL,
	`riskScore` int,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	`resolvedAt` timestamp,
	CONSTRAINT `security_alerts_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `sessions` (
	`id` varchar(36) NOT NULL,
	`identityId` varchar(36) NOT NULL,
	`sessionId` varchar(160) NOT NULL,
	`expiresAt` timestamp NOT NULL,
	`revokedAt` timestamp,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `sessions_id` PRIMARY KEY(`id`),
	CONSTRAINT `sessions_sessionId_unique` UNIQUE(`sessionId`)
);
--> statement-breakpoint
CREATE TABLE `users` (
	`id` int AUTO_INCREMENT NOT NULL,
	`openId` varchar(64) NOT NULL,
	`name` text,
	`email` varchar(320),
	`loginMethod` varchar(64),
	`role` enum('user','admin') NOT NULL DEFAULT 'user',
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	`lastSignedIn` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `users_id` PRIMARY KEY(`id`),
	CONSTRAINT `users_openId_unique` UNIQUE(`openId`)
);
--> statement-breakpoint
ALTER TABLE `asset_custody` ADD CONSTRAINT `asset_custody_assetId_assets_id_fk` FOREIGN KEY (`assetId`) REFERENCES `assets`(`id`) ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `asset_custody` ADD CONSTRAINT `asset_custody_custodianIdentityId_identities_id_fk` FOREIGN KEY (`custodianIdentityId`) REFERENCES `identities`(`id`) ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `asset_ownership` ADD CONSTRAINT `asset_ownership_assetId_assets_id_fk` FOREIGN KEY (`assetId`) REFERENCES `assets`(`id`) ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `asset_ownership` ADD CONSTRAINT `asset_ownership_ownerIdentityId_identities_id_fk` FOREIGN KEY (`ownerIdentityId`) REFERENCES `identities`(`id`) ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `assets` ADD CONSTRAINT `assets_ownerIdentityId_identities_id_fk` FOREIGN KEY (`ownerIdentityId`) REFERENCES `identities`(`id`) ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `assets` ADD CONSTRAINT `assets_custodianIdentityId_identities_id_fk` FOREIGN KEY (`custodianIdentityId`) REFERENCES `identities`(`id`) ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `audit_events` ADD CONSTRAINT `audit_events_actorIdentityId_identities_id_fk` FOREIGN KEY (`actorIdentityId`) REFERENCES `identities`(`id`) ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `authorization_decisions` ADD CONSTRAINT `authorization_decisions_actorIdentityId_identities_id_fk` FOREIGN KEY (`actorIdentityId`) REFERENCES `identities`(`id`) ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `authorization_decisions` ADD CONSTRAINT `authorization_decisions_policyId_policies_id_fk` FOREIGN KEY (`policyId`) REFERENCES `policies`(`id`) ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `identities` ADD CONSTRAINT `identities_linkedUserId_users_id_fk` FOREIGN KEY (`linkedUserId`) REFERENCES `users`(`id`) ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `identity_roles` ADD CONSTRAINT `identity_roles_identityId_identities_id_fk` FOREIGN KEY (`identityId`) REFERENCES `identities`(`id`) ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `identity_roles` ADD CONSTRAINT `identity_roles_roleId_roles_id_fk` FOREIGN KEY (`roleId`) REFERENCES `roles`(`id`) ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `identity_roles` ADD CONSTRAINT `identity_roles_assignedByIdentityId_identities_id_fk` FOREIGN KEY (`assignedByIdentityId`) REFERENCES `identities`(`id`) ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `public_keys` ADD CONSTRAINT `public_keys_identityId_identities_id_fk` FOREIGN KEY (`identityId`) REFERENCES `identities`(`id`) ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `role_permissions` ADD CONSTRAINT `role_permissions_roleId_roles_id_fk` FOREIGN KEY (`roleId`) REFERENCES `roles`(`id`) ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `role_permissions` ADD CONSTRAINT `role_permissions_permissionId_permissions_id_fk` FOREIGN KEY (`permissionId`) REFERENCES `permissions`(`id`) ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `security_alerts` ADD CONSTRAINT `security_alerts_identityId_identities_id_fk` FOREIGN KEY (`identityId`) REFERENCES `identities`(`id`) ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `security_alerts` ADD CONSTRAINT `security_alerts_assetId_assets_id_fk` FOREIGN KEY (`assetId`) REFERENCES `assets`(`id`) ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `sessions` ADD CONSTRAINT `sessions_identityId_identities_id_fk` FOREIGN KEY (`identityId`) REFERENCES `identities`(`id`) ON DELETE no action ON UPDATE no action;--> statement-breakpoint
CREATE INDEX `assets_owner_idx` ON `assets` (`ownerIdentityId`);--> statement-breakpoint
CREATE INDEX `assets_custodian_idx` ON `assets` (`custodianIdentityId`);--> statement-breakpoint
CREATE INDEX `audit_events_time_idx` ON `audit_events` (`timestamp`);--> statement-breakpoint
CREATE INDEX `audit_events_resource_idx` ON `audit_events` (`resourceType`,`resourceId`);--> statement-breakpoint
CREATE INDEX `authorization_actor_time_idx` ON `authorization_decisions` (`actorIdentityId`,`timestamp`);--> statement-breakpoint
CREATE INDEX `identities_organization_idx` ON `identities` (`organization`);--> statement-breakpoint
CREATE INDEX `policies_match_idx` ON `policies` (`resourceType`,`action`,`active`);--> statement-breakpoint
CREATE INDEX `public_keys_identity_idx` ON `public_keys` (`identityId`);