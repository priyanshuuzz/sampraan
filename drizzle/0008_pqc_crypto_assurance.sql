CREATE TABLE `assurance_challenges` (
	`id` varchar(36) NOT NULL,
	`identityId` varchar(36) NOT NULL,
	`did` varchar(255) NOT NULL,
	`operation` varchar(120) NOT NULL,
	`resourceType` varchar(100) NOT NULL,
	`resourceId` varchar(160) NOT NULL,
	`assuranceLevel` enum('BASELINE','ELEVATED','QUANTUM_HARDENED') NOT NULL,
	`requiredAlgorithms` json NOT NULL,
	`reasonCodes` json NOT NULL,
	`audience` varchar(120) NOT NULL,
	`ecdsaKeyIdentifier` varchar(80) NOT NULL,
	`pqcKeyIdentifier` varchar(80),
	`nonce` varchar(128) NOT NULL,
	`message` text NOT NULL,
	`ecdsaVerified` boolean NOT NULL DEFAULT false,
	`pqcVerified` boolean NOT NULL DEFAULT false,
	`expiresAt` timestamp NOT NULL,
	`consumedAt` timestamp,
	`executedAt` timestamp,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `assurance_challenges_id` PRIMARY KEY(`id`),
	CONSTRAINT `assurance_challenges_nonce_unique` UNIQUE(`nonce`)
);
--> statement-breakpoint
CREATE TABLE `pqc_key_records` (
	`id` varchar(36) NOT NULL,
	`identityId` varchar(36) NOT NULL,
	`did` varchar(255) NOT NULL,
	`keyIdentifier` varchar(80) NOT NULL,
	`algorithm` varchar(64) NOT NULL DEFAULT 'ML-DSA-65',
	`publicKey` text NOT NULL,
	`publicKeyFingerprint` varchar(64) NOT NULL,
	`keySource` enum('REGISTERED','SERVER_DERIVED') NOT NULL DEFAULT 'REGISTERED',
	`status` enum('ACTIVE','ROTATED','REVOKED') NOT NULL DEFAULT 'ACTIVE',
	`registeredByIdentityId` varchar(36),
	`supersededByKeyIdentifier` varchar(80),
	`note` varchar(200),
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	`deactivatedAt` timestamp,
	CONSTRAINT `pqc_key_records_id` PRIMARY KEY(`id`),
	CONSTRAINT `pqc_key_records_did_key_idx` UNIQUE(`did`,`keyIdentifier`)
);
--> statement-breakpoint
ALTER TABLE `assurance_challenges` ADD CONSTRAINT `assurance_challenges_identityId_identities_id_fk` FOREIGN KEY (`identityId`) REFERENCES `identities`(`id`) ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `pqc_key_records` ADD CONSTRAINT `pqc_key_records_identityId_identities_id_fk` FOREIGN KEY (`identityId`) REFERENCES `identities`(`id`) ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `pqc_key_records` ADD CONSTRAINT `pqc_key_records_registeredByIdentityId_identities_id_fk` FOREIGN KEY (`registeredByIdentityId`) REFERENCES `identities`(`id`) ON DELETE no action ON UPDATE no action;--> statement-breakpoint
CREATE INDEX `assurance_challenges_identity_idx` ON `assurance_challenges` (`identityId`);--> statement-breakpoint
CREATE INDEX `assurance_challenges_resource_idx` ON `assurance_challenges` (`resourceType`,`resourceId`);--> statement-breakpoint
CREATE INDEX `pqc_key_records_identity_idx` ON `pqc_key_records` (`identityId`);--> statement-breakpoint
CREATE INDEX `pqc_key_records_did_idx` ON `pqc_key_records` (`did`);