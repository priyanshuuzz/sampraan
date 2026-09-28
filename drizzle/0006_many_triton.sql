CREATE TABLE `did_key_records` (
	`id` varchar(36) NOT NULL,
	`did` varchar(255) NOT NULL,
	`keyIdentifier` varchar(80) NOT NULL,
	`algorithm` varchar(64) NOT NULL DEFAULT 'EcdsaSecp256k1Recovery',
	`status` enum('ACTIVE','ROTATED','REVOKED') NOT NULL DEFAULT 'ACTIVE',
	`createdByIdentityId` varchar(36),
	`supersededByKeyIdentifier` varchar(80),
	`note` varchar(200),
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	`deactivatedAt` timestamp,
	CONSTRAINT `did_key_records_id` PRIMARY KEY(`id`),
	CONSTRAINT `did_key_records_did_key_idx` UNIQUE(`did`,`keyIdentifier`)
);
--> statement-breakpoint
ALTER TABLE `did_challenges` ADD `purpose` varchar(60) DEFAULT 'AUTHENTICATION' NOT NULL;--> statement-breakpoint
ALTER TABLE `did_challenges` ADD `audience` varchar(120) DEFAULT 'sampraan' NOT NULL;--> statement-breakpoint
ALTER TABLE `did_challenges` ADD `keyIdentifier` varchar(80);--> statement-breakpoint
ALTER TABLE `did_records` ADD `keyIdentifier` varchar(80);--> statement-breakpoint
ALTER TABLE `did_records` ADD `rotatedFrom` varchar(80);--> statement-breakpoint
ALTER TABLE `did_key_records` ADD CONSTRAINT `did_key_records_createdByIdentityId_identities_id_fk` FOREIGN KEY (`createdByIdentityId`) REFERENCES `identities`(`id`) ON DELETE no action ON UPDATE no action;--> statement-breakpoint
CREATE INDEX `did_key_records_did_idx` ON `did_key_records` (`did`);