CREATE TABLE `did_records` (
	`id` varchar(36) NOT NULL,
	`identityId` varchar(36) NOT NULL,
	`did` varchar(255) NOT NULL,
	`method` varchar(80) NOT NULL,
	`subject` varchar(255) NOT NULL,
	`document` json,
	`status` enum('ACTIVE','REVOKED') NOT NULL DEFAULT 'ACTIVE',
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	`revokedAt` timestamp,
	CONSTRAINT `did_records_id` PRIMARY KEY(`id`),
	CONSTRAINT `did_records_did_unique` UNIQUE(`did`)
);
--> statement-breakpoint
ALTER TABLE `did_records` ADD CONSTRAINT `did_records_identityId_identities_id_fk` FOREIGN KEY (`identityId`) REFERENCES `identities`(`id`) ON DELETE no action ON UPDATE no action;--> statement-breakpoint
CREATE INDEX `did_records_identity_idx` ON `did_records` (`identityId`);