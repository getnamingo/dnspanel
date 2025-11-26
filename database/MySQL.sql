CREATE TABLE IF NOT EXISTS `users` (
    `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
    `email` varchar(249) COLLATE utf8mb4_unicode_ci NOT NULL,
    `password` varchar(255) CHARACTER SET latin1 COLLATE latin1_general_cs NOT NULL,
    `username` varchar(100) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
    `status` tinyint(2) unsigned NOT NULL DEFAULT '0',
    `verified` tinyint(1) unsigned NOT NULL DEFAULT '0',
    `resettable` tinyint(1) unsigned NOT NULL DEFAULT '1',
    `roles_mask` int(10) unsigned NOT NULL DEFAULT '0',
    `registered` int(10) unsigned NOT NULL,
    `last_login` int(10) unsigned DEFAULT NULL,
    `force_logout` mediumint(7) unsigned NOT NULL DEFAULT '0',
    `tfa_secret` VARCHAR(32),
    `tfa_enabled` TINYINT DEFAULT 0,
    `auth_method` ENUM('password', '2fa', 'webauthn') DEFAULT 'password',
    `backup_codes` TEXT,
    `password_last_updated` timestamp NULL DEFAULT current_timestamp(),
    PRIMARY KEY (`id`),
    UNIQUE KEY `email` (`email`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `users_audit` (
    `user_id` int(10) unsigned NOT NULL,
    `user_event` VARCHAR(255) NOT NULL,
    `user_resource` VARCHAR(255) default NULL,
    `user_agent` VARCHAR(255) NOT NULL,
    `user_ip` VARCHAR(45) NOT NULL,
    `user_location` VARCHAR(45) default NULL,
    `event_time` DATETIME(3) NOT NULL,
    `user_data` JSON default NULL,
    KEY `user_id` (`user_id`),
    KEY `user_event` (`user_event`),
    KEY `user_ip` (`user_ip`),
    FOREIGN KEY (user_id) REFERENCES users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `users_confirmations` (
    `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
    `user_id` int(10) unsigned NOT NULL,
    `email` varchar(249) COLLATE utf8mb4_unicode_ci NOT NULL,
    `selector` varchar(16) CHARACTER SET latin1 COLLATE latin1_general_cs NOT NULL,
    `token` varchar(255) CHARACTER SET latin1 COLLATE latin1_general_cs NOT NULL,
    `expires` int(10) unsigned NOT NULL,
    PRIMARY KEY (`id`),
    UNIQUE KEY `selector` (`selector`),
    KEY `email_expires` (`email`,`expires`),
    KEY `user_id` (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `users_remembered` (
    `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
    `user_id` int(10) unsigned NOT NULL,
    `selector` varchar(24) CHARACTER SET latin1 COLLATE latin1_general_cs NOT NULL,
    `token` varchar(255) CHARACTER SET latin1 COLLATE latin1_general_cs NOT NULL,
    `expires` int(10) unsigned NOT NULL,
    PRIMARY KEY (`id`),
    UNIQUE KEY `selector` (`selector`),
    KEY `user_id` (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `users_resets` (
    `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
    `user_id` int(10) unsigned NOT NULL,
    `selector` varchar(20) CHARACTER SET latin1 COLLATE latin1_general_cs NOT NULL,
    `token` varchar(255) CHARACTER SET latin1 COLLATE latin1_general_cs NOT NULL,
    `expires` int(10) unsigned NOT NULL,
    PRIMARY KEY (`id`),
    UNIQUE KEY `selector` (`selector`),
    KEY `user_expires` (`user_id`,`expires`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `users_throttling` (
    `bucket` varchar(44) CHARACTER SET latin1 COLLATE latin1_general_cs NOT NULL,
    `tokens` float unsigned NOT NULL,
    `replenished_at` int(10) unsigned NOT NULL,
    `expires_at` int(10) unsigned NOT NULL,
    PRIMARY KEY (`bucket`),
    KEY `expires_at` (`expires_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `users_webauthn` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `user_id` INT UNSIGNED NOT NULL,
    `credential_id` VARBINARY(255) NOT NULL,
    `public_key` TEXT NOT NULL,
    `attestation_object` BLOB,
    `sign_count` BIGINT NOT NULL,
    `user_agent` VARCHAR(512),
    `created_at` DATETIME(3) DEFAULT CURRENT_TIMESTAMP,
    `last_used_at` DATETIME(3) DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `zones` (
    `id` BIGINT(20) NOT NULL AUTO_INCREMENT,
    `client_id` BIGINT(20) NOT NULL,
    `domain_name` VARCHAR(75),
    `provider_id` VARCHAR(11),
    `zoneId` VARCHAR(100) DEFAULT NULL,
    `config` TEXT NOT NULL,
    `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
    `updated_at` DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
                
CREATE TABLE IF NOT EXISTS `records` (
    `id` BIGINT(20) NOT NULL AUTO_INCREMENT,
    `domain_id` BIGINT(20) NOT NULL,
    `recordId` VARCHAR(100) DEFAULT NULL,
    `type` VARCHAR(10) NOT NULL,
    `host` VARCHAR(255) NOT NULL,
    `value` TEXT NOT NULL,
    `ttl` INT(11) DEFAULT NULL,
    `priority` INT(11) DEFAULT NULL,
    `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
    `updated_at` DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    FOREIGN KEY (`domain_id`) REFERENCES `zones`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `zone_users` (
    `zone_id` BIGINT(20) NOT NULL,
    `user_id` int(10) unsigned NOT NULL,
    PRIMARY KEY (`zone_id`, `user_id`),
    FOREIGN KEY (`zone_id`) REFERENCES `zones`(`id`) ON DELETE CASCADE,
    FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `error_log` (
    `id` INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY, 
    `channel` VARCHAR(255), 
    `level` INT(3),
    `level_name` VARCHAR(10),
    `message` TEXT,
    `context` JSON,
    `extra` JSON,
    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;