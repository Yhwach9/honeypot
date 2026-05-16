-- MySQL dump 10.13  Distrib 8.0.36
-- Host: 10.0.0.50    Database: production_db
-- Snapshot Date: 2024-01-15 02:00:01
-- Server version  8.0.36

SET NAMES utf8mb4;
SET foreign_key_checks = 0;

-- Table: users
CREATE TABLE `users` (
  `id` int NOT NULL AUTO_INCREMENT,
  `email` varchar(255) NOT NULL,
  `password_hash` varchar(255) NOT NULL,
  `created_at` timestamp DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
);

-- (file truncated - canary token)
