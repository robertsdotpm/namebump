-- phpMyAdmin SQL Dump
-- version 5.2.3
-- https://www.phpmyadmin.net/
--
-- Host: localhost
-- Generation Time: Dec 22, 2025 at 04:13 AM
-- Server version: 8.4.7
-- PHP Version: 8.2.29

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `pnp`
--

-- --------------------------------------------------------

--
-- Table structure for table `ipv4s`
--

CREATE TABLE `ipv4s` (
  `id` bigint UNSIGNED NOT NULL,
  `v4_val` int UNSIGNED NOT NULL,
  `timestamp` bigint UNSIGNED NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `ipv6s`
--

CREATE TABLE `ipv6s` (
  `id` bigint UNSIGNED NOT NULL,
  `v6_glob_main` int UNSIGNED NOT NULL,
  `v6_glob_extra` smallint UNSIGNED NOT NULL,
  `v6_lan_id` smallint UNSIGNED NOT NULL,
  `v6_iface_id` bigint UNSIGNED NOT NULL,
  `timestamp` bigint UNSIGNED NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `names`
--

CREATE TABLE `names` (
  `id` bigint UNSIGNED NOT NULL,
  `name` varbinary(50) NOT NULL,
  `value` varbinary(500) NOT NULL,
  `owner_pub` binary(33) NOT NULL,
  `af` tinyint UNSIGNED NOT NULL,
  `ip_id` bigint UNSIGNED NOT NULL,
  `timestamp` bigint UNSIGNED NOT NULL,
  `updated` bigint UNSIGNED NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Indexes for dumped tables
--

--
-- Indexes for table `ipv4s`
--
ALTER TABLE `ipv4s`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `v4_val` (`v4_val`);

--
-- Indexes for table `ipv6s`
--
ALTER TABLE `ipv6s`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `v6_val` (`v6_glob_main`,`v6_glob_extra`,`v6_lan_id`,`v6_iface_id`);

--
-- Indexes for table `names`
--
ALTER TABLE `names`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `name` (`name`);

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `ipv4s`
--
ALTER TABLE `ipv4s`
  MODIFY `id` bigint UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=309;

--
-- AUTO_INCREMENT for table `ipv6s`
--
ALTER TABLE `ipv6s`
  MODIFY `id` bigint UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=383;

--
-- AUTO_INCREMENT for table `names`
--
ALTER TABLE `names`
  MODIFY `id` bigint UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=1232;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;