package com.kaao.security.data.local.db

import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey

@Entity(
    tableName = "threat_signatures",
    indices = [Index(value = ["sha256"], unique = true)]
)
data class ThreatSignatureEntity(
    @PrimaryKey val sha256: String,
    val family: String,
    val category: String,
    val severity: Int,
    val source: String,
    val addedAtMillis: Long
)

@Entity(tableName = "scan_history")
data class ScanHistoryEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0L,
    val scanType: String,
    val scannedItems: Int,
    val threatsFound: Int,
    val stalkerwareFound: Int,
    val durationMillis: Long,
    val completedAtMillis: Long
)

@Entity(
    tableName = "whitelist_entries",
    indices = [Index(value = ["entryType", "targetValue"], unique = true)]
)
data class WhitelistEntryEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0L,
    val entryType: String, // "CLEANER_PATH", "APP_PACKAGE", "DNS_ALLOW"
    val targetValue: String,
    val label: String,
    val addedAtMillis: Long
)

@Entity(
    tableName = "dns_block_rules",
    indices = [Index(value = ["domain"], unique = true), Index(value = ["category"])]
)
data class DnsBlockRuleEntity(
    @PrimaryKey val domain: String,
    val category: String, // PHISHING, MALWARE, ADWARE, CUSTOM_BLOCK, CUSTOM_ALLOW
    val isUserCustom: Boolean = false,
    val addedAtMillis: Long
)

@Entity(
    tableName = "dns_query_logs",
    indices = [Index(value = ["timestampMillis"])]
)
data class DnsQueryLogEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0L,
    val domain: String,
    val queryType: String,
    val blocked: Boolean,
    val category: String,
    val latencyMs: Long,
    val timestampMillis: Long
)

@Entity(tableName = "cloud_reputation_cache")
data class CloudReputationCacheEntity(
    @PrimaryKey val sha256: String,
    val provider: String,
    val isMalicious: Boolean,
    val family: String?,
    val positives: Int,
    val totalEngines: Int,
    val checkedAtMillis: Long
)

@Entity(tableName = "game_profiles")
data class GameProfileEntity(
    @PrimaryKey val packageName: String,
    val appName: String,
    val isCustomAdded: Boolean,
    val isFirewallExcluded: Boolean = true,
    val lastLaunchedMillis: Long = 0L
)
