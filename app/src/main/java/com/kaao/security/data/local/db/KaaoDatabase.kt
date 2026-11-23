package com.kaao.security.data.local.db

import androidx.room.Database
import androidx.room.RoomDatabase

@Database(
    entities = [
        ThreatSignatureEntity::class,
        ScanHistoryEntity::class,
        WhitelistEntryEntity::class,
        DnsBlockRuleEntity::class,
        DnsQueryLogEntity::class,
        CloudReputationCacheEntity::class,
        GameProfileEntity::class
    ],
    version = 1,
    exportSchema = false
)
abstract class KaaoDatabase : RoomDatabase() {
    abstract fun threatSignatureDao(): ThreatSignatureDao
    abstract fun scanHistoryDao(): ScanHistoryDao
    abstract fun whitelistDao(): WhitelistDao
    abstract fun dnsBlockRuleDao(): DnsBlockRuleDao
    abstract fun dnsQueryLogDao(): DnsQueryLogDao
    abstract fun cloudReputationCacheDao(): CloudReputationCacheDao
    abstract fun gameProfileDao(): GameProfileDao

    companion object {
        const val DATABASE_NAME = "kaao_threat_vault.db"
    }
}
