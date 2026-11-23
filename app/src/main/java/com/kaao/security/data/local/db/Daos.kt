package com.kaao.security.data.local.db

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import kotlinx.coroutines.flow.Flow

@Dao
interface ThreatSignatureDao {
    @Query("SELECT * FROM threat_signatures WHERE sha256 = :sha256 LIMIT 1")
    suspend fun findBySha256(sha256: String): ThreatSignatureEntity?

    @Query("SELECT sha256 FROM threat_signatures")
    suspend fun getAllHashes(): List<String>

    @Query("SELECT COUNT(*) FROM threat_signatures")
    suspend fun count(): Int

    @Query("SELECT COUNT(*) FROM threat_signatures")
    fun observeCount(): Flow<Int>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertAll(entries: List<ThreatSignatureEntity>)
}

@Dao
interface ScanHistoryDao {
    @Query("SELECT * FROM scan_history ORDER BY completedAtMillis DESC LIMIT 20")
    fun observeRecent(): Flow<List<ScanHistoryEntity>>

    @Insert
    suspend fun insert(entry: ScanHistoryEntity)
}

@Dao
interface WhitelistDao {
    @Query("SELECT * FROM whitelist_entries ORDER BY addedAtMillis DESC")
    fun observeAll(): Flow<List<WhitelistEntryEntity>>

    @Query("SELECT * FROM whitelist_entries WHERE entryType = :type")
    suspend fun getByType(type: String): List<WhitelistEntryEntity>

    @Query("SELECT * FROM whitelist_entries WHERE entryType = :type ORDER BY addedAtMillis DESC")
    fun observeByType(type: String): Flow<List<WhitelistEntryEntity>>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsert(entry: WhitelistEntryEntity)

    @Query("DELETE FROM whitelist_entries WHERE id = :id")
    suspend fun deleteById(id: Long)

    @Query("DELETE FROM whitelist_entries WHERE entryType = :type AND targetValue = :target")
    suspend fun deleteByTarget(type: String, target: String)
}

@Dao
interface DnsBlockRuleDao {
    @Query("SELECT * FROM dns_block_rules")
    suspend fun getAll(): List<DnsBlockRuleEntity>

    @Query("SELECT * FROM dns_block_rules ORDER BY isUserCustom DESC, domain ASC")
    fun observeAll(): Flow<List<DnsBlockRuleEntity>>

    @Query("SELECT COUNT(*) FROM dns_block_rules")
    suspend fun count(): Int

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertAll(rules: List<DnsBlockRuleEntity>)

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsert(rule: DnsBlockRuleEntity)

    @Query("DELETE FROM dns_block_rules WHERE domain = :domain")
    suspend fun deleteByDomain(domain: String)
}

@Dao
interface DnsQueryLogDao {
    @Query("SELECT * FROM dns_query_logs ORDER BY timestampMillis DESC LIMIT 120")
    fun observeRecent(): Flow<List<DnsQueryLogEntity>>

    @Query("SELECT COUNT(*) FROM dns_query_logs WHERE blocked = 1")
    fun observeBlockedCount(): Flow<Long>

    @Insert
    suspend fun insert(entry: DnsQueryLogEntity)

    @Query("DELETE FROM dns_query_logs WHERE id NOT IN (SELECT id FROM dns_query_logs ORDER BY timestampMillis DESC LIMIT 500)")
    suspend fun pruneOld()

    @Query("DELETE FROM dns_query_logs")
    suspend fun clearAll()
}

@Dao
interface CloudReputationCacheDao {
    @Query("SELECT * FROM cloud_reputation_cache WHERE sha256 = :sha256 LIMIT 1")
    suspend fun find(sha256: String): CloudReputationCacheEntity?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsert(entry: CloudReputationCacheEntity)

    @Query("DELETE FROM cloud_reputation_cache WHERE checkedAtMillis < :cutoffMillis")
    suspend fun pruneExpired(cutoffMillis: Long)
}

@Dao
interface GameProfileDao {
    @Query("SELECT * FROM game_profiles ORDER BY lastLaunchedMillis DESC, appName ASC")
    fun observeAll(): Flow<List<GameProfileEntity>>

    @Query("SELECT * FROM game_profiles")
    suspend fun getAll(): List<GameProfileEntity>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsert(profile: GameProfileEntity)

    @Query("DELETE FROM game_profiles WHERE packageName = :packageName")
    suspend fun delete(packageName: String)
}
