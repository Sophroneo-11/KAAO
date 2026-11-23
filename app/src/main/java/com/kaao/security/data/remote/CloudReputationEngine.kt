package com.kaao.security.data.remote

import com.kaao.security.data.local.db.CloudReputationCacheDao
import com.kaao.security.data.local.db.CloudReputationCacheEntity
import com.kaao.security.data.local.prefs.KaaoPreferencesRepository
import com.kaao.security.domain.model.CloudReputationResult
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Pluggable hash-only cloud reputation provider interface.
 * Strictly transmits SHA-256 hashes only — never uploads APK binaries or user files.
 */
interface CloudReputationProvider {
    val providerName: String
    suspend fun isConfigured(): Boolean
    suspend fun lookupSha256(sha256: String): CloudReputationResult?
}

@Singleton
class MalwareBazaarProvider @Inject constructor(
    private val api: MalwareBazaarApi
) : CloudReputationProvider {

    override val providerName: String = "MalwareBazaar"

    override suspend fun isConfigured(): Boolean = true

    override suspend fun lookupSha256(sha256: String): CloudReputationResult? = runCatching {
        val response = api.queryHash(sha256Hash = sha256.lowercase())
        if (response.queryStatus == "ok" && response.data.isNotEmpty()) {
            val hit = response.data.first()
            CloudReputationResult(
                sha256 = sha256.lowercase(),
                provider = providerName,
                isMalicious = true,
                family = hit.signature ?: hit.tags?.firstOrNull() ?: "MalwareBazaar.Detected",
                positives = 1,
                totalEngines = 1
            )
        } else {
            CloudReputationResult(
                sha256 = sha256.lowercase(),
                provider = providerName,
                isMalicious = false,
                family = null,
                positives = 0,
                totalEngines = 1
            )
        }
    }.getOrNull()
}

@Singleton
class VirusTotalProvider @Inject constructor(
    private val api: VirusTotalApi,
    private val prefs: KaaoPreferencesRepository
) : CloudReputationProvider {

    override val providerName: String = "VirusTotal"

    override suspend fun isConfigured(): Boolean = !prefs.getDecryptedVirusTotalApiKey().isNullOrBlank()

    override suspend fun lookupSha256(sha256: String): CloudReputationResult? {
        val apiKey = prefs.getDecryptedVirusTotalApiKey() ?: return null
        return runCatching {
            val response = api.getFileReport(sha256 = sha256.lowercase(), apiKey = apiKey)
            val stats = response.data?.attributes?.lastAnalysisStats
            val malicious = stats?.malicious ?: 0
            val suspicious = stats?.suspicious ?: 0
            val total = malicious + suspicious + (stats?.harmless ?: 0) + (stats?.undetected ?: 0)
            val label = response.data?.attributes?.threatClassification?.suggestedThreatLabel
            CloudReputationResult(
                sha256 = sha256.lowercase(),
                provider = providerName,
                isMalicious = malicious >= 2 || (malicious == 1 && suspicious >= 2),
                family = label ?: if (malicious > 0) "VirusTotal.Flagged" else null,
                positives = malicious,
                totalEngines = total
            )
        }.getOrNull()
    }
}

@Singleton
class CloudReputationEngine @Inject constructor(
    private val providers: Set<@JvmSuppressWildcards CloudReputationProvider>,
    private val cacheDao: CloudReputationCacheDao,
    private val prefs: KaaoPreferencesRepository
) {
    suspend fun lookupHashIfAllowed(
        sha256: String,
        forceOverrideOptIn: Boolean = false
    ): CloudReputationResult? = withContext(Dispatchers.IO) {
        val normalized = sha256.trim().lowercase()
        if (normalized.length != 64) return@withContext null

        val settings = prefs.getSettings()
        if (!forceOverrideOptIn && !settings.cloudHashLookupEnabled) {
            return@withContext null
        }

        val now = System.currentTimeMillis()
        val cached = cacheDao.find(normalized)
        if (cached != null && (now - cached.checkedAtMillis) < CACHE_TTL_MILLIS) {
            return@withContext CloudReputationResult(
                sha256 = cached.sha256,
                provider = cached.provider,
                isMalicious = cached.isMalicious,
                family = cached.family,
                positives = cached.positives,
                totalEngines = cached.totalEngines,
                checkedAtMillis = cached.checkedAtMillis
            )
        }

        var lastCleanResult: CloudReputationResult? = null
        for (provider in providers) {
            if (!provider.isConfigured()) continue
            val result = provider.lookupSha256(normalized) ?: continue
            if (result.isMalicious) {
                cacheResult(result)
                return@withContext result
            }
            lastCleanResult = result
        }

        if (lastCleanResult != null) {
            cacheResult(lastCleanResult)
        }
        lastCleanResult
    }

    private suspend fun cacheResult(result: CloudReputationResult) {
        cacheDao.upsert(
            CloudReputationCacheEntity(
                sha256 = result.sha256,
                provider = result.provider,
                isMalicious = result.isMalicious,
                family = result.family,
                positives = result.positives,
                totalEngines = result.totalEngines,
                checkedAtMillis = result.checkedAtMillis
            )
        )
    }

    companion object {
        private const val CACHE_TTL_MILLIS = 24L * 60L * 60L * 1000L // 24 hours
    }
}
