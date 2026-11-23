package com.kaao.security.data.remote

import com.kaao.security.data.local.db.CloudReputationCacheDao
import com.kaao.security.data.local.db.CloudReputationCacheEntity
import com.kaao.security.data.local.prefs.KaaoPreferencesRepository
import com.kaao.security.data.local.prefs.KaaoSettings
import com.kaao.security.domain.model.CloudReputationResult
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.mockk
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class CloudReputationEngineTest {

    private val testSha = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"

    @Test
    fun neverQueriesCloudProvidersWhenUserHasNotOptedIn() = runTest {
        val provider = mockk<CloudReputationProvider>(relaxed = true)
        val cacheDao = mockk<CloudReputationCacheDao>(relaxed = true)
        val prefs = mockk<KaaoPreferencesRepository>()
        coEvery { prefs.getSettings() } returns KaaoSettings(cloudHashLookupEnabled = false)

        val engine = CloudReputationEngine(setOf(provider), cacheDao, prefs)
        val result = engine.lookupHashIfAllowed(testSha, forceOverrideOptIn = false)

        assertNull(result)
        coVerify(exactly = 0) { provider.lookupSha256(any()) }
    }

    @Test
    fun returnsFreshCachedResultWithoutHittingNetwork() = runTest {
        val provider = mockk<CloudReputationProvider>(relaxed = true)
        val cacheDao = mockk<CloudReputationCacheDao>(relaxed = true)
        val prefs = mockk<KaaoPreferencesRepository>()
        coEvery { prefs.getSettings() } returns KaaoSettings(cloudHashLookupEnabled = true)
        coEvery { cacheDao.find(testSha) } returns CloudReputationCacheEntity(
            sha256 = testSha,
            provider = "MalwareBazaar",
            isMalicious = true,
            family = "Android.Banker.FluBot",
            positives = 1,
            totalEngines = 1,
            checkedAtMillis = System.currentTimeMillis()
        )

        val engine = CloudReputationEngine(setOf(provider), cacheDao, prefs)
        val result = engine.lookupHashIfAllowed(testSha)

        assertTrue(result?.isMalicious == true)
        assertEquals("Android.Banker.FluBot", result?.family)
        coVerify(exactly = 0) { provider.lookupSha256(any()) }
    }

    @Test
    fun queriesConfiguredProviderAndCachesMaliciousVerdict() = runTest {
        val cleanProvider = mockk<CloudReputationProvider>()
        coEvery { cleanProvider.isConfigured() } returns true
        coEvery { cleanProvider.lookupSha256(testSha) } returns CloudReputationResult(
            sha256 = testSha,
            provider = "MalwareBazaar",
            isMalicious = false,
            family = null
        )

        val vtProvider = mockk<CloudReputationProvider>()
        coEvery { vtProvider.isConfigured() } returns true
        coEvery { vtProvider.lookupSha256(testSha) } returns CloudReputationResult(
            sha256 = testSha,
            provider = "VirusTotal",
            isMalicious = true,
            family = "Trojan.AndroidOS.Spy",
            positives = 14,
            totalEngines = 65
        )

        val cacheDao = mockk<CloudReputationCacheDao>(relaxed = true)
        coEvery { cacheDao.find(testSha) } returns null
        val prefs = mockk<KaaoPreferencesRepository>()
        coEvery { prefs.getSettings() } returns KaaoSettings(cloudHashLookupEnabled = true)

        val engine = CloudReputationEngine(linkedSetOf(cleanProvider, vtProvider), cacheDao, prefs)
        val result = engine.lookupHashIfAllowed(testSha)

        assertTrue(result?.isMalicious == true)
        assertEquals("VirusTotal", result?.provider)
        assertEquals(14, result?.positives)
        coVerify(exactly = 1) { cacheDao.upsert(match { it.isMalicious && it.provider == "VirusTotal" }) }
        assertFalse(engine.lookupHashIfAllowed("invalid-short-hash") != null)
    }
}
