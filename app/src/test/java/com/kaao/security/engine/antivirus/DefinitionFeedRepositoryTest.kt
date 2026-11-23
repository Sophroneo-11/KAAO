package com.kaao.security.engine.antivirus

import com.kaao.security.core.crypto.BundleVerificationResult
import com.kaao.security.data.local.db.SeedThreatCatalog
import com.kaao.security.data.remote.DefinitionFeedApi
import com.kaao.security.engine.network.AegisVpnController
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.mockk
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException

class DefinitionFeedRepositoryTest {

    @Test
    fun verifiedRemoteBundleTriggersDnsMatcherReload() = runTest {
        val feedApi = mockk<DefinitionFeedApi>()
        val avRepo = mockk<AntivirusRepository>()
        val vpnController = mockk<AegisVpnController>(relaxed = true)

        val bundle = SeedThreatCatalog.signedInitialBundle()
        coEvery { feedApi.fetchSignedBundle(any()) } returns bundle
        coEvery { avRepo.verifyAndApplySignedBundle(bundle) } returns BundleVerificationResult.Verified(
            version = bundle.version,
            signatureCount = bundle.sha256Signatures.size,
            domainCount = bundle.blockedDomains.size
        )

        val repo = DefinitionFeedRepository(feedApi, avRepo, vpnController)
        val result = repo.syncFromRemoteFeed()

        assertTrue(result is BundleVerificationResult.Verified)
        coVerify(exactly = 1) { vpnController.reloadMatcherRules() }
    }

    @Test
    fun rejectedRemoteBundleDoesNotReloadDnsRules() = runTest {
        val feedApi = mockk<DefinitionFeedApi>()
        val avRepo = mockk<AntivirusRepository>()
        val vpnController = mockk<AegisVpnController>(relaxed = true)

        val bundle = SeedThreatCatalog.signedInitialBundle()
        coEvery { feedApi.fetchSignedBundle(any()) } returns bundle
        coEvery { avRepo.verifyAndApplySignedBundle(bundle) } returns BundleVerificationResult.Rejected("Signature mismatch")

        val repo = DefinitionFeedRepository(feedApi, avRepo, vpnController)
        val result = repo.syncFromRemoteFeed()

        assertTrue(result is BundleVerificationResult.Rejected)
        coVerify(exactly = 0) { vpnController.reloadMatcherRules() }
    }

    @Test
    fun networkFailureReturnsRejectedGracefully() = runTest {
        val feedApi = mockk<DefinitionFeedApi>()
        val avRepo = mockk<AntivirusRepository>(relaxed = true)
        val vpnController = mockk<AegisVpnController>(relaxed = true)

        coEvery { feedApi.fetchSignedBundle(any()) } throws IOException("Certificate pinning failure")

        val repo = DefinitionFeedRepository(feedApi, avRepo, vpnController)
        val result = repo.syncFromRemoteFeed()

        assertTrue(result is BundleVerificationResult.Rejected)
        coVerify(exactly = 0) { avRepo.verifyAndApplySignedBundle(any()) }
        coVerify(exactly = 0) { vpnController.reloadMatcherRules() }
    }
}
