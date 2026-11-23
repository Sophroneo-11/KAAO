package com.kaao.security.core.crypto

import com.kaao.security.data.local.db.SeedThreatCatalog
import kotlinx.serialization.json.Json
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Verifies that the production bundled SeedThreatCatalog and definitions/kaao-definitions-v1.json
 * pass real ECDSA-P256 verification against the production pinned NIST P-256 X.509 public key.
 */
class SeedThreatBundleCryptoTest {

    private val verifier = SignatureBundleVerifier()
    private val json = Json { ignoreUnknownKeys = true }

    @Test
    fun productionSignedSeedBundleVerifiesAgainstPinnedPublicKey() {
        val seedBundle = SeedThreatCatalog.signedInitialBundle()
        val result = verifier.verify(
            bundle = seedBundle,
            currentInstalledVersion = 0L,
            publicKeyBase64 = SignatureBundleVerifier.DEFAULT_PINNED_P256_PUBLIC_KEY_B64
        )
        assertTrue("Expected production seed bundle to pass ECDSA-P256 verification, got $result", result is BundleVerificationResult.Verified)
        val verified = result as BundleVerificationResult.Verified
        assertEquals(SeedThreatCatalog.INITIAL_BUNDLE_VERSION, verified.version)
        assertTrue(verified.signatureCount >= 10)
        assertTrue(verified.domainCount >= 20)
    }

    @Test
    fun remoteFeedJsonFilePassesEcdsaP256Verification() {
        val candidates = listOf(
            File("../definitions/kaao-definitions-v1.json"),
            File("definitions/kaao-definitions-v1.json")
        )
        val feedFile = candidates.firstOrNull { it.exists() }
        assertTrue("Expected definitions/kaao-definitions-v1.json to exist", feedFile != null)
        val bundle = json.decodeFromString(SignedDefinitionBundle.serializer(), feedFile!!.readText())
        val result = verifier.verify(
            bundle = bundle,
            currentInstalledVersion = 0L,
            publicKeyBase64 = SignatureBundleVerifier.DEFAULT_PINNED_P256_PUBLIC_KEY_B64
        )
        assertTrue("Expected definitions/kaao-definitions-v1.json to verify cleanly, got $result", result is BundleVerificationResult.Verified)
    }

    @Test
    fun tamperingWithProductionSeedBundleCausesRejection() {
        val seedBundle = SeedThreatCatalog.signedInitialBundle()
        val tampered = seedBundle.copy(
            blockedDomains = seedBundle.blockedDomains + SignedDomainEntry("injected.example", "MALWARE")
        )
        val result = verifier.verify(
            bundle = tampered,
            currentInstalledVersion = 0L,
            publicKeyBase64 = SignatureBundleVerifier.DEFAULT_PINNED_P256_PUBLIC_KEY_B64
        )
        assertTrue(result is BundleVerificationResult.Rejected)
    }
}
