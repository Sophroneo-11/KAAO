package com.kaao.security.core.crypto

import com.kaao.security.data.local.db.SeedThreatCatalog
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Verifies that the production bundled SeedThreatCatalog passes real ECDSA-P256 verification
 * against the production pinned NIST P-256 X.509 public key.
 */
class SeedThreatBundleCryptoTest {

    private val verifier = SignatureBundleVerifier()

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
