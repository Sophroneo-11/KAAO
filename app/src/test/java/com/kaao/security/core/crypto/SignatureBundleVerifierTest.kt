package com.kaao.security.core.crypto

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Base64

class SignatureBundleVerifierTest {

    private val verifier = SignatureBundleVerifier()

    private fun generateP256KeyPair(): KeyPair {
        val kpg = KeyPairGenerator.getInstance("EC")
        kpg.initialize(ECGenParameterSpec("secp256r1"))
        return kpg.generateKeyPair()
    }

    private fun signBundle(unsigned: SignedDefinitionBundle, keyPair: KeyPair): SignedDefinitionBundle {
        val canonical = verifier.canonicalPayload(unsigned).toByteArray(Charsets.UTF_8)
        val signer = Signature.getInstance(SignatureBundleVerifier.ECDSA_ALGORITHM)
        signer.initSign(keyPair.private)
        signer.update(canonical)
        val sigB64 = Base64.getEncoder().encodeToString(signer.sign())
        return unsigned.copy(ecdsaP256SignatureBase64 = sigB64)
    }

    @Test
    fun validEcdsaP256SignedBundlePassesVerification() {
        val keyPair = generateP256KeyPair()
        val pubB64 = Base64.getEncoder().encodeToString(keyPair.public.encoded)
        val unsigned = SignedDefinitionBundle(
            version = 10L,
            issuedAtEpochSec = 1763856000L,
            sha256Signatures = listOf(
                SignedThreatEntry(
                    sha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
                    family = "EICAR-Test",
                    category = "TestFile",
                    severity = 4
                )
            ),
            blockedDomains = listOf(SignedDomainEntry("evil-phish.example", "PHISHING")),
            ecdsaP256SignatureBase64 = ""
        )
        val signed = signBundle(unsigned, keyPair)

        val result = verifier.verify(signed, currentInstalledVersion = 9L, publicKeyBase64 = pubB64)
        assertTrue(result is BundleVerificationResult.Verified)
        val verified = result as BundleVerificationResult.Verified
        assertEquals(10L, verified.version)
        assertEquals(1, verified.signatureCount)
        assertEquals(1, verified.domainCount)
    }

    @Test
    fun tamperedPayloadIsRejected() {
        val keyPair = generateP256KeyPair()
        val pubB64 = Base64.getEncoder().encodeToString(keyPair.public.encoded)
        val signed = signBundle(
            SignedDefinitionBundle(
                version = 10L,
                issuedAtEpochSec = 1763856000L,
                sha256Signatures = emptyList(),
                blockedDomains = listOf(SignedDomainEntry("evil.example", "MALWARE")),
                ecdsaP256SignatureBase64 = ""
            ),
            keyPair
        )
        val tampered = signed.copy(
            blockedDomains = listOf(SignedDomainEntry("tampered.example", "MALWARE"))
        )

        val result = verifier.verify(tampered, currentInstalledVersion = 5L, publicKeyBase64 = pubB64)
        assertTrue(result is BundleVerificationResult.Rejected)
    }

    @Test
    fun olderVersionIsRejectedByAntiRollback() {
        val keyPair = generateP256KeyPair()
        val pubB64 = Base64.getEncoder().encodeToString(keyPair.public.encoded)
        val signed = signBundle(
            SignedDefinitionBundle(
                version = 4L,
                issuedAtEpochSec = 1763856000L,
                sha256Signatures = emptyList(),
                blockedDomains = emptyList(),
                ecdsaP256SignatureBase64 = ""
            ),
            keyPair
        )

        val result = verifier.verify(signed, currentInstalledVersion = 10L, publicKeyBase64 = pubB64)
        assertTrue(result is BundleVerificationResult.Rejected)
    }
}
