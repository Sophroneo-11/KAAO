package com.kaao.security.core.crypto

import kotlinx.serialization.Serializable
import java.security.KeyFactory
import java.security.PublicKey
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import javax.inject.Inject
import javax.inject.Singleton

@Serializable
data class SignedDefinitionBundle(
    val version: Long,
    val issuedAtEpochSec: Long,
    val sha256Signatures: List<SignedThreatEntry>,
    val blockedDomains: List<SignedDomainEntry>,
    val ecdsaP256SignatureBase64: String
)

@Serializable
data class SignedThreatEntry(
    val sha256: String,
    val family: String,
    val category: String,
    val severity: Int
)

@Serializable
data class SignedDomainEntry(
    val domain: String,
    val category: String
)

sealed interface BundleVerificationResult {
    data class Verified(val version: Long, val signatureCount: Int, val domainCount: Int) : BundleVerificationResult
    data class Rejected(val reason: String) : BundleVerificationResult
}

/**
 * Verifies signed threat & DNS definition bundles using ECDSA over NIST P-256 (SHA256withECDSA)
 * with monotonic version anti-rollback enforcement.
 */
@Singleton
class SignatureBundleVerifier @Inject constructor() {

    fun verify(
        bundle: SignedDefinitionBundle,
        currentInstalledVersion: Long,
        publicKeyBase64: String = DEFAULT_PINNED_P256_PUBLIC_KEY_B64
    ): BundleVerificationResult {
        if (bundle.version < currentInstalledVersion) {
            return BundleVerificationResult.Rejected(
                "Anti-rollback check failed: bundle v${bundle.version} < installed v$currentInstalledVersion"
            )
        }
        if (bundle.ecdsaP256SignatureBase64.isBlank()) {
            return BundleVerificationResult.Rejected("Missing ECDSA-P256 signature")
        }

        val canonicalBytes = canonicalPayload(bundle).toByteArray(Charsets.UTF_8)
        val verified = runCatching {
            val publicKey = decodeX509EcPublicKey(publicKeyBase64)
            val signatureBytes = Base64.getDecoder().decode(bundle.ecdsaP256SignatureBase64)
            val verifier = Signature.getInstance(ECDSA_ALGORITHM)
            verifier.initVerify(publicKey)
            verifier.update(canonicalBytes)
            verifier.verify(signatureBytes)
        }.getOrElse { error ->
            return BundleVerificationResult.Rejected(
                "ECDSA-P256 verification error: ${error.message ?: "invalid key or signature"}"
            )
        }

        return if (verified) {
            BundleVerificationResult.Verified(
                version = bundle.version,
                signatureCount = bundle.sha256Signatures.size,
                domainCount = bundle.blockedDomains.size
            )
        } else {
            BundleVerificationResult.Rejected("ECDSA-P256 cryptographic signature mismatch")
        }
    }

    fun canonicalPayload(bundle: SignedDefinitionBundle): String {
        val sb = StringBuilder()
        sb.append("KAAO-DEF-V1|")
        sb.append(bundle.version).append('|')
        sb.append(bundle.issuedAtEpochSec).append('|')
        bundle.sha256Signatures
            .sortedBy { it.sha256.lowercase() }
            .forEach { entry ->
                sb.append(entry.sha256.lowercase())
                    .append(':')
                    .append(entry.family)
                    .append(':')
                    .append(entry.category)
                    .append(':')
                    .append(entry.severity)
                    .append(';')
            }
        sb.append('|')
        bundle.blockedDomains
            .sortedBy { it.domain.lowercase() }
            .forEach { domain ->
                sb.append(domain.domain.lowercase())
                    .append(':')
                    .append(domain.category)
                    .append(';')
            }
        return sb.toString()
    }

    private fun decodeX509EcPublicKey(base64Spki: String): PublicKey {
        val keyBytes = Base64.getDecoder().decode(base64Spki)
        val spec = X509EncodedKeySpec(keyBytes)
        return KeyFactory.getInstance("EC").generatePublic(spec)
    }

    companion object {
        const val ECDSA_ALGORITHM = "SHA256withECDSA"

        /**
         * Pinned NIST P-256 (secp256r1) X.509 SPKI public key for KAAO definition releases.
         */
        const val DEFAULT_PINNED_P256_PUBLIC_KEY_B64 =
            "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4v8W2F0z0h7h0aP5v6mG0c0h6o4S" +
                "7w3H8vV2F9g5k3j1L7p8n2q4R6t8V0w2Y4z6A8c0E2g4I6k8M0o2Q4s6Ug=="
    }
}
