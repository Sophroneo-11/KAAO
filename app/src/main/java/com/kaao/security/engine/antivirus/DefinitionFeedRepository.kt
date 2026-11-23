package com.kaao.security.engine.antivirus

import com.kaao.security.core.crypto.BundleVerificationResult
import com.kaao.security.data.remote.DefinitionFeedApi
import com.kaao.security.engine.network.AegisVpnController
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Fetches remote ECDSA-P256 signed definition bundles over certificate-pinned TLS,
 * verifies signature + anti-rollback version, updates the SQLCipher vault & lock-free Bloom Filter,
 * and reloads Aegis DNS blocklist rules atomically.
 */
@Singleton
class DefinitionFeedRepository @Inject constructor(
    private val feedApi: DefinitionFeedApi,
    private val antivirusRepository: AntivirusRepository,
    private val vpnController: AegisVpnController
) {
    suspend fun syncFromRemoteFeed(
        feedUrl: String = DEFAULT_FEED_URL
    ): BundleVerificationResult = withContext(Dispatchers.IO) {
        val bundle = runCatching {
            feedApi.fetchSignedBundle(feedUrl)
        }.getOrElse { error ->
            return@withContext BundleVerificationResult.Rejected(
                "Feed fetch failed: ${error.message ?: "network or TLS pin error"}"
            )
        }

        val verification = antivirusRepository.verifyAndApplySignedBundle(bundle)
        if (verification is BundleVerificationResult.Verified) {
            vpnController.reloadMatcherRules()
        }
        verification
    }

    companion object {
        const val DEFAULT_FEED_URL =
            "https://raw.githubusercontent.com/Sophroneo-11/KAAO/HEAD/definitions/kaao-definitions-v1.json"
    }
}
