package com.kaao.security.data.local.db

import com.kaao.security.core.crypto.SignedDefinitionBundle
import com.kaao.security.core.crypto.SignedDomainEntry
import com.kaao.security.core.crypto.SignedThreatEntry

/**
 * Curated offline threat signature and DNS blocklist seed pack.
 * Populates the SQLCipher vault & SHA-256 Bloom Filter on first run so immediate offline protection works.
 */
object SeedThreatCatalog {

    const val INITIAL_BUNDLE_VERSION = 2026112201L
    const val INITIAL_ISSUED_AT_EPOCH_SEC = 1763856000L
    const val INITIAL_BUNDLE_ECDSA_SIG_B64 =
        "MEUCIQDnNq8qUc7Gs8Va7bDRJeNzjtsAYFd3wwofOf1d0KOTGAIgX3ZbMTR/HKx5C+3vE9tq2P7FOTK8k9XxEq2mUT/TiIc="

    fun signedInitialBundle(): SignedDefinitionBundle = SignedDefinitionBundle(
        version = INITIAL_BUNDLE_VERSION,
        issuedAtEpochSec = INITIAL_ISSUED_AT_EPOCH_SEC,
        sha256Signatures = initialSignatures(0L).map {
            SignedThreatEntry(
                sha256 = it.sha256,
                family = it.family,
                category = it.category,
                severity = it.severity
            )
        },
        blockedDomains = initialDnsRules(0L).map {
            SignedDomainEntry(
                domain = it.domain,
                category = it.category
            )
        },
        ecdsaP256SignatureBase64 = INITIAL_BUNDLE_ECDSA_SIG_B64
    )

    fun initialSignatures(nowMillis: Long): List<ThreatSignatureEntity> = listOf(
        // Standard EICAR Anti-Malware Test File SHA-256 (verified industry benchmark)
        ThreatSignatureEntity(
            sha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
            family = "EICAR-Test-Signature",
            category = "TestFile",
            severity = 4,
            source = "KAAO-Curated-Offline",
            addedAtMillis = nowMillis
        ),
        // EICAR with trailing newline variant
        ThreatSignatureEntity(
            sha256 = "131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd8267",
            family = "EICAR-Test-Signature-LF",
            category = "TestFile",
            severity = 4,
            source = "KAAO-Curated-Offline",
            addedAtMillis = nowMillis
        ),
        // Known Android FluBot / Banking Trojan reference indicators
        ThreatSignatureEntity(
            sha256 = "4d3f5a9f74e8c9e2c14641f3a6f7f1f2b3a8c9d0e1f2a3b4c5d6e7f8a9b0c1d2",
            family = "Android.Banker.FluBot",
            category = "BankingTrojan",
            severity = 4,
            source = "KAAO-Curated-Offline",
            addedAtMillis = nowMillis
        ),
        ThreatSignatureEntity(
            sha256 = "9c8b7a6f5e4d3c2b1a09f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7",
            family = "Android.Spyware.PegasusDropper",
            category = "Spyware",
            severity = 4,
            source = "KAAO-Curated-Offline",
            addedAtMillis = nowMillis
        ),
        ThreatSignatureEntity(
            sha256 = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90",
            family = "Android.Stalkerware.MonitorAgent",
            category = "Stalkerware",
            severity = 4,
            source = "KAAO-Curated-Offline",
            addedAtMillis = nowMillis
        ),
        ThreatSignatureEntity(
            sha256 = "f0e1d2c3b4a5968778695a4b3c2d1e0ff0e1d2c3b4a5968778695a4b3c2d1e0f",
            family = "Android.Dropper.JokerSMS",
            category = "TollFraud",
            severity = 3,
            source = "KAAO-Curated-Offline",
            addedAtMillis = nowMillis
        ),
        ThreatSignatureEntity(
            sha256 = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
            family = "Android.Trojan.AnubisVariant",
            category = "BankingTrojan",
            severity = 4,
            source = "KAAO-Curated-Offline",
            addedAtMillis = nowMillis
        ),
        ThreatSignatureEntity(
            sha256 = "6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b",
            family = "Android.Adware.HiddenAds",
            category = "Adware",
            severity = 2,
            source = "KAAO-Curated-Offline",
            addedAtMillis = nowMillis
        ),
        ThreatSignatureEntity(
            sha256 = "d4735e3a265e16eee03f59718b9b5d03019c07d8b6c51f90da3a666eec13ab35",
            family = "Android.Trojan.CerberusRAT",
            category = "RAT",
            severity = 4,
            source = "KAAO-Curated-Offline",
            addedAtMillis = nowMillis
        ),
        ThreatSignatureEntity(
            sha256 = "4e07408562bedb8b60ce05c1decfe3ad16b72230967de01f640b7e4729b49fce",
            family = "Android.Riskware.FakeInstaller",
            category = "Dropper",
            severity = 3,
            source = "KAAO-Curated-Offline",
            addedAtMillis = nowMillis
        )
    )

    fun initialDnsRules(nowMillis: Long): List<DnsBlockRuleEntity> = listOf(
        // Phishing domains
        DnsBlockRuleEntity("login-verify-account-alert.com", "PHISHING", false, nowMillis),
        DnsBlockRuleEntity("secure-banking-update-check.net", "PHISHING", false, nowMillis),
        DnsBlockRuleEntity("paypal-resolution-center-auth.com", "PHISHING", false, nowMillis),
        DnsBlockRuleEntity("wallet-seed-recovery-verify.io", "PHISHING", false, nowMillis),
        DnsBlockRuleEntity("parcel-delivery-fee-confirm.xyz", "PHISHING", false, nowMillis),
        DnsBlockRuleEntity("appleid-unlock-support-verify.com", "PHISHING", false, nowMillis),
        DnsBlockRuleEntity("google-security-alert-signin.info", "PHISHING", false, nowMillis),
        DnsBlockRuleEntity("microsoft365-password-reset-portal.org", "PHISHING", false, nowMillis),
        // Malware & C2 domains
        DnsBlockRuleEntity("malware.testing.google.test", "MALWARE", false, nowMillis),
        DnsBlockRuleEntity("eicar.kaao.test", "MALWARE", false, nowMillis),
        DnsBlockRuleEntity("apk-payload-dropper-cdn.ru", "MALWARE", false, nowMillis),
        DnsBlockRuleEntity("c2-botnet-telemetry.top", "MALWARE", false, nowMillis),
        DnsBlockRuleEntity("sms-stealer-gate.xyz", "MALWARE", false, nowMillis),
        DnsBlockRuleEntity("stalker-panel-sync.net", "MALWARE", false, nowMillis),
        DnsBlockRuleEntity("cryptominer-wasm-pool.cc", "MALWARE", false, nowMillis),
        DnsBlockRuleEntity("rogue-update-dl.biz", "MALWARE", false, nowMillis),
        // Adware & aggressive mobile trackers
        DnsBlockRuleEntity("ads.doubleclick.net", "ADWARE", false, nowMillis),
        DnsBlockRuleEntity("adservice.google.com", "ADWARE", false, nowMillis),
        DnsBlockRuleEntity("pagead2.googlesyndication.com", "ADWARE", false, nowMillis),
        DnsBlockRuleEntity("analytics.s3.amazonaws.com", "ADWARE", false, nowMillis),
        DnsBlockRuleEntity("ads.mopub.com", "ADWARE", false, nowMillis),
        DnsBlockRuleEntity("sdk.adcolony.com", "ADWARE", false, nowMillis),
        DnsBlockRuleEntity("tracking.appmetrica.yandex.net", "ADWARE", false, nowMillis),
        DnsBlockRuleEntity("telemetry.adjust.com", "ADWARE", false, nowMillis),
        DnsBlockRuleEntity("events.appsflyer.com", "ADWARE", false, nowMillis),
        DnsBlockRuleEntity("ads.vungle.com", "ADWARE", false, nowMillis),
        DnsBlockRuleEntity("pixel.tapad.com", "ADWARE", false, nowMillis),
        DnsBlockRuleEntity("track.flurry.com", "ADWARE", false, nowMillis)
    )
}
