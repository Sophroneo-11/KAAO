package com.kaao.security.engine.antivirus

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Environment
import com.kaao.security.core.crypto.BundleVerificationResult
import com.kaao.security.core.crypto.HashUtils
import com.kaao.security.core.crypto.SignatureBundleVerifier
import com.kaao.security.core.crypto.SignedDefinitionBundle
import com.kaao.security.data.local.db.DnsBlockRuleDao
import com.kaao.security.data.local.db.DnsBlockRuleEntity
import com.kaao.security.data.local.db.ScanHistoryDao
import com.kaao.security.data.local.db.ScanHistoryEntity
import com.kaao.security.data.local.db.SeedThreatCatalog
import com.kaao.security.data.local.db.ThreatSignatureDao
import com.kaao.security.data.local.db.ThreatSignatureEntity
import com.kaao.security.data.local.db.WhitelistDao
import com.kaao.security.data.local.db.WhitelistEntryEntity
import com.kaao.security.data.local.prefs.KaaoPreferencesRepository
import com.kaao.security.data.remote.CloudReputationEngine
import com.kaao.security.domain.model.AntivirusScanProgress
import com.kaao.security.domain.model.CloudReputationResult
import com.kaao.security.domain.model.StalkerwareFinding
import com.kaao.security.domain.model.ThreatFinding
import com.kaao.security.domain.model.ThreatSeverity
import com.kaao.security.domain.model.ThreatSource
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import java.io.File
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class AntivirusRepository @Inject constructor(
    @ApplicationContext private val context: Context,
    private val threatSignatureDao: ThreatSignatureDao,
    private val scanHistoryDao: ScanHistoryDao,
    private val whitelistDao: WhitelistDao,
    private val dnsBlockRuleDao: DnsBlockRuleDao,
    private val prefs: KaaoPreferencesRepository,
    private val bloomFilter: Sha256BloomFilter,
    private val staticApkAnalyzer: StaticApkAnalyzer,
    private val stalkerwareAuditor: StalkerwarePrivilegeAuditor,
    private val cloudReputationEngine: CloudReputationEngine,
    private val signatureBundleVerifier: SignatureBundleVerifier,
    private val json: Json
) {
    private val _scanProgress = MutableStateFlow(AntivirusScanProgress())
    val scanProgress: StateFlow<AntivirusScanProgress> = _scanProgress.asStateFlow()

    private val _threatFindings = MutableStateFlow<List<ThreatFinding>>(emptyList())
    val threatFindings: StateFlow<List<ThreatFinding>> = _threatFindings.asStateFlow()

    private val _stalkerwareFindings = MutableStateFlow<List<StalkerwareFinding>>(emptyList())
    val stalkerwareFindings: StateFlow<List<StalkerwareFinding>> = _stalkerwareFindings.asStateFlow()

    val signatureCountFlow: Flow<Int> = threatSignatureDao.observeCount()
    val scanHistoryFlow: Flow<List<ScanHistoryEntity>> = scanHistoryDao.observeRecent()

    val bloomCapacity: Int
        get() = bloomFilter.bitCapacity

    val bloomItemCount: Int
        get() = bloomFilter.itemCount

    suspend fun initializeVaultAndBloomFilter(): BundleVerificationResult = withContext(Dispatchers.IO) {
        val now = System.currentTimeMillis()
        val seedBundle = SeedThreatCatalog.signedInitialBundle()
        val verification = signatureBundleVerifier.verify(
            bundle = seedBundle,
            currentInstalledVersion = 0L
        )

        if (threatSignatureDao.count() == 0 && verification is BundleVerificationResult.Verified) {
            threatSignatureDao.upsertAll(SeedThreatCatalog.initialSignatures(now))
        }
        if (dnsBlockRuleDao.count() == 0 && verification is BundleVerificationResult.Verified) {
            dnsBlockRuleDao.upsertAll(SeedThreatCatalog.initialDnsRules(now))
        }

        val allHashes = threatSignatureDao.getAllHashes()
        bloomFilter.rebuildFromHexHashes(allHashes)
        val settings = prefs.getSettings()
        if (verification is BundleVerificationResult.Verified && settings.lastDefinitionVerifiedMillis == 0L) {
            prefs.updateDefinitionMetadata(seedBundle.version, now)
        }
        verification
    }

    suspend fun importSignedJsonBundle(rawJson: String): BundleVerificationResult = withContext(Dispatchers.IO) {
        val parsed = runCatching {
            json.decodeFromString(SignedDefinitionBundle.serializer(), rawJson)
        }.getOrElse { error ->
            return@withContext BundleVerificationResult.Rejected(
                "Malformed definition bundle JSON: ${error.message ?: "parse error"}"
            )
        }
        verifyAndApplySignedBundle(parsed)
    }

    suspend fun verifyAndApplySignedBundle(
        bundle: SignedDefinitionBundle,
        publicKeyBase64: String = SignatureBundleVerifier.DEFAULT_PINNED_P256_PUBLIC_KEY_B64
    ): BundleVerificationResult = withContext(Dispatchers.IO) {
        val currentVersion = prefs.getSettings().definitionVersion
        val verification = signatureBundleVerifier.verify(bundle, currentVersion, publicKeyBase64)
        if (verification is BundleVerificationResult.Verified) {
            val now = System.currentTimeMillis()
            val sigEntities = bundle.sha256Signatures.map {
                ThreatSignatureEntity(
                    sha256 = it.sha256.lowercase(),
                    family = it.family,
                    category = it.category,
                    severity = it.severity.coerceIn(1, 4),
                    source = "ECDSA-P256-Signed-v${bundle.version}",
                    addedAtMillis = now
                )
            }
            if (sigEntities.isNotEmpty()) {
                threatSignatureDao.upsertAll(sigEntities)
            }
            val domainEntities = bundle.blockedDomains.map {
                DnsBlockRuleEntity(
                    domain = it.domain.lowercase(),
                    category = it.category.uppercase(),
                    isUserCustom = false,
                    addedAtMillis = now
                )
            }
            if (domainEntities.isNotEmpty()) {
                dnsBlockRuleDao.upsertAll(domainEntities)
            }
            bloomFilter.rebuildFromHexHashes(threatSignatureDao.getAllHashes())
            prefs.updateDefinitionMetadata(bundle.version, now)
        }
        verification
    }

    suspend fun runInstalledAppsScan(includeSystemApps: Boolean = false): List<ThreatFinding> =
        withContext(Dispatchers.IO) {
            val start = System.currentTimeMillis()
            if (bloomFilter.itemCount == 0) initializeVaultAndBloomFilter()

            val whitelistedPackages = whitelistDao.getByType(WHITELIST_TYPE_APP)
                .map { it.targetValue }
                .toSet()

            val pm = context.packageManager
            val apps = runCatching {
                pm.getInstalledApplications(PackageManager.GET_META_DATA)
            }.getOrDefault(emptyList()).filter { app ->
                app.packageName != context.packageName &&
                    app.packageName !in whitelistedPackages &&
                    (includeSystemApps || (app.flags and ApplicationInfo.FLAG_SYSTEM) == 0)
            }

            _scanProgress.value = AntivirusScanProgress(
                isScanning = true,
                currentTarget = "Initializing SHA-256 Bloom Filter...",
                scannedCount = 0,
                totalCount = apps.size,
                stage = "Scanning Installed Apps"
            )

            val discovered = mutableListOf<ThreatFinding>()
            apps.forEachIndexed { index, app ->
                val label = runCatching { pm.getApplicationLabel(app).toString() }.getOrDefault(app.packageName)
                _scanProgress.value = AntivirusScanProgress(
                    isScanning = true,
                    currentTarget = label,
                    scannedCount = index + 1,
                    totalCount = apps.size,
                    stage = "Inspecting APK & DEX heuristics"
                )

                val sourceDir = app.sourceDir
                if (!sourceDir.isNullOrBlank()) {
                    val finding = inspectApkOrFile(
                        file = File(sourceDir),
                        title = label,
                        packageName = app.packageName,
                        isSystemApp = (app.flags and ApplicationInfo.FLAG_SYSTEM) != 0,
                        defaultSource = ThreatSource.STATIC_APK_HEURISTIC
                    )
                    if (finding != null) discovered.add(finding)
                }
            }

            _scanProgress.value = AntivirusScanProgress(
                isScanning = true,
                currentTarget = "Auditing Device Admin & Accessibility privileges...",
                scannedCount = apps.size,
                totalCount = apps.size,
                stage = "Stalkerware Privilege Audit"
            )
            val stalkerware = stalkerwareAuditor.auditActivePrivileges(whitelistedPackages)
            _stalkerwareFindings.value = stalkerware

            _threatFindings.value = discovered.sortedByDescending { it.riskScore }
            _scanProgress.value = AntivirusScanProgress(
                isScanning = false,
                currentTarget = "Scan complete",
                scannedCount = apps.size,
                totalCount = apps.size,
                stage = "Idle"
            )

            scanHistoryDao.insert(
                ScanHistoryEntity(
                    scanType = if (includeSystemApps) "FULL_APPS" else "QUICK_APPS",
                    scannedItems = apps.size,
                    threatsFound = discovered.size,
                    stalkerwareFound = stalkerware.size,
                    durationMillis = System.currentTimeMillis() - start,
                    completedAtMillis = System.currentTimeMillis()
                )
            )
            discovered
        }

    suspend fun runDeepDownloadsAndApkScan(): List<ThreatFinding> = withContext(Dispatchers.IO) {
        val start = System.currentTimeMillis()
        if (bloomFilter.itemCount == 0) initializeVaultAndBloomFilter()

        val appFindings = runInstalledAppsScan(includeSystemApps = false).toMutableList()
        val downloadsDir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
        val candidateFiles = mutableListOf<File>()

        if (downloadsDir != null && downloadsDir.exists() && downloadsDir.canRead()) {
            downloadsDir.walkTopDown()
                .maxDepth(4)
                .filter { it.isFile && it.canRead() && it.length() in 1L..MAX_SCAN_FILE_BYTES }
                .filter { file ->
                    val ext = file.extension.lowercase()
                    ext in SCANNABLE_EXTENSIONS || file.name.contains("eicar", ignoreCase = true)
                }
                .take(300)
                .forEach { candidateFiles.add(it) }
        }

        candidateFiles.forEachIndexed { index, file ->
            _scanProgress.value = AntivirusScanProgress(
                isScanning = true,
                currentTarget = file.name,
                scannedCount = index + 1,
                totalCount = candidateFiles.size,
                stage = "Scanning Downloads & APKs"
            )
            val finding = inspectApkOrFile(
                file = file,
                title = file.name,
                packageName = null,
                isSystemApp = false,
                defaultSource = ThreatSource.DOWNLOADS_OBSERVER
            )
            if (finding != null) appFindings.add(finding)
        }

        val sorted = appFindings.distinctBy { it.id }.sortedByDescending { it.riskScore }
        _threatFindings.value = sorted
        _scanProgress.value = AntivirusScanProgress(
            isScanning = false,
            currentTarget = "Deep scan complete",
            scannedCount = candidateFiles.size,
            totalCount = candidateFiles.size,
            stage = "Idle"
        )

        scanHistoryDao.insert(
            ScanHistoryEntity(
                scanType = "DEEP_STORAGE_AND_APPS",
                scannedItems = candidateFiles.size,
                threatsFound = sorted.size,
                stalkerwareFound = _stalkerwareFindings.value.size,
                durationMillis = System.currentTimeMillis() - start,
                completedAtMillis = System.currentTimeMillis()
            )
        )
        sorted
    }

    suspend fun runStalkerwareAuditOnly(): List<StalkerwareFinding> = withContext(Dispatchers.IO) {
        val whitelisted = whitelistDao.getByType(WHITELIST_TYPE_APP).map { it.targetValue }.toSet()
        val results = stalkerwareAuditor.auditActivePrivileges(whitelisted)
        _stalkerwareFindings.value = results
        results
    }

    suspend fun scanSinglePackage(
        packageName: String,
        source: ThreatSource = ThreatSource.REALTIME_INSTALL_SHIELD
    ): ThreatFinding? = withContext(Dispatchers.IO) {
        if (bloomFilter.itemCount == 0) initializeVaultAndBloomFilter()
        val whitelisted = whitelistDao.getByType(WHITELIST_TYPE_APP).map { it.targetValue }.toSet()
        if (packageName in whitelisted || packageName == context.packageName) return@withContext null

        val pm = context.packageManager
        val appInfo = runCatching { pm.getApplicationInfo(packageName, 0) }.getOrNull()
            ?: return@withContext null
        val label = runCatching { pm.getApplicationLabel(appInfo).toString() }.getOrDefault(packageName)
        val finding = inspectApkOrFile(
            file = File(appInfo.sourceDir),
            title = label,
            packageName = packageName,
            isSystemApp = (appInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0,
            defaultSource = source
        )
        if (finding != null) {
            recordRealtimeFinding(finding)
        }
        finding
    }

    suspend fun scanSingleFile(
        file: File,
        source: ThreatSource = ThreatSource.DOWNLOADS_OBSERVER
    ): ThreatFinding? = withContext(Dispatchers.IO) {
        if (bloomFilter.itemCount == 0) initializeVaultAndBloomFilter()
        val finding = inspectApkOrFile(
            file = file,
            title = file.name,
            packageName = null,
            isSystemApp = false,
            defaultSource = source
        )
        if (finding != null) {
            recordRealtimeFinding(finding)
        }
        finding
    }

    suspend fun verifyHashWithCloud(sha256: String): CloudReputationResult? =
        cloudReputationEngine.lookupHashIfAllowed(sha256, forceOverrideOptIn = true)

    suspend fun whitelistApp(packageName: String, label: String) = withContext(Dispatchers.IO) {
        whitelistDao.upsert(
            WhitelistEntryEntity(
                entryType = WHITELIST_TYPE_APP,
                targetValue = packageName,
                label = label,
                addedAtMillis = System.currentTimeMillis()
            )
        )
        _threatFindings.value = _threatFindings.value.filterNot { it.packageName == packageName }
        _stalkerwareFindings.value = _stalkerwareFindings.value.filterNot { it.packageName == packageName }
    }

    fun dismissFinding(findingId: String) {
        _threatFindings.value = _threatFindings.value.filterNot { it.id == findingId }
    }

    private suspend fun inspectApkOrFile(
        file: File,
        title: String,
        packageName: String?,
        isSystemApp: Boolean,
        defaultSource: ThreatSource
    ): ThreatFinding? {
        if (!file.exists() || !file.isFile || !file.canRead()) return null
        val sha256Bytes = HashUtils.sha256File(file) ?: return null
        val sha256Hex = HashUtils.toHex(sha256Bytes)

        // Stage 1: O(k) Lock-Free Bloom Filter pre-check -> SQLCipher exact confirmation
        if (bloomFilter.mightContainBytes(sha256Bytes)) {
            val sigMatch = threatSignatureDao.findBySha256(sha256Hex)
            if (sigMatch != null) {
                val sev = when (sigMatch.severity) {
                    4 -> ThreatSeverity.CRITICAL
                    3 -> ThreatSeverity.HIGH
                    2 -> ThreatSeverity.MEDIUM
                    else -> ThreatSeverity.LOW
                }
                return ThreatFinding(
                    id = "${packageName ?: file.absolutePath}#$sha256Hex",
                    title = title,
                    packageName = packageName,
                    filePath = file.absolutePath,
                    sha256 = sha256Hex,
                    family = sigMatch.family,
                    severity = sev,
                    riskScore = 95,
                    source = ThreatSource.BLOOM_SIGNATURE_VAULT,
                    reasons = listOf(
                        "Exact SHA-256 signature match in encrypted KAAO threat vault",
                        "Classification: ${sigMatch.category} (${sigMatch.source})"
                    ),
                    detectedAtMillis = System.currentTimeMillis(),
                    isSystemApp = isSystemApp
                )
            }
        }

        // Stage 2: Static APK/DEX/Hidden-Asset Heuristic Analysis
        val isApkLike = file.extension.equals("apk", ignoreCase = true) || packageName != null
        val staticResult = if (isApkLike) staticApkAnalyzer.analyzeApk(file) else null

        // Stage 3: Optional Hash-Only Cloud Reputation (only when opted in by user)
        val shouldQueryCloud = staticResult == null || staticResult.riskScore >= 20 || packageName == null
        val cloudResult = if (shouldQueryCloud) {
            cloudReputationEngine.lookupHashIfAllowed(sha256Hex)
        } else {
            null
        }

        if (cloudResult != null && cloudResult.isMalicious) {
            val combinedReasons = buildList {
                add("Flagged malicious by ${cloudResult.provider} hash-only intelligence (${cloudResult.positives}/${cloudResult.totalEngines})")
                staticResult?.reasons?.forEach { add(it) }
            }
            val cloudSource = if (cloudResult.provider == "VirusTotal") {
                ThreatSource.CLOUD_VIRUSTOTAL
            } else {
                ThreatSource.CLOUD_MALWAREBAZAAR
            }
            return ThreatFinding(
                id = "${packageName ?: file.absolutePath}#$sha256Hex",
                title = title,
                packageName = packageName,
                filePath = file.absolutePath,
                sha256 = sha256Hex,
                family = cloudResult.family ?: "Cloud.Malicious",
                severity = ThreatSeverity.CRITICAL,
                riskScore = maxOf(90, staticResult?.riskScore ?: 90),
                source = cloudSource,
                reasons = combinedReasons,
                detectedAtMillis = System.currentTimeMillis(),
                isSystemApp = isSystemApp
            )
        }

        if (staticResult != null && staticResult.riskScore >= 35) {
            return ThreatFinding(
                id = "${packageName ?: file.absolutePath}#$sha256Hex",
                title = title,
                packageName = packageName,
                filePath = file.absolutePath,
                sha256 = sha256Hex,
                family = staticResult.detectedFamily,
                severity = staticResult.severity,
                riskScore = staticResult.riskScore,
                source = defaultSource,
                reasons = staticResult.reasons,
                detectedAtMillis = System.currentTimeMillis(),
                isSystemApp = isSystemApp
            )
        }

        return null
    }

    private fun recordRealtimeFinding(finding: ThreatFinding) {
        val current = _threatFindings.value.filterNot { it.id == finding.id }
        _threatFindings.value = (listOf(finding) + current).sortedByDescending { it.riskScore }
    }

    companion object {
        const val WHITELIST_TYPE_APP = "APP_PACKAGE"
        private const val MAX_SCAN_FILE_BYTES = 250L * 1024L * 1024L
        private val SCANNABLE_EXTENSIONS = setOf("apk", "apks", "xapk", "dex", "jar", "zip", "txt", "com", "bin")
    }
}
