package com.kaao.security.engine.antivirus

import com.kaao.security.core.crypto.HashUtils
import com.kaao.security.domain.model.ThreatSeverity
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileInputStream
import java.io.InputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipInputStream
import javax.inject.Inject
import javax.inject.Singleton
import kotlin.math.ln

data class StaticApkAnalysisResult(
    val sha256: String,
    val riskScore: Int,
    val severity: ThreatSeverity,
    val detectedFamily: String,
    val reasons: List<String>,
    val manifestPermissions: Set<String>,
    val dexCount: Int,
    val hiddenAssetCount: Int
)

/**
 * Static APK Manifest, DEX, and Hidden-Asset Heuristic Analyzer.
 * Inspects AndroidManifest.xml toxic permission combinations, DEX reflection/dropper APIs & packing entropy,
 * and hidden nested APK/DEX/ELF binaries masquerading inside assets/ or res/raw/.
 */
@Singleton
class StaticApkAnalyzer @Inject constructor() {

    fun analyzeApk(apkFile: File): StaticApkAnalysisResult? {
        if (!apkFile.exists() || !apkFile.isFile || !apkFile.canRead()) return null
        val sha256 = HashUtils.sha256FileHex(apkFile) ?: return null

        var riskScore = 0
        val reasons = mutableListOf<String>()
        val foundPermissions = mutableSetOf<String>()
        var dexCount = 0
        var hiddenAssetCount = 0
        var hasDynamicLoader = false
        var hasSmsAbuseApi = false
        var hasRootExecApi = false
        var hasAccessibilityActionApi = false
        var hasHighEntropyDex = false

        runCatching {
            ZipInputStream(FileInputStream(apkFile).buffered()).use { zis ->
                var entry: ZipEntry? = zis.nextEntry
                var entriesScanned = 0
                while (entry != null && entriesScanned < MAX_ZIP_ENTRIES) {
                    entriesScanned++
                    val name = entry.name
                    if (!entry.isDirectory) {
                        when {
                            name == "AndroidManifest.xml" -> {
                                val manifestBytes = readCapped(zis, MAX_MANIFEST_BYTES)
                                val strings = BinaryAxmlScanner.extractStrings(manifestBytes)
                                strings.filterTo(foundPermissions) {
                                    it.startsWith("android.permission.") ||
                                        it == "android.permission.BIND_ACCESSIBILITY_SERVICE" ||
                                        it == "android.permission.BIND_DEVICE_ADMIN" ||
                                        it == "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE"
                                }
                            }

                            name.matches(DEX_ENTRY_REGEX) -> {
                                dexCount++
                                val dexBytes = readCapped(zis, MAX_DEX_SCAN_BYTES)
                                if (dexBytes.size >= 8 && !hasValidDexMagic(dexBytes)) {
                                    riskScore += 20
                                    reasons.add("Malformed or obfuscated DEX header in $name")
                                }
                                val entropy = shannonEntropy(dexBytes)
                                if (dexBytes.size >= 16_384 && entropy >= 7.55) {
                                    hasHighEntropyDex = true
                                }
                                val dexAscii = String(dexBytes, Charsets.ISO_8859_1)
                                if (dexAscii.contains("DexClassLoader") ||
                                    dexAscii.contains("InMemoryDexClassLoader") ||
                                    dexAscii.contains("PathClassLoader")
                                ) {
                                    hasDynamicLoader = true
                                }
                                if (dexAscii.contains("SmsManager") &&
                                    (dexAscii.contains("sendTextMessage") || dexAscii.contains("sendMultipartTextMessage"))
                                ) {
                                    hasSmsAbuseApi = true
                                }
                                if (dexAscii.contains("Runtime;->exec") ||
                                    dexAscii.contains("/system/bin/su") ||
                                    dexAscii.contains("/system/xbin/su")
                                ) {
                                    hasRootExecApi = true
                                }
                                if (dexAscii.contains("performGlobalAction") &&
                                    dexAscii.contains("AccessibilityNodeInfo")
                                ) {
                                    hasAccessibilityActionApi = true
                                }
                            }

                            name.startsWith("assets/") || name.startsWith("res/raw/") -> {
                                val lower = name.lowercase()
                                val header = readCapped(zis, 16)
                                val isExplicitHiddenCode = lower.endsWith(".apk") ||
                                    lower.endsWith(".dex") ||
                                    lower.endsWith(".jar")
                                val isMasqueradingMedia = (lower.endsWith(".png") ||
                                    lower.endsWith(".jpg") ||
                                    lower.endsWith(".jpeg") ||
                                    lower.endsWith(".mp3") ||
                                    lower.endsWith(".ogg") ||
                                    lower.endsWith(".dat") ||
                                    lower.endsWith(".bin") ||
                                    lower.endsWith(".ttf")) &&
                                    (hasValidDexMagic(header) || hasElfMagic(header) || hasZipMagic(header))

                                if (isExplicitHiddenCode) {
                                    hiddenAssetCount++
                                    riskScore += 28
                                    reasons.add("Embedded executable payload in asset: $name")
                                } else if (isMasqueradingMedia) {
                                    hiddenAssetCount++
                                    riskScore += 35
                                    reasons.add("Hidden DEX/ELF/APK binary masquerading as media/data: $name")
                                }
                            }
                        }
                    }
                    zis.closeEntry()
                    entry = zis.nextEntry
                }
            }
        }

        // Evaluate toxic AndroidManifest permission combinations
        val hasAccessibility = foundPermissions.contains("android.permission.BIND_ACCESSIBILITY_SERVICE")
        val hasDeviceAdmin = foundPermissions.contains("android.permission.BIND_DEVICE_ADMIN")
        val hasOverlay = foundPermissions.contains("android.permission.SYSTEM_ALERT_WINDOW")
        val hasSms = foundPermissions.contains("android.permission.READ_SMS") ||
            foundPermissions.contains("android.permission.RECEIVE_SMS") ||
            foundPermissions.contains("android.permission.SEND_SMS")
        val hasInstallPkgs = foundPermissions.contains("android.permission.REQUEST_INSTALL_PACKAGES")
        val hasBoot = foundPermissions.contains("android.permission.RECEIVE_BOOT_COMPLETED")
        val hasMicAndLocation = foundPermissions.contains("android.permission.RECORD_AUDIO") &&
            foundPermissions.contains("android.permission.ACCESS_FINE_LOCATION")

        if (hasAccessibility && hasOverlay) {
            riskScore += 32
            reasons.add("High-risk overlay + Accessibility combination (banking/clickjacking vector)")
        }
        if (hasAccessibility && hasSms) {
            riskScore += 30
            reasons.add("Accessibility combined with SMS access (2FA interception pattern)")
        }
        if (hasInstallPkgs && hasSms) {
            riskScore += 24
            reasons.add("Silent dropper pattern: APK install permission combined with SMS access")
        }
        if (hasDeviceAdmin && hasBoot && hasSms) {
            riskScore += 28
            reasons.add("Persistent surveillance pattern: Device Admin + Boot + SMS")
        }
        if (hasMicAndLocation && hasBoot && hasAccessibility) {
            riskScore += 26
            reasons.add("Stalkerware profile: Accessibility + Microphone + GPS + Boot persistence")
        }

        // DEX behavioral heuristic combinations
        if (hasDynamicLoader && (hiddenAssetCount > 0 || hasInstallPkgs || hasAccessibility)) {
            riskScore += 25
            reasons.add("Dynamic DEX/code loading paired with elevated privileges or hidden payload")
        }
        if (hasSmsAbuseApi && hasSms) {
            riskScore += 22
            reasons.add("DEX invokes SmsManager.sendTextMessage with SMS permission")
        }
        if (hasRootExecApi && (hasDynamicLoader || hasAccessibility)) {
            riskScore += 18
            reasons.add("Shell/su execution markers detected in DEX bytecode")
        }
        if (hasAccessibilityActionApi && hasOverlay) {
            riskScore += 20
            reasons.add("Automated Accessibility gesture injection paired with overlay permission")
        }
        if (hasHighEntropyDex) {
            riskScore += 15
            reasons.add("High Shannon entropy DEX detected (possible packer or encrypted payload)")
        }

        val clampedScore = riskScore.coerceIn(0, 100)
        val severity = when {
            clampedScore >= 75 -> ThreatSeverity.CRITICAL
            clampedScore >= 55 -> ThreatSeverity.HIGH
            clampedScore >= 35 -> ThreatSeverity.MEDIUM
            clampedScore >= 20 -> ThreatSeverity.LOW
            else -> ThreatSeverity.SAFE
        }

        val family = when {
            hiddenAssetCount > 0 && hasDynamicLoader -> "Heuristic.Android.Dropper"
            hasAccessibility && hasOverlay -> "Heuristic.Android.BankerOverlay"
            hasAccessibility && hasSms -> "Heuristic.Android.SpywareSMS"
            hasDeviceAdmin && hasBoot -> "Heuristic.Android.Stalkerware"
            clampedScore >= 35 -> "Heuristic.Android.Suspicious"
            else -> "Clean"
        }

        return StaticApkAnalysisResult(
            sha256 = sha256,
            riskScore = clampedScore,
            severity = severity,
            detectedFamily = family,
            reasons = reasons,
            manifestPermissions = foundPermissions,
            dexCount = dexCount,
            hiddenAssetCount = hiddenAssetCount
        )
    }

    internal fun shannonEntropy(bytes: ByteArray): Double {
        if (bytes.isEmpty()) return 0.0
        val counts = IntArray(256)
        for (b in bytes) {
            counts[b.toInt() and 0xFF]++
        }
        val total = bytes.size.toDouble()
        var entropy = 0.0
        for (count in counts) {
            if (count > 0) {
                val p = count / total
                entropy -= p * (ln(p) / LN2)
            }
        }
        return entropy
    }

    private fun readCapped(input: InputStream, maxBytes: Int): ByteArray {
        val out = ByteArrayOutputStream()
        val buf = ByteArray(8192)
        var remaining = maxBytes
        while (remaining > 0) {
            val read = input.read(buf, 0, minOf(buf.size, remaining))
            if (read <= 0) break
            out.write(buf, 0, read)
            remaining -= read
        }
        return out.toByteArray()
    }

    private fun hasValidDexMagic(bytes: ByteArray): Boolean =
        bytes.size >= 8 &&
            bytes[0] == 0x64.toByte() && // d
            bytes[1] == 0x65.toByte() && // e
            bytes[2] == 0x78.toByte() && // x
            bytes[3] == 0x0A.toByte()    // \n

    private fun hasElfMagic(bytes: ByteArray): Boolean =
        bytes.size >= 4 &&
            bytes[0] == 0x7F.toByte() &&
            bytes[1] == 0x45.toByte() && // E
            bytes[2] == 0x4C.toByte() && // L
            bytes[3] == 0x46.toByte()    // F

    private fun hasZipMagic(bytes: ByteArray): Boolean =
        bytes.size >= 4 &&
            bytes[0] == 0x50.toByte() && // P
            bytes[1] == 0x4B.toByte() && // K
            bytes[2] == 0x03.toByte() &&
            bytes[3] == 0x04.toByte()

    companion object {
        private val DEX_ENTRY_REGEX = Regex("^classes\\d*\\.dex$")
        private const val MAX_ZIP_ENTRIES = 1500
        private const val MAX_MANIFEST_BYTES = 512 * 1024
        private const val MAX_DEX_SCAN_BYTES = 2 * 1024 * 1024
        private const val LN2 = 0.6931471805599453
    }
}
