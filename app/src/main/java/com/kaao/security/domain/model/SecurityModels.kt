package com.kaao.security.domain.model

import android.net.Uri

enum class ThreatSeverity(val label: String, val weight: Int) {
    SAFE("Safe", 0),
    LOW("Low", 1),
    MEDIUM("Medium", 2),
    HIGH("High", 3),
    CRITICAL("Critical", 4)
}

enum class ThreatSource(val label: String) {
    BLOOM_SIGNATURE_VAULT("Local SHA-256 Vault"),
    STATIC_APK_HEURISTIC("Static APK / DEX Heuristics"),
    CLOUD_MALWAREBAZAAR("MalwareBazaar Hash Intel"),
    CLOUD_VIRUSTOTAL("VirusTotal Hash Intel"),
    REALTIME_INSTALL_SHIELD("Real-Time Install Shield"),
    DOWNLOADS_OBSERVER("Downloads Monitor")
}

data class ThreatFinding(
    val id: String,
    val title: String,
    val packageName: String?,
    val filePath: String?,
    val sha256: String,
    val family: String,
    val severity: ThreatSeverity,
    val riskScore: Int,
    val source: ThreatSource,
    val reasons: List<String>,
    val detectedAtMillis: Long,
    val isSystemApp: Boolean = false
)

enum class StalkerwarePrivilege(val label: String, val description: String, val riskPoints: Int) {
    DEVICE_ADMIN(
        "Device Administrator",
        "Can lock screen, enforce policies, and block standard uninstallation.",
        35
    ),
    ACCESSIBILITY_SERVICE(
        "Accessibility Service",
        "Can observe all screen content, keystrokes, and perform taps automatically.",
        40
    ),
    NOTIFICATION_LISTENER(
        "Notification Listener",
        "Can read incoming 2FA codes, SMS previews, and private chat messages.",
        25
    ),
    USAGE_ACCESS(
        "Usage Access",
        "Can track foreground app history and active usage sessions.",
        15
    )
}

data class StalkerwareFinding(
    val packageName: String,
    val appName: String,
    val privileges: List<StalkerwarePrivilege>,
    val riskScore: Int,
    val severity: ThreatSeverity,
    val installerSource: String,
    val hasLauncherIcon: Boolean,
    val advisory: String
)

data class AntivirusScanProgress(
    val isScanning: Boolean = false,
    val currentTarget: String = "",
    val scannedCount: Int = 0,
    val totalCount: Int = 0,
    val stage: String = "Idle"
)

data class CloudReputationResult(
    val sha256: String,
    val provider: String,
    val isMalicious: Boolean,
    val family: String?,
    val positives: Int = 0,
    val totalEngines: Int = 0,
    val checkedAtMillis: Long = System.currentTimeMillis()
)

enum class DohProvider(val id: String, val displayName: String, val endpointUrl: String, val hostname: String) {
    CLOUDFLARE(
        id = "cloudflare",
        displayName = "Cloudflare 1.1.1.1 (DoH)",
        endpointUrl = "https://cloudflare-dns.com/dns-query",
        hostname = "cloudflare-dns.com"
    ),
    QUAD9(
        id = "quad9",
        displayName = "Quad9 Malware-Blocking (DoH)",
        endpointUrl = "https://dns.quad9.net/dns-query",
        hostname = "dns.quad9.net"
    )
}

enum class DnsRuleCategory(val label: String) {
    PHISHING("Phishing"),
    MALWARE("Malware"),
    ADWARE("Adware & Trackers"),
    CUSTOM_BLOCK("Custom Block"),
    CUSTOM_ALLOW("Custom Allow")
}

data class DnsQueryEvent(
    val id: Long = 0L,
    val domain: String,
    val queryType: String,
    val blocked: Boolean,
    val category: String,
    val latencyMs: Long,
    val timestampMillis: Long
)

enum class AegisVpnMode(val label: String) {
    OFF("Disconnected"),
    DNS_SHIELD("Split-Route DoH Shield"),
    GAME_FIREWALL("Game Mode Firewall")
}

data class AegisVpnState(
    val mode: AegisVpnMode = AegisVpnMode.OFF,
    val activeGamePackage: String? = null,
    val activeGameName: String? = null,
    val dohProvider: DohProvider = DohProvider.CLOUDFLARE,
    val queriesProcessed: Long = 0L,
    val queriesBlocked: Long = 0L,
    val lastError: String? = null
)

enum class WifiSecurityProtocol(val label: String, val isWeak: Boolean) {
    OPEN("Open (Unencrypted)", true),
    WEP("WEP (Broken Legacy)", true),
    WPA("WPA (Deprecated)", true),
    WPA2("WPA2-PSK", false),
    WPA3("WPA3-SAE", false),
    OWE("Enhanced Open (OWE)", false),
    ENTERPRISE("WPA2/WPA3 Enterprise", false),
    UNKNOWN("Unknown / Disconnected", false)
}

data class WifiAuditReport(
    val isConnectedToWifi: Boolean = false,
    val ssid: String = "Not Connected",
    val bssid: String = "--",
    val protocol: WifiSecurityProtocol = WifiSecurityProtocol.UNKNOWN,
    val isCaptivePortal: Boolean = false,
    val isPrivateDnsActive: Boolean = false,
    val privateDnsHost: String? = null,
    val dnsServers: List<String> = emptyList(),
    val hasSuspiciousDnsOverride: Boolean = false,
    val rssiDbm: Int = 0,
    val linkSpeedMbps: Int = 0,
    val frequencyBand: String = "--",
    val isMetered: Boolean = false,
    val safetyScore: Int = 100,
    val advisories: List<String> = emptyList(),
    val inspectedAtMillis: Long = 0L
)

enum class CleanerCategory(val label: String, val description: String) {
    DUPLICATES("Duplicates", "Byte-verified identical files (3-stage SHA-256)"),
    LEFTOVER_APKS("Leftover APKs", "Downloaded installer packages no longer needed"),
    TEMP_AND_LOGS("Temp & Logs", "Residual .tmp, .log, .bak, and crash dump files"),
    EMPTY_FOLDERS("Empty Folders", "Directories containing zero files"),
    LARGE_AND_MESSAGING("Large & Messaging", "Large files (25+ MB) and messaging media")
}

data class CleanableItem(
    val id: String,
    val name: String,
    val path: String,
    val sizeBytes: Long,
    val lastModifiedMillis: Long,
    val category: CleanerCategory,
    val contentUri: Uri? = null,
    val duplicateGroupId: String? = null,
    val isSuggestedOriginal: Boolean = false,
    val detailBadge: String? = null,
    val isSelected: Boolean = false
)

data class AppStorageInfo(
    val packageName: String,
    val appName: String,
    val appBytes: Long,
    val dataBytes: Long,
    val cacheBytes: Long,
    val totalBytes: Long,
    val isExactStats: Boolean
)

data class CleanerScanResult(
    val items: List<CleanableItem> = emptyList(),
    val appStorage: List<AppStorageInfo> = emptyList(),
    val totalStorageBytes: Long = 0L,
    val availableStorageBytes: Long = 0L,
    val reclaimableBytes: Long = 0L,
    val scannedFilesCount: Int = 0,
    val scannedAtMillis: Long = 0L
)

data class DeletionResult(
    val deletedCount: Int,
    val reclaimedBytes: Long,
    val skippedWhitelistedCount: Int,
    val failedCount: Int,
    val pendingMediaStoreUris: List<Uri> = emptyList()
)

data class GameApp(
    val packageName: String,
    val appName: String,
    val isAutoDetected: Boolean,
    val versionName: String
)

data class DeviceTelemetry(
    val thermalStatusLabel: String = "Nominal",
    val thermalSeverity: ThreatSeverity = ThreatSeverity.SAFE,
    val thermalHeadroom: Float? = null,
    val batteryPercent: Int = 100,
    val batteryTempCelsius: Float = 28.0f,
    val isCharging: Boolean = false,
    val availableRamBytes: Long = 0L,
    val totalRamBytes: Long = 0L,
    val ramUsagePercent: Int = 0,
    val tcpPingMs: Long? = null,
    val updatedAtMillis: Long = 0L
)

data class GameBoostConfig(
    val enableBackgroundFirewall: Boolean = true,
    val enableDndSilence: Boolean = true,
    val lockBrightness: Boolean = false,
    val targetBrightnessPercent: Int = 75,
    val pauseAutoSync: Boolean = true,
    val showFloatingHud: Boolean = true
)

data class GameSessionState(
    val isActive: Boolean = false,
    val activePackage: String? = null,
    val activeGameName: String? = null,
    val startedAtMillis: Long = 0L,
    val appliedFirewall: Boolean = false,
    val appliedDnd: Boolean = false,
    val appliedBrightness: Boolean = false,
    val appliedSyncPause: Boolean = false,
    val appliedHud: Boolean = false
)

data class HealthScoreComponent(
    val id: String,
    val title: String,
    val earnedPoints: Int,
    val maxPoints: Int,
    val statusDetail: String,
    val severity: ThreatSeverity
)

data class HealthScoreReport(
    val totalScore: Int,
    val gradeLabel: String,
    val severity: ThreatSeverity,
    val components: List<HealthScoreComponent>,
    val computedAtMillis: Long
)

data class SmartScanState(
    val isRunning: Boolean = false,
    val antivirusDone: Boolean = false,
    val stalkerwareDone: Boolean = false,
    val wifiDone: Boolean = false,
    val storageDone: Boolean = false,
    val summaryMessage: String = "Ready to run a concurrent full-device security check",
    val lastCompletedMillis: Long = 0L
)
