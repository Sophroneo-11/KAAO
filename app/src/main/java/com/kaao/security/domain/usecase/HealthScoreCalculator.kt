package com.kaao.security.domain.usecase

import com.kaao.security.domain.model.HealthScoreComponent
import com.kaao.security.domain.model.HealthScoreReport
import com.kaao.security.domain.model.StalkerwareFinding
import com.kaao.security.domain.model.ThreatFinding
import com.kaao.security.domain.model.ThreatSeverity
import com.kaao.security.domain.model.WifiAuditReport
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Pure, transparent 0–100 Health Score calculator.
 * Weight distribution (total 100 pts):
 * - Antivirus & App Integrity: 35 pts
 * - Stalkerware Privilege Audit: 20 pts
 * - Web Shield & Real-Time Protection: 20 pts
 * - Wi-Fi Security Posture: 15 pts
 * - Storage Hygiene: 10 pts
 */
@Singleton
class HealthScoreCalculator @Inject constructor() {

    fun calculate(
        threatFindings: List<ThreatFinding>,
        stalkerwareFindings: List<StalkerwareFinding>,
        isDnsShieldActive: Boolean,
        isRealtimeShieldActive: Boolean,
        wifiAudit: WifiAuditReport,
        reclaimableBytes: Long,
        nowMillis: Long = System.currentTimeMillis()
    ): HealthScoreReport {
        // 1. Antivirus (35 pts)
        val avDeduction = threatFindings.sumOf { finding ->
            when (finding.severity) {
                ThreatSeverity.CRITICAL -> 35
                ThreatSeverity.HIGH -> 22
                ThreatSeverity.MEDIUM -> 12
                ThreatSeverity.LOW -> 5
                ThreatSeverity.SAFE -> 0
            }
        }
        val avPoints = (35 - avDeduction).coerceIn(0, 35)
        val avSeverity = when {
            threatFindings.any { it.severity == ThreatSeverity.CRITICAL } -> ThreatSeverity.CRITICAL
            threatFindings.any { it.severity == ThreatSeverity.HIGH } -> ThreatSeverity.HIGH
            threatFindings.isNotEmpty() -> ThreatSeverity.MEDIUM
            else -> ThreatSeverity.SAFE
        }
        val avDetail = if (threatFindings.isEmpty()) {
            "0 active malware or heuristic threats"
        } else {
            "${threatFindings.size} threat(s) require guided remediation"
        }

        // 2. Stalkerware Privileges (20 pts)
        val stalkerDeduction = stalkerwareFindings.sumOf { finding ->
            when (finding.severity) {
                ThreatSeverity.CRITICAL -> 20
                ThreatSeverity.HIGH -> 14
                ThreatSeverity.MEDIUM -> 8
                ThreatSeverity.LOW -> 3
                ThreatSeverity.SAFE -> 0
            }
        }
        val stalkerPoints = (20 - stalkerDeduction).coerceIn(0, 20)
        val stalkerSeverity = stalkerwareFindings.maxByOrNull { it.severity.weight }?.severity
            ?: ThreatSeverity.SAFE
        val stalkerDetail = if (stalkerwareFindings.isEmpty()) {
            "No suspicious privileged apps detected"
        } else {
            "${stalkerwareFindings.size} app(s) hold elevated surveillance privileges"
        }

        // 3. Web Shield & Real-Time Protection (20 pts)
        val shieldPoints = (if (isDnsShieldActive) 12 else 0) + (if (isRealtimeShieldActive) 8 else 0)
        val shieldSeverity = when {
            isDnsShieldActive && isRealtimeShieldActive -> ThreatSeverity.SAFE
            isDnsShieldActive || isRealtimeShieldActive -> ThreatSeverity.LOW
            else -> ThreatSeverity.MEDIUM
        }
        val shieldDetail = when {
            isDnsShieldActive && isRealtimeShieldActive -> "Aegis DoH Shield & Real-Time Monitor active"
            isDnsShieldActive -> "Aegis DoH Shield active; Real-Time Monitor off"
            isRealtimeShieldActive -> "Real-Time Monitor active; Aegis DoH Shield off"
            else -> "Enable Aegis DoH Shield & Real-Time protection (+20 pts)"
        }

        // 4. Wi-Fi Security Posture (15 pts)
        val wifiPoints = if (!wifiAudit.isConnectedToWifi) {
            15
        } else {
            ((wifiAudit.safetyScore / 100.0) * 15.0).toInt().coerceIn(0, 15)
        }
        val wifiSeverity = when {
            !wifiAudit.isConnectedToWifi -> ThreatSeverity.SAFE
            wifiAudit.safetyScore < 50 -> ThreatSeverity.HIGH
            wifiAudit.safetyScore < 80 -> ThreatSeverity.MEDIUM
            else -> ThreatSeverity.SAFE
        }
        val wifiDetail = if (!wifiAudit.isConnectedToWifi) {
            "No risky Wi-Fi network attached"
        } else {
            "${wifiAudit.ssid} • ${wifiAudit.protocol.label} (${wifiAudit.safetyScore}/100)"
        }

        // 5. Storage Hygiene (10 pts)
        val reclaimableMb = reclaimableBytes / (1024L * 1024L)
        val storagePoints = when {
            reclaimableMb < 100L -> 10
            reclaimableMb < 500L -> 8
            reclaimableMb < 1500L -> 5
            else -> 2
        }
        val storageSeverity = when {
            storagePoints >= 8 -> ThreatSeverity.SAFE
            storagePoints >= 5 -> ThreatSeverity.LOW
            else -> ThreatSeverity.MEDIUM
        }
        val storageDetail = if (reclaimableMb <= 0L) {
            "Storage hygiene optimal"
        } else {
            "$reclaimableMb MB of duplicates, APKs, or temp files reclaimable"
        }

        val components = listOf(
            HealthScoreComponent("av", "Antivirus & APK Integrity", avPoints, 35, avDetail, avSeverity),
            HealthScoreComponent("stalker", "Stalkerware Privilege Audit", stalkerPoints, 20, stalkerDetail, stalkerSeverity),
            HealthScoreComponent("shield", "Aegis DNS & Real-Time Shield", shieldPoints, 20, shieldDetail, shieldSeverity),
            HealthScoreComponent("wifi", "Wi-Fi Network Safety", wifiPoints, 15, wifiDetail, wifiSeverity),
            HealthScoreComponent("storage", "Storage Hygiene", storagePoints, 10, storageDetail, storageSeverity)
        )

        val totalScore = components.sumOf { it.earnedPoints }.coerceIn(0, 100)
        val (grade, overallSeverity) = when {
            totalScore >= 85 -> "Hardened" to ThreatSeverity.SAFE
            totalScore >= 70 -> "Protected" to ThreatSeverity.LOW
            totalScore >= 50 -> "Attention Needed" to ThreatSeverity.MEDIUM
            totalScore >= 30 -> "At Risk" to ThreatSeverity.HIGH
            else -> "Critical Exposure" to ThreatSeverity.CRITICAL
        }

        return HealthScoreReport(
            totalScore = totalScore,
            gradeLabel = grade,
            severity = overallSeverity,
            components = components,
            computedAtMillis = nowMillis
        )
    }
}
