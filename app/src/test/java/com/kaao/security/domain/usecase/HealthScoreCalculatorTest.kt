package com.kaao.security.domain.usecase

import com.kaao.security.domain.model.StalkerwareFinding
import com.kaao.security.domain.model.StalkerwarePrivilege
import com.kaao.security.domain.model.ThreatFinding
import com.kaao.security.domain.model.ThreatSeverity
import com.kaao.security.domain.model.ThreatSource
import com.kaao.security.domain.model.WifiAuditReport
import com.kaao.security.domain.model.WifiSecurityProtocol
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class HealthScoreCalculatorTest {

    private val calculator = HealthScoreCalculator()

    @Test
    fun hardenedDeviceWithAllShieldsAndCleanWifiScores100() {
        val report = calculator.calculate(
            threatFindings = emptyList(),
            stalkerwareFindings = emptyList(),
            isDnsShieldActive = true,
            isRealtimeShieldActive = true,
            wifiAudit = WifiAuditReport(
                isConnectedToWifi = true,
                ssid = "Home5G",
                protocol = WifiSecurityProtocol.WPA3,
                safetyScore = 100
            ),
            reclaimableBytes = 10L * 1024L * 1024L
        )
        assertEquals(100, report.totalScore)
        assertEquals("Hardened", report.gradeLabel)
        assertEquals(ThreatSeverity.SAFE, report.severity)
        assertEquals(5, report.components.size)
        assertEquals(100, report.components.sumOf { it.maxPoints })
    }

    @Test
    fun criticalThreatStalkerwareAndOpenWifiLowerScoreTransparently() {
        val threat = ThreatFinding(
            id = "t1",
            title = "Trojan",
            packageName = "com.evil.banker",
            filePath = null,
            sha256 = "a".repeat(64),
            family = "Android.Banker",
            severity = ThreatSeverity.CRITICAL,
            riskScore = 95,
            source = ThreatSource.BLOOM_SIGNATURE_VAULT,
            reasons = listOf("Vault match"),
            detectedAtMillis = 1L
        )
        val stalker = StalkerwareFinding(
            packageName = "com.spy.hidden",
            appName = "System Update",
            privileges = listOf(StalkerwarePrivilege.ACCESSIBILITY_SERVICE, StalkerwarePrivilege.DEVICE_ADMIN),
            riskScore = 90,
            severity = ThreatSeverity.CRITICAL,
            installerSource = "Sideloaded / Unknown",
            hasLauncherIcon = false,
            advisory = "Stalkerware"
        )
        val report = calculator.calculate(
            threatFindings = listOf(threat),
            stalkerwareFindings = listOf(stalker),
            isDnsShieldActive = false,
            isRealtimeShieldActive = false,
            wifiAudit = WifiAuditReport(
                isConnectedToWifi = true,
                ssid = "AirportFreeWifi",
                protocol = WifiSecurityProtocol.OPEN,
                safetyScore = 25
            ),
            reclaimableBytes = 2000L * 1024L * 1024L
        )

        // AV=0, Stalker=0, Shield=0, Wi-Fi=3, Storage=2 -> 5
        assertEquals(5, report.totalScore)
        assertEquals(ThreatSeverity.CRITICAL, report.severity)
        assertTrue(report.components.first { it.id == "av" }.earnedPoints == 0)
        assertTrue(report.components.first { it.id == "stalker" }.earnedPoints == 0)
    }
}
