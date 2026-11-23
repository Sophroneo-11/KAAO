package com.kaao.security.engine.network

import com.kaao.security.domain.model.WifiSecurityProtocol
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class WifiSecurityEvaluatorTest {

    private val evaluator = WifiSecurityEvaluator()

    @Test
    fun openWifiWithCaptivePortalAndRogueDnsOverridePenalizesScore() {
        val report = evaluator.evaluate(
            isConnectedToWifi = true,
            ssid = "CoffeeShop_Free",
            bssid = "aa:bb:cc:dd:ee:ff",
            protocol = WifiSecurityProtocol.OPEN,
            isCaptivePortal = true,
            isPrivateDnsActive = false,
            privateDnsHost = null,
            dnsServers = listOf("185.228.100.55"),
            rssiDbm = -68,
            linkSpeedMbps = 72,
            frequencyMhz = 2437,
            isMetered = false
        )

        assertTrue(report.hasSuspiciousDnsOverride)
        assertTrue(report.isCaptivePortal)
        assertEquals("2.4 GHz", report.frequencyBand)
        assertTrue("Expected unsafe Wi-Fi score <= 15, got ${report.safetyScore}", report.safetyScore <= 15)
    }

    @Test
    fun wpa3WithPrivateDnsAndStandardRouterDnsScores100() {
        val report = evaluator.evaluate(
            isConnectedToWifi = true,
            ssid = "SecureLab_5G",
            bssid = "11:22:33:44:55:66",
            protocol = WifiSecurityProtocol.WPA3,
            isCaptivePortal = false,
            isPrivateDnsActive = true,
            privateDnsHost = "one.one.one.one",
            dnsServers = listOf("192.168.1.1"),
            rssiDbm = -45,
            linkSpeedMbps = 866,
            frequencyMhz = 5180,
            isMetered = false
        )

        assertFalse(report.hasSuspiciousDnsOverride)
        assertEquals("5 GHz", report.frequencyBand)
        assertEquals(100, report.safetyScore)
    }
}
