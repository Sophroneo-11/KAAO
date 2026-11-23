package com.kaao.security.engine.network

import com.kaao.security.domain.model.WifiAuditReport
import com.kaao.security.domain.model.WifiSecurityProtocol
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Pure, deterministic evaluator for Wi-Fi security posture.
 * Evaluates encryption strength (Open/WEP/WPA/WPA2/WPA3), Captive Portal exposure,
 * Private DNS status, and non-standard/rogue DNS server overrides.
 */
@Singleton
class WifiSecurityEvaluator @Inject constructor() {

    fun evaluate(
        isConnectedToWifi: Boolean,
        ssid: String,
        bssid: String,
        protocol: WifiSecurityProtocol,
        isCaptivePortal: Boolean,
        isPrivateDnsActive: Boolean,
        privateDnsHost: String?,
        dnsServers: List<String>,
        rssiDbm: Int,
        linkSpeedMbps: Int,
        frequencyMhz: Int,
        isMetered: Boolean,
        nowMillis: Long = System.currentTimeMillis()
    ): WifiAuditReport {
        if (!isConnectedToWifi) {
            return WifiAuditReport(
                isConnectedToWifi = false,
                ssid = "Not connected to Wi-Fi",
                bssid = "--",
                protocol = WifiSecurityProtocol.UNKNOWN,
                safetyScore = 100,
                advisories = listOf("Connect to a Wi-Fi network to inspect encryption, captive portal, and DNS posture."),
                inspectedAtMillis = nowMillis
            )
        }

        var score = 100
        val advisories = mutableListOf<String>()

        when (protocol) {
            WifiSecurityProtocol.OPEN -> {
                score -= 55
                advisories.add("Unencrypted Open Wi-Fi: traffic can be passively sniffed on the local network. Enable Aegis DoH Shield immediately.")
            }

            WifiSecurityProtocol.WEP -> {
                score -= 50
                advisories.add("Broken WEP encryption detected: trivially cracked in minutes. Avoid banking or credentials on this network.")
            }

            WifiSecurityProtocol.WPA -> {
                score -= 30
                advisories.add("Legacy WPA-TKIP encryption is deprecated. Prefer WPA2 or WPA3.")
            }

            WifiSecurityProtocol.WPA2 -> {
                advisories.add("WPA2-PSK encryption active.")
            }

            WifiSecurityProtocol.WPA3 -> {
                advisories.add("Strong WPA3-SAE encryption active with forward secrecy.")
            }

            WifiSecurityProtocol.OWE -> {
                advisories.add("Enhanced Open (OWE) opportunistic encryption active.")
            }

            WifiSecurityProtocol.ENTERPRISE -> {
                advisories.add("802.1X Enterprise Wi-Fi authentication active.")
            }

            WifiSecurityProtocol.UNKNOWN -> {
                score -= 10
                advisories.add("Wi-Fi encryption type could not be verified without location/SSID visibility.")
            }
        }

        if (isCaptivePortal) {
            score -= 20
            advisories.add("Captive portal interception detected: network redirects HTTP/DNS until sign-in completes.")
        }

        val suspiciousDns = detectSuspiciousDnsOverride(dnsServers, isPrivateDnsActive)
        if (suspiciousDns) {
            score -= 20
            advisories.add("Unrecognized public/custom DNS server (${dnsServers.joinToString()}) detected without encrypted Private DNS.")
        } else if (!isPrivateDnsActive && protocol.isWeak) {
            score -= 10
            advisories.add("Encrypted Private DNS (DoT/DoH) is not enabled on an untrusted Wi-Fi network.")
        }

        if (isPrivateDnsActive) {
            advisories.add("Android Private DNS active${privateDnsHost?.let { " ($it)" } ?: ""}.")
        }

        val band = when {
            frequencyMhz in 2400..2500 -> "2.4 GHz"
            frequencyMhz in 4900..5900 -> "5 GHz"
            frequencyMhz >= 5925 -> "6 GHz"
            else -> "--"
        }

        return WifiAuditReport(
            isConnectedToWifi = true,
            ssid = ssid,
            bssid = bssid,
            protocol = protocol,
            isCaptivePortal = isCaptivePortal,
            isPrivateDnsActive = isPrivateDnsActive,
            privateDnsHost = privateDnsHost,
            dnsServers = dnsServers,
            hasSuspiciousDnsOverride = suspiciousDns,
            rssiDbm = rssiDbm,
            linkSpeedMbps = linkSpeedMbps,
            frequencyBand = band,
            isMetered = isMetered,
            safetyScore = score.coerceIn(0, 100),
            advisories = advisories,
            inspectedAtMillis = nowMillis
        )
    }

    internal fun detectSuspiciousDnsOverride(
        dnsServers: List<String>,
        isPrivateDnsActive: Boolean
    ): Boolean {
        if (isPrivateDnsActive || dnsServers.isEmpty()) return false
        return dnsServers.any { ip ->
            !isLocalRouterOrPrivateIp(ip) && ip !in TRUSTED_PUBLIC_RESOLVERS
        }
    }

    private fun isLocalRouterOrPrivateIp(ip: String): Boolean {
        return ip.startsWith("10.") ||
            ip.startsWith("192.168.") ||
            ip.startsWith("172.16.") ||
            ip.startsWith("172.17.") ||
            ip.startsWith("172.18.") ||
            ip.startsWith("172.19.") ||
            ip.startsWith("172.2") ||
            ip.startsWith("172.30.") ||
            ip.startsWith("172.31.") ||
            ip.startsWith("fe80:") ||
            ip.startsWith("fd") ||
            ip.startsWith("fc") ||
            ip == "127.0.0.1"
    }

    companion object {
        private val TRUSTED_PUBLIC_RESOLVERS = setOf(
            "1.1.1.1", "1.0.0.1",
            "8.8.8.8", "8.8.4.4",
            "9.9.9.9", "149.112.112.112",
            "208.67.222.222", "208.67.220.220",
            "2606:4700:4700::1111", "2606:4700:4700::1001",
            "2001:4860:4860::8888", "2001:4860:4860::8844",
            "2620:fe::fe", "2620:fe::9"
        )
    }
}
