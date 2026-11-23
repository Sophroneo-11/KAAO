package com.kaao.security.engine.network

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.wifi.WifiInfo
import android.net.wifi.WifiManager
import android.os.Build
import com.kaao.security.domain.model.WifiAuditReport
import com.kaao.security.domain.model.WifiSecurityProtocol
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class WifiSecurityInspector @Inject constructor(
    @ApplicationContext private val context: Context,
    private val evaluator: WifiSecurityEvaluator
) {
    private val _report = MutableStateFlow(WifiAuditReport())
    val report: StateFlow<WifiAuditReport> = _report.asStateFlow()

    suspend fun inspectCurrentWifi(): WifiAuditReport = withContext(Dispatchers.IO) {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
        val activeNetwork = cm?.activeNetwork
        val capabilities = activeNetwork?.let { cm.getNetworkCapabilities(it) }
        val isWifi = capabilities?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true

        if (!isWifi || activeNetwork == null) {
            val disconnected = evaluator.evaluate(
                isConnectedToWifi = false,
                ssid = "",
                bssid = "",
                protocol = WifiSecurityProtocol.UNKNOWN,
                isCaptivePortal = false,
                isPrivateDnsActive = false,
                privateDnsHost = null,
                dnsServers = emptyList(),
                rssiDbm = 0,
                linkSpeedMbps = 0,
                frequencyMhz = 0,
                isMetered = false
            )
            _report.value = disconnected
            return@withContext disconnected
        }

        val linkProps = cm.getLinkProperties(activeNetwork)
        val dnsServers = linkProps?.dnsServers?.mapNotNull { it.hostAddress }.orEmpty()
        val isPrivateDns = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            linkProps?.isPrivateDnsActive == true
        } else {
            false
        }
        val privateDnsHost = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            linkProps?.privateDnsServerName
        } else {
            null
        }
        val isCaptivePortal = capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_CAPTIVE_PORTAL)
        val isMetered = !capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED)

        val wifiInfo = extractWifiInfo(capabilities)
        val rawSsid = runCatching { wifiInfo?.ssid }.getOrNull().orEmpty()
            .removeSurrounding("\"")
            .takeIf { it.isNotBlank() && it != "<unknown ssid>" }
            ?: "Connected Wi-Fi"
        val bssid = runCatching { wifiInfo?.bssid }.getOrNull()
            ?.takeIf { it != "02:00:00:00:00:00" }
            ?: "Protected"
        val rssi = runCatching { wifiInfo?.rssi }.getOrDefault(-55) ?: -55
        val linkSpeed = runCatching { wifiInfo?.linkSpeed }.getOrDefault(0) ?: 0
        val frequency = runCatching { wifiInfo?.frequency }.getOrDefault(0) ?: 0
        val protocol = resolveSecurityProtocol(wifiInfo)

        val evaluated = evaluator.evaluate(
            isConnectedToWifi = true,
            ssid = rawSsid,
            bssid = bssid,
            protocol = protocol,
            isCaptivePortal = isCaptivePortal,
            isPrivateDnsActive = isPrivateDns,
            privateDnsHost = privateDnsHost,
            dnsServers = dnsServers,
            rssiDbm = rssi,
            linkSpeedMbps = linkSpeed,
            frequencyMhz = frequency,
            isMetered = isMetered
        )
        _report.value = evaluated
        evaluated
    }

    private fun extractWifiInfo(capabilities: NetworkCapabilities): WifiInfo? {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            val transportInfo = capabilities.transportInfo
            if (transportInfo is WifiInfo) return transportInfo
        }
        val wifiManager = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager
        @Suppress("DEPRECATION")
        return runCatching { wifiManager?.connectionInfo }.getOrNull()
    }

    private fun resolveSecurityProtocol(wifiInfo: WifiInfo?): WifiSecurityProtocol {
        if (wifiInfo == null) return WifiSecurityProtocol.UNKNOWN
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            return when (wifiInfo.currentSecurityType) {
                WifiInfo.SECURITY_TYPE_OPEN -> WifiSecurityProtocol.OPEN
                WifiInfo.SECURITY_TYPE_WEP -> WifiSecurityProtocol.WEP
                WifiInfo.SECURITY_TYPE_PSK -> WifiSecurityProtocol.WPA2
                WifiInfo.SECURITY_TYPE_SAE -> WifiSecurityProtocol.WPA3
                WifiInfo.SECURITY_TYPE_OWE -> WifiSecurityProtocol.OWE
                WifiInfo.SECURITY_TYPE_EAP,
                WifiInfo.SECURITY_TYPE_EAP_WPA3_ENTERPRISE,
                WifiInfo.SECURITY_TYPE_EAP_WPA3_ENTERPRISE_192_BIT -> WifiSecurityProtocol.ENTERPRISE
                WifiInfo.SECURITY_TYPE_WAPI_PSK,
                WifiInfo.SECURITY_TYPE_WAPI_CERT -> WifiSecurityProtocol.WPA2
                else -> WifiSecurityProtocol.UNKNOWN
            }
        }
        return WifiSecurityProtocol.WPA2
    }
}
