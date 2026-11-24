package com.kaao.security.ui.webshield

import android.content.Intent
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.kaao.security.core.permission.PermissionManager
import com.kaao.security.data.local.db.DnsBlockRuleEntity
import com.kaao.security.data.local.prefs.KaaoPreferencesRepository
import com.kaao.security.data.local.prefs.KaaoSettings
import com.kaao.security.domain.model.AegisVpnMode
import com.kaao.security.domain.model.AegisVpnState
import com.kaao.security.domain.model.DnsQueryEvent
import com.kaao.security.domain.model.DohProvider
import com.kaao.security.domain.model.WifiAuditReport
import com.kaao.security.engine.network.AegisVpnController
import com.kaao.security.engine.network.WifiSecurityInspector
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import javax.inject.Inject

data class WebShieldUiState(
    val vpnState: AegisVpnState = AegisVpnState(),
    val settings: KaaoSettings = KaaoSettings(),
    val wifiAudit: WifiAuditReport = WifiAuditReport(),
    val recentQueries: List<DnsQueryEvent> = emptyList(),
    val totalBlocked: Long = 0L,
    val totalRuleCount: Int = 0,
    val customRules: List<DnsBlockRuleEntity> = emptyList(),
    val ruleFeedback: String? = null
)

@HiltViewModel
class WebShieldViewModel @Inject constructor(
    private val vpnController: AegisVpnController,
    private val wifiSecurityInspector: WifiSecurityInspector,
    private val prefs: KaaoPreferencesRepository,
    private val permissionManager: PermissionManager
) : ViewModel() {

    private val ruleFeedbackFlow = MutableStateFlow<String?>(null)

    private val primaryFlow = combine(
        vpnController.vpnState,
        prefs.settingsFlow,
        wifiSecurityInspector.report
    ) { vpn, settings, wifi ->
        Triple(vpn, settings, wifi)
    }

    private val rulesAndLogsFlow = combine(
        vpnController.recentQueriesFlow,
        vpnController.totalBlockedFlow,
        vpnController.customRulesFlow,
        ruleFeedbackFlow
    ) { queries, blockedCount, allRules, feedback ->
        RulesAndLogs(queries, blockedCount, allRules, feedback)
    }

    private data class RulesAndLogs(
        val queries: List<DnsQueryEvent>,
        val blockedCount: Long,
        val allRules: List<DnsBlockRuleEntity>,
        val feedback: String?
    )

    val uiState: StateFlow<WebShieldUiState> = combine(
        primaryFlow,
        rulesAndLogsFlow
    ) { (vpn, settings, wifi), rl ->
        WebShieldUiState(
            vpnState = vpn,
            settings = settings,
            wifiAudit = wifi,
            recentQueries = rl.queries,
            totalBlocked = rl.blockedCount,
            totalRuleCount = rl.allRules.size,
            customRules = rl.allRules.filter { it.isUserCustom },
            ruleFeedback = rl.feedback
        )
    }.stateIn(
        scope = viewModelScope,
        started = SharingStarted.WhileSubscribed(5_000),
        initialValue = WebShieldUiState()
    )

    init {
        inspectWifi()
    }

    fun inspectWifi() {
        viewModelScope.launch {
            wifiSecurityInspector.inspectCurrentWifi()
        }
    }

    fun buildVpnConsentIntent(): Intent? = permissionManager.buildVpnConsentIntent()

    fun startDnsShield() {
        vpnController.startDnsShield(uiState.value.settings.dohProvider)
    }

    fun stopVpn() {
        vpnController.stopVpn()
    }

    fun selectDohProvider(provider: DohProvider) {
        viewModelScope.launch {
            prefs.setDohProvider(provider)
            vpnController.reloadMatcherRules()
            if (uiState.value.vpnState.mode == AegisVpnMode.DNS_SHIELD) {
                vpnController.startDnsShield(provider)
            }
        }
    }

    fun updateFilterCategories(phishing: Boolean, malware: Boolean, adware: Boolean) {
        viewModelScope.launch {
            prefs.setDnsCategories(phishing, malware, adware)
            vpnController.reloadMatcherRules()
        }
    }

    fun addCustomRule(domain: String, allow: Boolean) {
        viewModelScope.launch {
            val added = vpnController.addCustomRule(domain, allow)
            ruleFeedbackFlow.value = if (added) {
                "Saved ${if (allow) "ALLOW" else "BLOCK"} rule to SQLCipher vault."
            } else {
                "Enter a valid domain name (e.g. tracker.example.com)."
            }
        }
    }

    fun updateCustomRule(oldDomain: String, newDomain: String, allow: Boolean) {
        viewModelScope.launch {
            val updated = vpnController.updateCustomRule(oldDomain, newDomain, allow)
            ruleFeedbackFlow.value = if (updated) {
                "Updated custom DNS rule in SQLCipher vault."
            } else {
                "Invalid domain name."
            }
        }
    }

    fun toggleCustomRuleMode(rule: DnsBlockRuleEntity) {
        viewModelScope.launch {
            val currentlyAllowed = rule.category == "CUSTOM_ALLOW"
            vpnController.toggleCustomRuleMode(rule.domain, currentlyAllowed)
        }
    }

    fun applyTelemetryPreset() {
        viewModelScope.launch {
            vpnController.applyCustomBlockPreset(TELEMETRY_PRESET_DOMAINS)
            ruleFeedbackFlow.value = "Applied Telemetry & Analytics preset (+${TELEMETRY_PRESET_DOMAINS.size} domains)."
        }
    }

    fun applyCryptoMinerPreset() {
        viewModelScope.launch {
            vpnController.applyCustomBlockPreset(CRYPTOMINER_PRESET_DOMAINS)
            ruleFeedbackFlow.value = "Applied Crypto-Miner preset (+${CRYPTOMINER_PRESET_DOMAINS.size} domains)."
        }
    }

    fun removeCustomRule(domain: String) {
        viewModelScope.launch {
            vpnController.removeCustomRule(domain)
        }
    }

    fun clearRuleFeedback() {
        ruleFeedbackFlow.value = null
    }

    fun clearLogs() {
        viewModelScope.launch {
            vpnController.clearQueryLogs()
        }
    }

    companion object {
        private val TELEMETRY_PRESET_DOMAINS = listOf(
            "metrics.icloud.com",
            "telemetry.mozilla.org",
            "vortex.data.microsoft.com",
            "graph.instagram.com"
        )
        private val CRYPTOMINER_PRESET_DOMAINS = listOf(
            "coinhive.com",
            "coin-hive.com",
            "minero.cc",
            "webminepool.com"
        )
    }
}
