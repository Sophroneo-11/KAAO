package com.kaao.security.ui.webshield

import android.content.Intent
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.kaao.security.core.permission.PermissionManager
import com.kaao.security.data.local.db.DnsBlockRuleEntity
import com.kaao.security.data.local.prefs.KaaoPreferencesRepository
import com.kaao.security.data.local.prefs.KaaoSettings
import com.kaao.security.domain.model.AegisVpnState
import com.kaao.security.domain.model.DnsQueryEvent
import com.kaao.security.domain.model.DohProvider
import com.kaao.security.domain.model.WifiAuditReport
import com.kaao.security.engine.network.AegisVpnController
import com.kaao.security.engine.network.WifiSecurityInspector
import dagger.hilt.android.lifecycle.HiltViewModel
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
    val customRules: List<DnsBlockRuleEntity> = emptyList()
)

@HiltViewModel
class WebShieldViewModel @Inject constructor(
    private val vpnController: AegisVpnController,
    private val wifiSecurityInspector: WifiSecurityInspector,
    private val prefs: KaaoPreferencesRepository,
    private val permissionManager: PermissionManager
) : ViewModel() {

    private val primaryFlow = combine(
        vpnController.vpnState,
        prefs.settingsFlow,
        wifiSecurityInspector.report
    ) { vpn, settings, wifi ->
        Triple(vpn, settings, wifi)
    }

    val uiState: StateFlow<WebShieldUiState> = combine(
        primaryFlow,
        vpnController.recentQueriesFlow,
        vpnController.totalBlockedFlow,
        vpnController.customRulesFlow
    ) { (vpn, settings, wifi), queries, blockedCount, allRules ->
        WebShieldUiState(
            vpnState = vpn,
            settings = settings,
            wifiAudit = wifi,
            recentQueries = queries,
            totalBlocked = blockedCount,
            customRules = allRules.filter { it.isUserCustom }
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
            if (uiState.value.vpnState.mode == com.kaao.security.domain.model.AegisVpnMode.DNS_SHIELD) {
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
            vpnController.addCustomRule(domain, allow)
        }
    }

    fun removeCustomRule(domain: String) {
        viewModelScope.launch {
            vpnController.removeCustomRule(domain)
        }
    }

    fun clearLogs() {
        viewModelScope.launch {
            vpnController.clearQueryLogs()
        }
    }
}
