package com.kaao.security.ui.dashboard

import android.content.Context
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.kaao.security.data.local.prefs.KaaoPreferencesRepository
import com.kaao.security.domain.model.AegisVpnMode
import com.kaao.security.domain.model.AegisVpnState
import com.kaao.security.domain.model.GameSessionState
import com.kaao.security.domain.model.HealthScoreReport
import com.kaao.security.domain.model.SmartScanState
import com.kaao.security.domain.model.WifiAuditReport
import com.kaao.security.domain.usecase.HealthScoreCalculator
import com.kaao.security.domain.usecase.SmartScanOrchestrator
import com.kaao.security.engine.antivirus.AntivirusRepository
import com.kaao.security.engine.cleaner.StorageScanner
import com.kaao.security.engine.gamebooster.GameSessionManager
import com.kaao.security.engine.network.AegisVpnController
import com.kaao.security.engine.network.WifiSecurityInspector
import com.kaao.security.service.RealtimeMonitorService
import dagger.hilt.android.lifecycle.HiltViewModel
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import javax.inject.Inject

data class DashboardUiState(
    val healthReport: HealthScoreReport,
    val smartScan: SmartScanState,
    val vpnState: AegisVpnState,
    val wifiAudit: WifiAuditReport,
    val isRealtimeShieldActive: Boolean,
    val threatCount: Int,
    val stalkerwareCount: Int,
    val reclaimableBytes: Long,
    val blockedQueriesTotal: Long,
    val activeGameSession: GameSessionState
)

@HiltViewModel
class DashboardViewModel @Inject constructor(
    @ApplicationContext private val context: Context,
    private val antivirusRepository: AntivirusRepository,
    private val vpnController: AegisVpnController,
    private val wifiSecurityInspector: WifiSecurityInspector,
    private val storageScanner: StorageScanner,
    private val gameSessionManager: GameSessionManager,
    private val smartScanOrchestrator: SmartScanOrchestrator,
    private val healthScoreCalculator: HealthScoreCalculator,
    private val prefs: KaaoPreferencesRepository
) : ViewModel() {

    private data class CoreSecurityInputs(
        val threatCount: Int,
        val stalkerCount: Int,
        val vpnState: AegisVpnState,
        val realtimeActive: Boolean,
        val wifi: WifiAuditReport,
        val reclaimableBytes: Long,
        val healthReport: HealthScoreReport
    )

    private val coreFlow = combine(
        antivirusRepository.threatFindings,
        antivirusRepository.stalkerwareFindings,
        vpnController.vpnState,
        RealtimeMonitorService.isRunning,
        wifiSecurityInspector.report
    ) { threats, stalkers, vpn, realtime, wifi ->
        val reclaimable = storageScanner.scanResult.value.reclaimableBytes
        val report = healthScoreCalculator.calculate(
            threatFindings = threats,
            stalkerwareFindings = stalkers,
            isDnsShieldActive = vpn.mode == AegisVpnMode.DNS_SHIELD,
            isRealtimeShieldActive = realtime,
            wifiAudit = wifi,
            reclaimableBytes = reclaimable
        )
        CoreSecurityInputs(
            threatCount = threats.size,
            stalkerCount = stalkers.size,
            vpnState = vpn,
            realtimeActive = realtime,
            wifi = wifi,
            reclaimableBytes = reclaimable,
            healthReport = report
        )
    }

    val uiState: StateFlow<DashboardUiState> = combine(
        coreFlow,
        storageScanner.scanResult,
        smartScanOrchestrator.state,
        vpnController.totalBlockedFlow,
        gameSessionManager.sessionState
    ) { core, storage, smartScan, blockedTotal, gameSession ->
        val updatedReport = healthScoreCalculator.calculate(
            threatFindings = antivirusRepository.threatFindings.value,
            stalkerwareFindings = antivirusRepository.stalkerwareFindings.value,
            isDnsShieldActive = core.vpnState.mode == AegisVpnMode.DNS_SHIELD,
            isRealtimeShieldActive = core.realtimeActive,
            wifiAudit = core.wifi,
            reclaimableBytes = storage.reclaimableBytes
        )
        DashboardUiState(
            healthReport = updatedReport,
            smartScan = smartScan,
            vpnState = core.vpnState,
            wifiAudit = core.wifi,
            isRealtimeShieldActive = core.realtimeActive,
            threatCount = core.threatCount,
            stalkerwareCount = core.stalkerCount,
            reclaimableBytes = storage.reclaimableBytes,
            blockedQueriesTotal = blockedTotal,
            activeGameSession = gameSession
        )
    }.stateIn(
        scope = viewModelScope,
        started = SharingStarted.WhileSubscribed(5_000),
        initialValue = DashboardUiState(
            healthReport = healthScoreCalculator.calculate(
                threatFindings = emptyList(),
                stalkerwareFindings = emptyList(),
                isDnsShieldActive = false,
                isRealtimeShieldActive = false,
                wifiAudit = WifiAuditReport(),
                reclaimableBytes = 0L
            ),
            smartScan = SmartScanState(),
            vpnState = AegisVpnState(),
            wifiAudit = WifiAuditReport(),
            isRealtimeShieldActive = false,
            threatCount = 0,
            stalkerwareCount = 0,
            reclaimableBytes = 0L,
            blockedQueriesTotal = 0L,
            activeGameSession = GameSessionState()
        )
    )

    init {
        viewModelScope.launch {
            wifiSecurityInspector.inspectCurrentWifi()
        }
    }

    fun runSmartScan() {
        viewModelScope.launch {
            smartScanOrchestrator.runConcurrentSmartScan()
        }
    }

    fun toggleRealtimeShield(enable: Boolean) {
        viewModelScope.launch {
            prefs.setRealtimeShieldEnabled(enable)
            if (enable) {
                RealtimeMonitorService.start(context)
            } else {
                RealtimeMonitorService.stop(context)
            }
        }
    }

    fun restoreActiveGameSession() {
        viewModelScope.launch {
            gameSessionManager.endSessionAndRestore()
        }
    }
}
