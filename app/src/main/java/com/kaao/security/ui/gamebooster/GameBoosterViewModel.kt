package com.kaao.security.ui.gamebooster

import android.content.Intent
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.kaao.security.core.permission.PermissionManager
import com.kaao.security.core.permission.PermissionStatusSnapshot
import com.kaao.security.data.local.prefs.KaaoPreferencesRepository
import com.kaao.security.domain.model.DeviceTelemetry
import com.kaao.security.domain.model.FirewallExceptionApp
import com.kaao.security.domain.model.GameApp
import com.kaao.security.domain.model.GameBoostConfig
import com.kaao.security.domain.model.GameSessionState
import com.kaao.security.engine.gamebooster.DeviceTelemetryCollector
import com.kaao.security.engine.gamebooster.GameDetector
import com.kaao.security.engine.gamebooster.GameSessionManager
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import javax.inject.Inject

data class GameBoosterUiState(
    val telemetry: DeviceTelemetry = DeviceTelemetry(),
    val config: GameBoostConfig = GameBoostConfig(),
    val session: GameSessionState = GameSessionState(),
    val games: List<GameApp> = emptyList(),
    val launchableApps: List<GameApp> = emptyList(),
    val firewallExceptionPackages: Set<String> = emptySet(),
    val firewallExceptionCandidates: List<FirewallExceptionApp> = emptyList(),
    val permissions: PermissionStatusSnapshot? = null
)

@HiltViewModel
class GameBoosterViewModel @Inject constructor(
    private val gameDetector: GameDetector,
    private val telemetryCollector: DeviceTelemetryCollector,
    private val gameSessionManager: GameSessionManager,
    private val permissionManager: PermissionManager,
    private val prefs: KaaoPreferencesRepository
) : ViewModel() {

    private val gamesFlow = MutableStateFlow<List<GameApp>>(emptyList())
    private val allAppsFlow = MutableStateFlow<List<GameApp>>(emptyList())
    private val exceptionCandidatesFlow = MutableStateFlow<List<FirewallExceptionApp>>(emptyList())
    private val permsFlow = MutableStateFlow(permissionManager.getSnapshot())

    private val baseFlow = combine(
        telemetryCollector.observeTelemetry(2500L),
        prefs.settingsFlow,
        gameSessionManager.sessionState
    ) { telemetry, settings, session ->
        Triple(telemetry, settings, session)
    }

    val uiState: StateFlow<GameBoosterUiState> = combine(
        baseFlow,
        gamesFlow,
        allAppsFlow,
        exceptionCandidatesFlow,
        permsFlow
    ) { (telemetry, settings, session), games, allApps, candidates, perms ->
        val selected = settings.gameFirewallExceptionPackages
        val syncedCandidates = candidates.map { it.copy(isSelected = it.packageName in selected) }
        GameBoosterUiState(
            telemetry = telemetry,
            config = settings.gameBoostConfig,
            session = session,
            games = games,
            launchableApps = allApps,
            firewallExceptionPackages = selected,
            firewallExceptionCandidates = syncedCandidates,
            permissions = perms
        )
    }.stateIn(
        scope = viewModelScope,
        started = SharingStarted.WhileSubscribed(5_000),
        initialValue = GameBoosterUiState(permissions = permissionManager.getSnapshot())
    )

    init {
        refreshLibrary()
    }

    fun refreshLibrary() {
        permsFlow.value = permissionManager.getSnapshot()
        viewModelScope.launch {
            gamesFlow.value = gameDetector.loadGameLibrary()
            val selected = prefs.getSettings().gameFirewallExceptionPackages
            exceptionCandidatesFlow.value = gameDetector.loadFirewallExceptionCandidates(selected)
        }
    }

    fun loadAllLaunchableAppsForPicker() {
        viewModelScope.launch {
            allAppsFlow.value = gameDetector.loadAllLaunchableApps()
        }
    }

    fun loadFirewallExceptionCandidates() {
        viewModelScope.launch {
            val selected = prefs.getSettings().gameFirewallExceptionPackages
            exceptionCandidatesFlow.value = gameDetector.loadFirewallExceptionCandidates(selected)
        }
    }

    fun toggleFirewallException(packageName: String) {
        viewModelScope.launch {
            prefs.toggleGameFirewallException(packageName)
        }
    }

    fun addCustomGame(app: GameApp) {
        viewModelScope.launch {
            gameDetector.addCustomGame(app.packageName, app.appName)
            gamesFlow.value = gameDetector.loadGameLibrary()
        }
    }

    fun removeCustomGame(packageName: String) {
        viewModelScope.launch {
            gameDetector.removeCustomGame(packageName)
            gamesFlow.value = gameDetector.loadGameLibrary()
        }
    }

    fun updateConfig(transform: (GameBoostConfig) -> GameBoostConfig) {
        viewModelScope.launch {
            val updated = transform(uiState.value.config)
            prefs.updateGameBoostConfig(updated)
        }
    }

    fun launchBoostedGame(game: GameApp) {
        viewModelScope.launch {
            gameSessionManager.startBoostedSession(game, uiState.value.config)
        }
    }

    fun endSessionAndRestore() {
        viewModelScope.launch {
            gameSessionManager.endSessionAndRestore()
        }
    }

    fun buildVpnConsentIntent(): Intent? = permissionManager.buildVpnConsentIntent()
    fun buildDndIntent(): Intent = permissionManager.buildDndAccessIntent()
    fun buildWriteSettingsIntent(): Intent = permissionManager.buildWriteSettingsIntent()
    fun buildOverlayIntent(): Intent = permissionManager.buildOverlayPermissionIntent()
}
