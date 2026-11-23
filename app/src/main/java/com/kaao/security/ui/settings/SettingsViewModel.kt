package com.kaao.security.ui.settings

import android.content.Context
import android.content.Intent
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.kaao.security.core.crypto.KeystorePassphraseManager
import com.kaao.security.core.permission.PermissionManager
import com.kaao.security.core.permission.PermissionStatusSnapshot
import com.kaao.security.data.local.db.WhitelistEntryEntity
import com.kaao.security.data.local.prefs.KaaoPreferencesRepository
import com.kaao.security.data.local.prefs.KaaoSettings
import com.kaao.security.engine.antivirus.AntivirusRepository
import com.kaao.security.engine.cleaner.SafeDeletionRepository
import com.kaao.security.service.RealtimeMonitorService
import com.kaao.security.worker.DeltaPackageAuditWorker
import dagger.hilt.android.lifecycle.HiltViewModel
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import javax.inject.Inject

data class SettingsUiState(
    val settings: KaaoSettings = KaaoSettings(),
    val isRealtimeRunning: Boolean = false,
    val signatureCount: Int = 0,
    val bloomBitCapacity: Int = 0,
    val keystoreReady: Boolean = false,
    val cleanerWhitelist: List<WhitelistEntryEntity> = emptyList(),
    val permissions: PermissionStatusSnapshot? = null,
    val statusBanner: String? = null
)

@HiltViewModel
class SettingsViewModel @Inject constructor(
    @ApplicationContext private val context: Context,
    private val prefs: KaaoPreferencesRepository,
    private val antivirusRepository: AntivirusRepository,
    private val safeDeletionRepository: SafeDeletionRepository,
    private val keystorePassphraseManager: KeystorePassphraseManager,
    private val permissionManager: PermissionManager
) : ViewModel() {

    private val permsFlow = MutableStateFlow(permissionManager.getSnapshot())
    private val bannerFlow = MutableStateFlow<String?>(null)

    private val baseFlow = combine(
        prefs.settingsFlow,
        RealtimeMonitorService.isRunning,
        antivirusRepository.signatureCountFlow,
        safeDeletionRepository.cleanerWhitelistFlow
    ) { settings, rtRunning, sigCount, whitelist ->
        SettingsUiState(
            settings = settings,
            isRealtimeRunning = rtRunning,
            signatureCount = sigCount,
            bloomBitCapacity = antivirusRepository.bloomCapacity,
            keystoreReady = keystorePassphraseManager.isHardwareKeyReady(),
            cleanerWhitelist = whitelist
        )
    }

    val uiState: StateFlow<SettingsUiState> = combine(
        baseFlow,
        permsFlow,
        bannerFlow
    ) { base, perms, banner ->
        base.copy(permissions = perms, statusBanner = banner)
    }.stateIn(
        scope = viewModelScope,
        started = SharingStarted.WhileSubscribed(5_000),
        initialValue = SettingsUiState(
            keystoreReady = keystorePassphraseManager.isHardwareKeyReady(),
            permissions = permissionManager.getSnapshot()
        )
    )

    fun refreshPermissions() {
        permsFlow.value = permissionManager.getSnapshot()
    }

    fun toggleRealtimeShield(enabled: Boolean) {
        viewModelScope.launch {
            prefs.setRealtimeShieldEnabled(enabled)
            if (enabled) {
                RealtimeMonitorService.start(context)
            } else {
                RealtimeMonitorService.stop(context)
            }
        }
    }

    fun toggleDownloadsObserver(enabled: Boolean) {
        viewModelScope.launch {
            prefs.setDownloadsObserverEnabled(enabled)
            if (uiState.value.isRealtimeRunning) {
                RealtimeMonitorService.stop(context)
                RealtimeMonitorService.start(context)
            }
        }
    }

    fun toggleDeltaPackageAudit(enabled: Boolean) {
        viewModelScope.launch {
            prefs.setDeltaPackageAuditEnabled(enabled)
            if (enabled) {
                DeltaPackageAuditWorker.schedulePeriodic(context)
            } else {
                DeltaPackageAuditWorker.cancel(context)
            }
        }
    }

    fun toggleCloudHashLookup(enabled: Boolean) {
        viewModelScope.launch {
            prefs.setCloudHashLookupEnabled(enabled)
        }
    }

    fun saveVirusTotalApiKey(apiKey: String) {
        viewModelScope.launch {
            prefs.saveVirusTotalApiKey(apiKey)
            bannerFlow.value = if (apiKey.isBlank()) {
                "VirusTotal API key cleared from Android Keystore storage."
            } else {
                "VirusTotal API key encrypted with AES-256-GCM Keystore."
            }
        }
    }

    fun rebuildAndVerifyVault() {
        viewModelScope.launch {
            antivirusRepository.initializeVaultAndBloomFilter()
            bannerFlow.value = "SQLCipher vault verified & Bloom Filter rebuilt (${antivirusRepository.bloomItemCount} signatures)."
        }
    }

    fun removeWhitelistEntry(id: Long) {
        viewModelScope.launch {
            safeDeletionRepository.removeWhitelistEntry(id)
        }
    }

    fun clearBanner() {
        bannerFlow.value = null
    }

    fun buildAllFilesIntent(): Intent = permissionManager.buildAllFilesAccessIntent()
    fun buildUsageIntent(): Intent = permissionManager.buildUsageAccessIntent()
    fun buildOverlayIntent(): Intent = permissionManager.buildOverlayPermissionIntent()
    fun buildDndIntent(): Intent = permissionManager.buildDndAccessIntent()
    fun buildWriteSettingsIntent(): Intent = permissionManager.buildWriteSettingsIntent()
}
