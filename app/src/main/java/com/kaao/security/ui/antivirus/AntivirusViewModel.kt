package com.kaao.security.ui.antivirus

import android.content.Context
import android.content.Intent
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.kaao.security.core.permission.PermissionManager
import com.kaao.security.data.local.db.ScanHistoryEntity
import com.kaao.security.data.local.prefs.KaaoPreferencesRepository
import com.kaao.security.domain.model.AntivirusScanProgress
import com.kaao.security.domain.model.CloudReputationResult
import com.kaao.security.domain.model.StalkerwareFinding
import com.kaao.security.domain.model.StalkerwarePrivilege
import com.kaao.security.domain.model.ThreatFinding
import com.kaao.security.engine.antivirus.AntivirusRepository
import com.kaao.security.service.DeepScanForegroundService
import dagger.hilt.android.lifecycle.HiltViewModel
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import javax.inject.Inject

data class AntivirusUiState(
    val progress: AntivirusScanProgress = AntivirusScanProgress(),
    val threats: List<ThreatFinding> = emptyList(),
    val stalkerwareFindings: List<StalkerwareFinding> = emptyList(),
    val signatureCount: Int = 0,
    val definitionVersion: Long = 0L,
    val scanHistory: List<ScanHistoryEntity> = emptyList(),
    val cloudLookupFeedback: String? = null
)

@HiltViewModel
class AntivirusViewModel @Inject constructor(
    @ApplicationContext private val context: Context,
    private val antivirusRepository: AntivirusRepository,
    private val permissionManager: PermissionManager,
    private val prefs: KaaoPreferencesRepository
) : ViewModel() {

    private val cloudFeedbackFlow = MutableStateFlow<String?>(null)

    private val primaryFlow = combine(
        antivirusRepository.scanProgress,
        antivirusRepository.threatFindings,
        antivirusRepository.stalkerwareFindings,
        antivirusRepository.signatureCountFlow
    ) { progress, threats, stalkerware, sigCount ->
        AntivirusUiState(
            progress = progress,
            threats = threats,
            stalkerwareFindings = stalkerware,
            signatureCount = sigCount
        )
    }

    val uiState: StateFlow<AntivirusUiState> = combine(
        primaryFlow,
        prefs.settingsFlow,
        antivirusRepository.scanHistoryFlow,
        cloudFeedbackFlow
    ) { base, settings, history, feedback ->
        base.copy(
            definitionVersion = settings.definitionVersion,
            scanHistory = history,
            cloudLookupFeedback = feedback
        )
    }.stateIn(
        scope = viewModelScope,
        started = SharingStarted.WhileSubscribed(5_000),
        initialValue = AntivirusUiState()
    )

    fun startQuickAppScan() {
        viewModelScope.launch {
            antivirusRepository.runInstalledAppsScan(includeSystemApps = false)
        }
    }

    fun startDeepScanService() {
        DeepScanForegroundService.startDeepScan(context)
    }

    fun runStalkerwareAudit() {
        viewModelScope.launch {
            antivirusRepository.runStalkerwareAuditOnly()
        }
    }

    fun verifyFindingInCloud(finding: ThreatFinding) {
        viewModelScope.launch {
            cloudFeedbackFlow.value = "Querying SHA-256 hash (${finding.sha256.take(12)}...)..."
            val result: CloudReputationResult? = antivirusRepository.verifyHashWithCloud(finding.sha256)
            cloudFeedbackFlow.value = when {
                result == null -> "Cloud hash check unavailable (offline or rate limited)"
                result.isMalicious -> "${result.provider}: MALICIOUS (${result.family ?: "Flagged"}, ${result.positives}/${result.totalEngines})"
                else -> "${result.provider}: No malware hit for SHA-256 ${finding.sha256.take(12)}..."
            }
        }
    }

    fun clearCloudFeedback() {
        cloudFeedbackFlow.value = null
    }

    fun whitelistPackage(packageName: String, label: String) {
        viewModelScope.launch {
            antivirusRepository.whitelistApp(packageName, label)
        }
    }

    fun dismissFinding(findingId: String) {
        antivirusRepository.dismissFinding(findingId)
    }

    fun buildUninstallIntent(packageName: String): Intent =
        permissionManager.buildUninstallIntent(packageName)

    fun buildAppDetailsIntent(packageName: String): Intent =
        permissionManager.buildAppDetailsIntent(packageName)

    fun buildPrivilegeRevokeIntent(privilege: StalkerwarePrivilege): Intent = when (privilege) {
        StalkerwarePrivilege.DEVICE_ADMIN -> permissionManager.buildDeviceAdminSettingsIntent()
        StalkerwarePrivilege.ACCESSIBILITY_SERVICE -> permissionManager.buildAccessibilitySettingsIntent()
        StalkerwarePrivilege.NOTIFICATION_LISTENER -> permissionManager.buildNotificationListenerSettingsIntent()
        StalkerwarePrivilege.USAGE_ACCESS -> permissionManager.buildUsageAccessIntent()
    }
}
