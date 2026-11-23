package com.kaao.security.domain.usecase

import com.kaao.security.domain.model.SmartScanState
import com.kaao.security.engine.antivirus.AntivirusRepository
import com.kaao.security.engine.cleaner.StorageScanner
import com.kaao.security.engine.network.WifiSecurityInspector
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.withContext
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Executes Antivirus, Stalkerware Privilege Audit, Wi-Fi Security Inspection, and Storage Hygiene scan
 * concurrently with per-module progress tracking.
 */
@Singleton
class SmartScanOrchestrator @Inject constructor(
    private val antivirusRepository: AntivirusRepository,
    private val wifiSecurityInspector: WifiSecurityInspector,
    private val storageScanner: StorageScanner
) {
    private val _state = MutableStateFlow(SmartScanState())
    val state: StateFlow<SmartScanState> = _state.asStateFlow()

    suspend fun runConcurrentSmartScan() = withContext(Dispatchers.IO) {
        if (_state.value.isRunning) return@withContext

        _state.value = SmartScanState(
            isRunning = true,
            antivirusDone = false,
            stalkerwareDone = false,
            wifiDone = false,
            storageDone = false,
            summaryMessage = "Running concurrent Antivirus, Stalkerware, Wi-Fi & Storage audit..."
        )

        coroutineScope {
            val avJob = async {
                antivirusRepository.runInstalledAppsScan(includeSystemApps = false)
                _state.update { it.copy(antivirusDone = true, stalkerwareDone = true) }
            }
            val wifiJob = async {
                wifiSecurityInspector.inspectCurrentWifi()
                _state.update { it.copy(wifiDone = true) }
            }
            val storageJob = async {
                storageScanner.runFullStorageScan()
                _state.update { it.copy(storageDone = true) }
            }
            awaitAll(avJob, wifiJob, storageJob)
        }

        val threats = antivirusRepository.threatFindings.value.size
        val stalkers = antivirusRepository.stalkerwareFindings.value.size
        val wifiScore = wifiSecurityInspector.report.value.safetyScore
        val reclaimMb = storageScanner.scanResult.value.reclaimableBytes / (1024L * 1024L)

        val summary = buildString {
            append("$threats malware/heuristic threat(s) • ")
            append("$stalkers privileged app(s) • ")
            append("Wi-Fi $wifiScore/100 • ")
            append("${reclaimMb}MB reclaimable")
        }

        _state.value = SmartScanState(
            isRunning = false,
            antivirusDone = true,
            stalkerwareDone = true,
            wifiDone = true,
            storageDone = true,
            summaryMessage = summary,
            lastCompletedMillis = System.currentTimeMillis()
        )
    }
}
