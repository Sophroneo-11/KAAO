package com.kaao.security.domain.usecase

import com.kaao.security.domain.model.CleanerScanResult
import com.kaao.security.domain.model.WifiAuditReport
import com.kaao.security.engine.antivirus.AntivirusRepository
import com.kaao.security.engine.cleaner.StorageScanner
import com.kaao.security.engine.network.WifiSecurityInspector
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SmartScanOrchestratorTest {

    @Test
    fun runsAntivirusWifiAndStorageConcurrentlyAndPublishesSummary() = runTest {
        val avRepo = mockk<AntivirusRepository>()
        every { avRepo.threatFindings } returns MutableStateFlow(emptyList())
        every { avRepo.stalkerwareFindings } returns MutableStateFlow(emptyList())
        coEvery { avRepo.runInstalledAppsScan(false) } returns emptyList()

        val wifiInspector = mockk<WifiSecurityInspector>()
        val wifiReport = WifiAuditReport(isConnectedToWifi = true, ssid = "Lab", safetyScore = 95)
        every { wifiInspector.report } returns MutableStateFlow(wifiReport)
        coEvery { wifiInspector.inspectCurrentWifi() } returns wifiReport

        val storageScanner = mockk<StorageScanner>()
        val storageResult = CleanerScanResult(reclaimableBytes = 128L * 1024L * 1024L)
        every { storageScanner.scanResult } returns MutableStateFlow(storageResult)
        coEvery { storageScanner.runFullStorageScan() } returns storageResult

        val orchestrator = SmartScanOrchestrator(avRepo, wifiInspector, storageScanner)
        orchestrator.runConcurrentSmartScan()

        val finalState = orchestrator.state.value
        assertFalse(finalState.isRunning)
        assertTrue(finalState.antivirusDone)
        assertTrue(finalState.stalkerwareDone)
        assertTrue(finalState.wifiDone)
        assertTrue(finalState.storageDone)
        assertTrue(finalState.summaryMessage.contains("Wi-Fi 95/100"))
        assertTrue(finalState.summaryMessage.contains("128MB reclaimable"))

        coVerify(exactly = 1) { avRepo.runInstalledAppsScan(false) }
        coVerify(exactly = 1) { wifiInspector.inspectCurrentWifi() }
        coVerify(exactly = 1) { storageScanner.runFullStorageScan() }
    }
}
