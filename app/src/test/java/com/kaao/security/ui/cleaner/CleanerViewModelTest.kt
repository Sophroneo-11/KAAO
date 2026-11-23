package com.kaao.security.ui.cleaner

import com.kaao.security.core.permission.PermissionManager
import com.kaao.security.core.permission.PermissionStatusSnapshot
import com.kaao.security.core.permission.StorageScanMode
import com.kaao.security.domain.model.CleanableItem
import com.kaao.security.domain.model.CleanerCategory
import com.kaao.security.domain.model.CleanerScanResult
import com.kaao.security.domain.model.DeletionResult
import com.kaao.security.engine.cleaner.SafeDeletionRepository
import com.kaao.security.engine.cleaner.StorageScanner
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class CleanerViewModelTest {

    private val testDispatcher = StandardTestDispatcher()

    @Before
    fun setUp() {
        Dispatchers.setMain(testDispatcher)
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
    }

    @Test
    fun bulkSelectDuplicatesKeepsOriginalUnselectedAndConfirmedDeleteCallsRepository() = runTest {
        val original = CleanableItem(
            id = "dup1",
            name = "orig.jpg",
            path = "/storage/emulated/0/DCIM/orig.jpg",
            sizeBytes = 4096L,
            lastModifiedMillis = 100L,
            category = CleanerCategory.DUPLICATES,
            duplicateGroupId = "abc",
            isSuggestedOriginal = true,
            isSelected = false
        )
        val duplicate = CleanableItem(
            id = "dup2",
            name = "copy.jpg",
            path = "/storage/emulated/0/Download/copy.jpg",
            sizeBytes = 4096L,
            lastModifiedMillis = 200L,
            category = CleanerCategory.DUPLICATES,
            duplicateGroupId = "abc",
            isSuggestedOriginal = false,
            isSelected = false
        )

        val scanFlow = MutableStateFlow(CleanerScanResult(items = listOf(original, duplicate)))
        val isScanningFlow = MutableStateFlow(false)

        val scanner = mockk<StorageScanner>()
        every { scanner.scanResult } returns scanFlow
        every { scanner.isScanning } returns isScanningFlow
        every { scanner.updateCachedResult(any()) } answers { scanFlow.value = firstArg() }
        coEvery { scanner.runFullStorageScan() } returns CleanerScanResult()

        val deletionRepo = mockk<SafeDeletionRepository>()
        coEvery { deletionRepo.deleteConfirmedItems(any(), true) } returns DeletionResult(1, 4096L, 0, 0)

        val permManager = mockk<PermissionManager>()
        every { permManager.getSnapshot() } returns PermissionStatusSnapshot(
            notificationsGranted = true,
            usageStatsGranted = false,
            allFilesAccessGranted = true,
            mediaReadGranted = true,
            overlayGranted = false,
            dndPolicyGranted = false,
            writeSettingsGranted = false,
            vpnConsentGranted = false,
            storageScanMode = StorageScanMode.ALL_FILES
        )

        val vm = CleanerViewModel(scanner, deletionRepo, permManager)

        vm.selectAllInCategory(CleanerCategory.DUPLICATES, select = true)
        val afterBulk = scanFlow.value.items
        assertFalse("Suggested original must remain unselected on bulk select", afterBulk.first { it.id == "dup1" }.isSelected)
        assertTrue("Duplicate copy must be selected on bulk select", afterBulk.first { it.id == "dup2" }.isSelected)

        // Collect uiState briefly so stateIn activates
        val collector = backgroundScope.launch { vm.uiState.collect { } }
        advanceUntilIdle()
        assertEquals(1, vm.uiState.value.selectedCount)
        assertEquals(4096L, vm.uiState.value.selectedBytes)

        vm.executeConfirmedDeletion()
        advanceUntilIdle()

        coVerify(exactly = 1) {
            deletionRepo.deleteConfirmedItems(
                approvedItems = match { it.size == 1 && it.first().id == "dup2" },
                userExplicitlyConfirmed = true
            )
        }
        collector.cancel()
    }
}
