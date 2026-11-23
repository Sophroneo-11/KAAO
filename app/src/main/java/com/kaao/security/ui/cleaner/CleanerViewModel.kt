package com.kaao.security.ui.cleaner

import android.content.Intent
import android.net.Uri
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.kaao.security.core.permission.PermissionManager
import com.kaao.security.core.permission.PermissionStatusSnapshot
import com.kaao.security.domain.model.AppStorageInfo
import com.kaao.security.domain.model.CleanableItem
import com.kaao.security.domain.model.CleanerCategory
import com.kaao.security.domain.model.DeletionResult
import com.kaao.security.engine.cleaner.SafeDeletionRepository
import com.kaao.security.engine.cleaner.StorageScanner
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

data class CleanerUiState(
    val isScanning: Boolean = false,
    val items: List<CleanableItem> = emptyList(),
    val appStorage: List<AppStorageInfo> = emptyList(),
    val totalStorageBytes: Long = 0L,
    val availableStorageBytes: Long = 0L,
    val scannedFilesCount: Int = 0,
    val permissions: PermissionStatusSnapshot? = null,
    val lastDeletionResult: DeletionResult? = null,
    val pendingMediaStoreDeleteUris: List<Uri> = emptyList()
) {
    val selectedItems: List<CleanableItem>
        get() = items.filter { it.isSelected }

    val selectedCount: Int
        get() = selectedItems.size

    val selectedBytes: Long
        get() = selectedItems.sumOf { it.sizeBytes }
}

@HiltViewModel
class CleanerViewModel @Inject constructor(
    private val storageScanner: StorageScanner,
    private val safeDeletionRepository: SafeDeletionRepository,
    private val permissionManager: PermissionManager
) : ViewModel() {

    private val permissionSnapshotFlow = MutableStateFlow(permissionManager.getSnapshot())
    private val deletionResultFlow = MutableStateFlow<DeletionResult?>(null)
    private val pendingUrisFlow = MutableStateFlow<List<Uri>>(emptyList())

    val uiState: StateFlow<CleanerUiState> = combine(
        storageScanner.isScanning,
        storageScanner.scanResult,
        permissionSnapshotFlow,
        deletionResultFlow,
        pendingUrisFlow
    ) { isScanning, scanResult, perms, delResult, pendingUris ->
        CleanerUiState(
            isScanning = isScanning,
            items = scanResult.items,
            appStorage = scanResult.appStorage,
            totalStorageBytes = scanResult.totalStorageBytes,
            availableStorageBytes = scanResult.availableStorageBytes,
            scannedFilesCount = scanResult.scannedFilesCount,
            permissions = perms,
            lastDeletionResult = delResult,
            pendingMediaStoreDeleteUris = pendingUris
        )
    }.stateIn(
        scope = viewModelScope,
        started = SharingStarted.WhileSubscribed(5_000),
        initialValue = CleanerUiState(permissions = permissionManager.getSnapshot())
    )

    fun refreshPermissions() {
        permissionSnapshotFlow.value = permissionManager.getSnapshot()
    }

    fun startStorageScan() {
        refreshPermissions()
        deletionResultFlow.value = null
        viewModelScope.launch {
            storageScanner.runFullStorageScan()
        }
    }

    fun toggleItemSelection(itemId: String) {
        val current = storageScanner.scanResult.value
        val updated = current.items.map { item ->
            if (item.id == itemId) item.copy(isSelected = !item.isSelected) else item
        }
        storageScanner.updateCachedResult(current.copy(items = updated))
    }

    fun selectAllInCategory(category: CleanerCategory, select: Boolean) {
        val current = storageScanner.scanResult.value
        val updated = current.items.map { item ->
            if (item.category == category) {
                val targetSelect = if (category == CleanerCategory.DUPLICATES && item.isSuggestedOriginal && select) {
                    false // Keep original unchecked when bulk-selecting duplicates
                } else {
                    select
                }
                item.copy(isSelected = targetSelect)
            } else {
                item
            }
        }
        storageScanner.updateCachedResult(current.copy(items = updated))
    }

    fun whitelistItem(item: CleanableItem) {
        viewModelScope.launch {
            safeDeletionRepository.addPathToWhitelist(item.path, item.name)
            val current = storageScanner.scanResult.value
            val remaining = current.items.filterNot { it.id == item.id }
            storageScanner.updateCachedResult(
                current.copy(
                    items = remaining,
                    reclaimableBytes = remaining.filter { !it.isSuggestedOriginal }.sumOf { it.sizeBytes }
                )
            )
        }
    }

    fun executeConfirmedDeletion() {
        val selected = uiState.value.selectedItems
        if (selected.isEmpty()) return
        viewModelScope.launch {
            val result = safeDeletionRepository.deleteConfirmedItems(
                approvedItems = selected,
                userExplicitlyConfirmed = true
            )
            deletionResultFlow.value = result
            if (result.pendingMediaStoreUris.isNotEmpty()) {
                pendingUrisFlow.value = result.pendingMediaStoreUris
            }
            // Refresh scan results to reflect deleted files accurately
            storageScanner.runFullStorageScan()
        }
    }

    fun clearPendingMediaStoreUris() {
        pendingUrisFlow.value = emptyList()
    }

    fun dismissDeletionBanner() {
        deletionResultFlow.value = null
    }

    fun buildAllFilesAccessIntent(): Intent = permissionManager.buildAllFilesAccessIntent()
    fun buildUsageAccessIntent(): Intent = permissionManager.buildUsageAccessIntent()
    fun buildAppDetailsIntent(packageName: String): Intent = permissionManager.buildAppDetailsIntent(packageName)
    fun requiredMediaPermissions(): Array<String> = permissionManager.requiredMediaPermissions()
}
