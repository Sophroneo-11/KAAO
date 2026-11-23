package com.kaao.security.ui.cleaner

import android.app.Activity
import android.os.Build
import android.provider.MediaStore
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.IntentSenderRequest
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.CleaningServices
import androidx.compose.material.icons.outlined.DeleteSweep
import androidx.compose.material.icons.outlined.Shield
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.kaao.security.core.permission.StorageScanMode
import com.kaao.security.core.util.ByteFormatters
import com.kaao.security.domain.model.AppStorageInfo
import com.kaao.security.domain.model.CleanableItem
import com.kaao.security.domain.model.CleanerCategory
import com.kaao.security.ui.components.PermissionRationaleBanner
import com.kaao.security.ui.components.SecurityCard
import com.kaao.security.ui.components.StatusTag
import com.kaao.security.ui.theme.KaaoColors

@Composable
fun CleanerScreen(
    viewModel: CleanerViewModel = hiltViewModel()
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val context = LocalContext.current

    // null = App Storage tab, otherwise specific CleanerCategory
    var selectedCategoryName by rememberSaveable { mutableStateOf(CleanerCategory.DUPLICATES.name) }
    var showConfirmModal by rememberSaveable { mutableStateOf(false) }

    val mediaPermLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.RequestMultiplePermissions()
    ) {
        viewModel.refreshPermissions()
        viewModel.startStorageScan()
    }

    val mediaDeleteLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.StartIntentSenderForResult()
    ) { result ->
        viewModel.clearPendingMediaStoreUris()
        if (result.resultCode == Activity.RESULT_OK) {
            viewModel.startStorageScan()
        }
    }

    LaunchedEffect(state.pendingMediaStoreDeleteUris) {
        val uris = state.pendingMediaStoreDeleteUris
        if (uris.isNotEmpty() && Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            runCatching {
                val pi = MediaStore.createDeleteRequest(context.contentResolver, uris)
                mediaDeleteLauncher.launch(IntentSenderRequest.Builder(pi.intentSender).build())
            }.onFailure {
                viewModel.clearPendingMediaStoreUris()
            }
        }
    }

    val activeCategory = CleanerCategory.entries.firstOrNull { it.name == selectedCategoryName }
    val filteredItems = if (activeCategory != null) {
        state.items.filter { it.category == activeCategory }
    } else {
        emptyList()
    }

    Column(modifier = Modifier.fillMaxSize()) {
        LazyColumn(
            modifier = Modifier.weight(1f),
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            // Storage Overview & Scan Button
            item {
                SecurityCard {
                    val usedBytes = (state.totalStorageBytes - state.availableStorageBytes).coerceAtLeast(0L)
                    val usedFraction = if (state.totalStorageBytes > 0L) {
                        (usedBytes.toDouble() / state.totalStorageBytes.toDouble()).toFloat().coerceIn(0f, 1f)
                    } else {
                        0f
                    }
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column {
                            Text(
                                text = "Deep Storage Cleaner",
                                style = MaterialTheme.typography.titleMedium,
                                color = KaaoColors.TextPrimary
                            )
                            Text(
                                text = if (state.totalStorageBytes > 0L) {
                                    "${ByteFormatters.formatBytes(usedBytes)} used of ${ByteFormatters.formatBytes(state.totalStorageBytes)}"
                                } else {
                                    "Tap Scan to inspect duplicates, APKs, logs & apps"
                                },
                                style = MaterialTheme.typography.bodySmall,
                                color = KaaoColors.TextSecondary
                            )
                        }
                        val modeLabel = when (state.permissions?.storageScanMode) {
                            StorageScanMode.ALL_FILES -> "All Files"
                            StorageScanMode.MEDIA_STORE_FALLBACK -> "MediaStore"
                            else -> "Limited"
                        }
                        StatusTag(
                            label = modeLabel,
                            accent = if (modeLabel == "All Files") KaaoColors.CyberEmerald else KaaoColors.WarningAmber
                        )
                    }

                    if (state.totalStorageBytes > 0L) {
                        Spacer(modifier = Modifier.height(10.dp))
                        LinearProgressIndicator(
                            progress = { usedFraction },
                            modifier = Modifier
                                .fillMaxWidth()
                                .height(8.dp)
                                .clip(RoundedCornerShape(4.dp)),
                            color = if (usedFraction > 0.85f) KaaoColors.ThreatCrimson else KaaoColors.ShieldCyan,
                            trackColor = KaaoColors.SurfaceElevated
                        )
                    }

                    Spacer(modifier = Modifier.height(12.dp))
                    Button(
                        onClick = { viewModel.startStorageScan() },
                        enabled = !state.isScanning,
                        modifier = Modifier.fillMaxWidth(),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = KaaoColors.CyberEmerald,
                            contentColor = KaaoColors.ObsidianBg
                        )
                    ) {
                        if (state.isScanning) {
                            CircularProgressIndicator(
                                modifier = Modifier.size(16.dp),
                                strokeWidth = 2.dp,
                                color = KaaoColors.ObsidianBg
                            )
                            Spacer(modifier = Modifier.width(8.dp))
                            Text("Running 3-Stage SHA-256 Scan...", fontWeight = FontWeight.Bold)
                        } else {
                            Icon(Icons.Outlined.CleaningServices, contentDescription = null)
                            Spacer(modifier = Modifier.width(8.dp))
                            Text("Analyze Storage & Duplicates", fontWeight = FontWeight.Bold)
                        }
                    }
                }
            }

            // Just-in-time Permission Banner with Graceful MediaStore Fallback
            if (state.permissions?.allFilesAccessGranted == false) {
                item {
                    val hasMedia = state.permissions?.mediaReadGranted == true
                    PermissionRationaleBanner(
                        title = if (hasMedia) "MediaStore Fallback Active" else "Storage Permission Needed",
                        description = if (hasMedia) {
                            "Scanning photos, videos, audio, and Downloads via MediaStore. Grant All Files Access to also clean leftover APKs, temp/log files, and empty folders."
                        } else {
                            "Grant Media Read for safe duplicate photo/video cleanup, or All Files Access for full deep storage cleaning."
                        },
                        actionLabel = if (hasMedia) "Enable All Files Access" else "Grant Media Access",
                        onAction = {
                            if (hasMedia) {
                                runCatching { context.startActivity(viewModel.buildAllFilesAccessIntent()) }
                            } else {
                                mediaPermLauncher.launch(viewModel.requiredMediaPermissions())
                            }
                        }
                    )
                }
            }

            // Last Deletion Result Summary
            state.lastDeletionResult?.let { result ->
                item {
                    SecurityCard(
                        borderColor = KaaoColors.CyberEmerald,
                        containerColor = KaaoColors.CyberEmeraldContainer.copy(alpha = 0.35f)
                    ) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    text = "Cleaned ${result.deletedCount} item(s) • ${ByteFormatters.formatBytes(result.reclaimedBytes)} freed",
                                    style = MaterialTheme.typography.titleMedium,
                                    color = KaaoColors.CyberEmerald
                                )
                                if (result.skippedWhitelistedCount > 0 || result.failedCount > 0) {
                                    Text(
                                        text = "${result.skippedWhitelistedCount} whitelisted/protected skipped • ${result.failedCount} could not be removed",
                                        style = MaterialTheme.typography.bodySmall,
                                        color = KaaoColors.TextSecondary
                                    )
                                }
                            }
                            TextButton(onClick = { viewModel.dismissDeletionBanner() }) {
                                Text("Dismiss")
                            }
                        }
                    }
                }
            }

            // Category Selector Row
            item {
                LazyRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    items(CleanerCategory.entries) { cat ->
                        val count = state.items.count { it.category == cat }
                        FilterChip(
                            selected = selectedCategoryName == cat.name,
                            onClick = { selectedCategoryName = cat.name },
                            label = { Text("${cat.label} ($count)") }
                        )
                    }
                    item {
                        FilterChip(
                            selected = selectedCategoryName == "APP_STORAGE",
                            onClick = { selectedCategoryName = "APP_STORAGE" },
                            label = { Text("App Storage (${state.appStorage.size})") }
                        )
                    }
                }
            }

            if (selectedCategoryName == "APP_STORAGE") {
                if (state.permissions?.usageStatsGranted == false) {
                    item {
                        PermissionRationaleBanner(
                            title = "Enable Usage Access for Exact App Cache Breakdown",
                            description = "Currently displaying APK size estimates. Grant Usage Access to inspect exact app data & cache bytes via StorageStatsManager.",
                            actionLabel = "Grant Usage Access",
                            onAction = {
                                runCatching { context.startActivity(viewModel.buildUsageAccessIntent()) }
                            }
                        )
                    }
                }
                items(state.appStorage, key = { it.packageName }) { app ->
                    AppStorageRowCard(
                        app = app,
                        onOpenAppSettings = {
                            runCatching { context.startActivity(viewModel.buildAppDetailsIntent(app.packageName)) }
                        }
                    )
                }
            } else if (activeCategory != null) {
                item {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = activeCategory.description,
                            style = MaterialTheme.typography.bodySmall,
                            color = KaaoColors.TextSecondary,
                            modifier = Modifier.weight(1f)
                        )
                        if (filteredItems.isNotEmpty()) {
                            val anyUnselected = filteredItems.any { !it.isSelected && !it.isSuggestedOriginal }
                            TextButton(onClick = { viewModel.selectAllInCategory(activeCategory, anyUnselected) }) {
                                Text(if (anyUnselected) "Select All" else "Clear")
                            }
                        }
                    }
                }

                if (filteredItems.isEmpty()) {
                    item {
                        SecurityCard {
                            Text(
                                text = "No ${activeCategory.label.lowercase()} found.",
                                style = MaterialTheme.typography.bodyMedium,
                                color = KaaoColors.TextSecondary
                            )
                        }
                    }
                } else {
                    items(filteredItems, key = { it.id }) { item ->
                        CleanableItemRow(
                            item = item,
                            onToggle = { viewModel.toggleItemSelection(item.id) },
                            onWhitelist = { viewModel.whitelistItem(item) }
                        )
                    }
                }
            }
        }

        // Sticky Explicit Confirmation Footer Bar
        if (state.selectedCount > 0) {
            Surface(
                color = KaaoColors.SurfaceElevated,
                tonalElevation = 8.dp
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp, vertical = 12.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column {
                        Text(
                            text = "${state.selectedCount} item(s) selected",
                            style = MaterialTheme.typography.titleMedium,
                            color = KaaoColors.TextPrimary
                        )
                        Text(
                            text = "Reclaim ${ByteFormatters.formatBytes(state.selectedBytes)}",
                            style = MaterialTheme.typography.bodySmall,
                            color = KaaoColors.CyberEmerald
                        )
                    }
                    Button(
                        onClick = { showConfirmModal = true },
                        colors = ButtonDefaults.buttonColors(containerColor = KaaoColors.ThreatCrimson)
                    ) {
                        Icon(Icons.Outlined.DeleteSweep, contentDescription = null)
                        Spacer(modifier = Modifier.width(6.dp))
                        Text("Review & Delete")
                    }
                }
            }
        }
    }

    // Explicit User-Confirmed Safe Deletion Modal
    if (showConfirmModal) {
        val grouped = state.selectedItems.groupBy { it.category }
        AlertDialog(
            onDismissRequest = { showConfirmModal = false },
            containerColor = KaaoColors.SurfaceDark,
            title = {
                Text(
                    text = "Confirm Permanent Deletion",
                    color = KaaoColors.TextPrimary
                )
            },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text(
                        text = "You are about to permanently delete ${state.selectedCount} file(s)/folder(s) totaling ${ByteFormatters.formatBytes(state.selectedBytes)}. Whitelisted and system paths are automatically protected.",
                        style = MaterialTheme.typography.bodySmall,
                        color = KaaoColors.TextSecondary
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                    grouped.forEach { (cat, list) ->
                        val catBytes = list.sumOf { it.sizeBytes }
                        Text(
                            text = "• ${cat.label}: ${list.size} item(s) (${ByteFormatters.formatBytes(catBytes)})",
                            style = MaterialTheme.typography.bodySmall,
                            color = KaaoColors.TextPrimary
                        )
                    }
                }
            },
            confirmButton = {
                Button(
                    onClick = {
                        showConfirmModal = false
                        viewModel.executeConfirmedDeletion()
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = KaaoColors.ThreatCrimson)
                ) {
                    Text("Delete Confirmed Items")
                }
            },
            dismissButton = {
                TextButton(onClick = { showConfirmModal = false }) {
                    Text("Cancel")
                }
            }
        )
    }
}

@Composable
private fun CleanableItemRow(
    item: CleanableItem,
    onToggle: () -> Unit,
    onWhitelist: () -> Unit
) {
    SecurityCard(containerColor = KaaoColors.SurfaceElevated) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Checkbox(
                checked = item.isSelected,
                onCheckedChange = { onToggle() }
            )
            Column(modifier = Modifier.weight(1f)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        text = item.name,
                        style = MaterialTheme.typography.bodyMedium,
                        color = KaaoColors.TextPrimary,
                        fontWeight = FontWeight.Medium,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.weight(1f, fill = false)
                    )
                    if (!item.detailBadge.isNullOrBlank()) {
                        Spacer(modifier = Modifier.width(6.dp))
                        StatusTag(
                            label = item.detailBadge,
                            accent = if (item.isSuggestedOriginal) KaaoColors.CyberEmerald else KaaoColors.ShieldCyan
                        )
                    }
                }
                Text(
                    text = item.path,
                    style = MaterialTheme.typography.labelSmall,
                    color = KaaoColors.TextMuted,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                Text(
                    text = ByteFormatters.formatBytes(item.sizeBytes),
                    style = MaterialTheme.typography.labelMedium,
                    color = KaaoColors.WarningAmber
                )
            }
            IconButton(onClick = onWhitelist) {
                Icon(
                    imageVector = Icons.Outlined.Shield,
                    contentDescription = "Exclude from cleaner",
                    tint = KaaoColors.TextSecondary
                )
            }
        }
    }
}

@Composable
private fun AppStorageRowCard(
    app: AppStorageInfo,
    onOpenAppSettings: () -> Unit
) {
    SecurityCard(containerColor = KaaoColors.SurfaceElevated) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = app.appName,
                    style = MaterialTheme.typography.titleMedium,
                    color = KaaoColors.TextPrimary,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                Text(
                    text = if (app.isExactStats) {
                        "App ${ByteFormatters.formatBytes(app.appBytes)} • Data ${ByteFormatters.formatBytes(app.dataBytes)} • Cache ${ByteFormatters.formatBytes(app.cacheBytes)}"
                    } else {
                        "APK ${ByteFormatters.formatBytes(app.appBytes)} (Grant Usage Access for cache)"
                    },
                    style = MaterialTheme.typography.bodySmall,
                    color = KaaoColors.TextSecondary
                )
            }
            OutlinedButton(onClick = onOpenAppSettings) {
                Text("Storage")
            }
        }
    }
}
