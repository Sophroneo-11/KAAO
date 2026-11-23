package com.kaao.security.ui.gamebooster

import android.app.Activity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Add
import androidx.compose.material.icons.outlined.PlayArrow
import androidx.compose.material.icons.outlined.Restore
import androidx.compose.material.icons.outlined.SportsEsports
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Slider
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.kaao.security.core.util.ByteFormatters
import com.kaao.security.domain.model.GameApp
import com.kaao.security.ui.components.SectionHeader
import com.kaao.security.ui.components.SecurityCard
import com.kaao.security.ui.components.SeverityPill
import com.kaao.security.ui.components.StatusTag
import com.kaao.security.ui.theme.KaaoColors
import java.util.Locale

@Composable
fun GameBoosterScreen(
    viewModel: GameBoosterViewModel = hiltViewModel()
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val context = LocalContext.current

    var showAddGameDialog by rememberSaveable { mutableStateOf(false) }
    var pendingGameLaunch by remember { mutableStateOf<GameApp?>(null) }

    val vpnConsentLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.StartActivityForResult()
    ) { result ->
        viewModel.refreshLibrary()
        val game = pendingGameLaunch
        pendingGameLaunch = null
        if (game != null && result.resultCode == Activity.RESULT_OK) {
            viewModel.launchBoostedGame(game)
        }
    }

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        // Active Session Banner
        if (state.session.isActive) {
            item {
                SecurityCard(
                    borderColor = KaaoColors.BoosterViolet,
                    containerColor = KaaoColors.BoosterVioletContainer.copy(alpha = 0.45f)
                ) {
                    Text(
                        text = "Boosted Session Active: ${state.session.activeGameName}",
                        style = MaterialTheme.typography.titleMedium,
                        color = KaaoColors.BoosterViolet
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = "Background firewall, DND, brightness & sync adjustments will revert automatically when you tap Restore.",
                        style = MaterialTheme.typography.bodySmall,
                        color = KaaoColors.TextPrimary
                    )
                    Spacer(modifier = Modifier.height(10.dp))
                    Button(
                        onClick = { viewModel.endSessionAndRestore() },
                        colors = ButtonDefaults.buttonColors(
                            containerColor = KaaoColors.CyberEmerald,
                            contentColor = KaaoColors.ObsidianBg
                        )
                    ) {
                        Icon(Icons.Outlined.Restore, contentDescription = null)
                        Spacer(modifier = Modifier.width(8.dp))
                        Text("Restore All System Settings", fontWeight = FontWeight.Bold)
                    }
                }
            }
        }

        // Live Device Telemetry Strip
        item {
            SecurityCard {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = "Live Hardware & Network Telemetry",
                        style = MaterialTheme.typography.titleMedium,
                        color = KaaoColors.TextPrimary
                    )
                    SeverityPill(
                        label = state.telemetry.thermalStatusLabel,
                        severity = state.telemetry.thermalSeverity
                    )
                }
                Spacer(modifier = Modifier.height(12.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    TelemetryCell(
                        label = "TCP PING",
                        value = state.telemetry.tcpPingMs?.let { "${it} ms" } ?: "-- ms",
                        accent = KaaoColors.ShieldCyan
                    )
                    TelemetryCell(
                        label = "THERMAL",
                        value = String.format(Locale.US, "%.1f°C", state.telemetry.batteryTempCelsius),
                        accent = KaaoColors.WarningAmber
                    )
                    TelemetryCell(
                        label = "RAM USED",
                        value = "${state.telemetry.ramUsagePercent}%",
                        accent = KaaoColors.BoosterViolet
                    )
                    TelemetryCell(
                        label = "BATTERY",
                        value = "${state.telemetry.batteryPercent}%",
                        accent = KaaoColors.CyberEmerald
                    )
                }
                if (state.telemetry.totalRamBytes > 0L) {
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        text = "Available RAM: ${ByteFormatters.formatBytes(state.telemetry.availableRamBytes)} / ${ByteFormatters.formatBytes(state.telemetry.totalRamBytes)} (Honest OS telemetry — no fake RAM killer)",
                        style = MaterialTheme.typography.labelSmall,
                        color = KaaoColors.TextMuted
                    )
                }
            }
        }

        // Reversible Pre-Launch Checklist
        item {
            SecurityCard {
                SectionHeader(title = "Reversible Pre-Launch Checklist")
                Spacer(modifier = Modifier.height(10.dp))

                ChecklistToggleRow(
                    title = "Aegis Background Bandwidth Firewall",
                    subtitle = "Zero-root VPN excludes active game via addDisallowedApplication() and blocks background hogs",
                    checked = state.config.enableBackgroundFirewall,
                    permissionMissingLabel = if (state.permissions?.vpnConsentGranted == false) "Prompt on launch" else null,
                    onCheckedChange = { enabled ->
                        viewModel.updateConfig { it.copy(enableBackgroundFirewall = enabled) }
                    }
                )
                HorizontalDivider(color = KaaoColors.SurfaceBorder)

                ChecklistToggleRow(
                    title = "Silence Distracting Notifications (DND)",
                    subtitle = "Snapshots current DND filter and restores it after session",
                    checked = state.config.enableDndSilence,
                    permissionMissingLabel = if (state.permissions?.dndPolicyGranted == false) "Grant DND" else null,
                    onPermissionAction = { runCatching { context.startActivity(viewModel.buildDndIntent()) } },
                    onCheckedChange = { enabled ->
                        viewModel.updateConfig { it.copy(enableDndSilence = enabled) }
                    }
                )
                HorizontalDivider(color = KaaoColors.SurfaceBorder)

                ChecklistToggleRow(
                    title = "Lock Screen Brightness (${state.config.targetBrightnessPercent}%)",
                    subtitle = "Prevents adaptive brightness drops while gaming; reverts on exit",
                    checked = state.config.lockBrightness,
                    permissionMissingLabel = if (state.permissions?.writeSettingsGranted == false) "Grant Settings" else null,
                    onPermissionAction = { runCatching { context.startActivity(viewModel.buildWriteSettingsIntent()) } },
                    onCheckedChange = { enabled ->
                        viewModel.updateConfig { it.copy(lockBrightness = enabled) }
                    }
                )
                if (state.config.lockBrightness) {
                    Slider(
                        value = state.config.targetBrightnessPercent.toFloat(),
                        onValueChange = { value ->
                            viewModel.updateConfig { it.copy(targetBrightnessPercent = value.toInt()) }
                        },
                        valueRange = 20f..100f
                    )
                }
                HorizontalDivider(color = KaaoColors.SurfaceBorder)

                ChecklistToggleRow(
                    title = "Pause Background Auto-Sync",
                    subtitle = "Temporarily pauses account sync traffic during gameplay",
                    checked = state.config.pauseAutoSync,
                    onCheckedChange = { enabled ->
                        viewModel.updateConfig { it.copy(pauseAutoSync = enabled) }
                    }
                )
                HorizontalDivider(color = KaaoColors.SurfaceBorder)

                ChecklistToggleRow(
                    title = "Floating Telemetry HUD Overlay",
                    subtitle = "Draggable pill with live ping, °C, RAM & 1-tap Restore (notification fallback if denied)",
                    checked = state.config.showFloatingHud,
                    permissionMissingLabel = if (state.permissions?.overlayGranted == false) "Grant Overlay" else null,
                    onPermissionAction = { runCatching { context.startActivity(viewModel.buildOverlayIntent()) } },
                    onCheckedChange = { enabled ->
                        viewModel.updateConfig { it.copy(showFloatingHud = enabled) }
                    }
                )
            }
        }

        // Game Library Header
        item {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = "Game Library (${state.games.size})",
                    style = MaterialTheme.typography.titleMedium,
                    color = KaaoColors.TextPrimary
                )
                OutlinedButton(
                    onClick = {
                        viewModel.loadAllLaunchableAppsForPicker()
                        showAddGameDialog = true
                    }
                ) {
                    Icon(Icons.Outlined.Add, contentDescription = null)
                    Spacer(modifier = Modifier.width(4.dp))
                    Text("Add App")
                }
            }
        }

        if (state.games.isEmpty()) {
            item {
                SecurityCard {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            imageVector = Icons.Outlined.SportsEsports,
                            contentDescription = null,
                            tint = KaaoColors.BoosterViolet
                        )
                        Spacer(modifier = Modifier.width(12.dp))
                        Column {
                            Text(
                                text = "No CATEGORY_GAME Apps Detected",
                                style = MaterialTheme.typography.titleMedium,
                                color = KaaoColors.TextPrimary
                            )
                            Text(
                                text = "Games declaring Android CATEGORY_GAME appear automatically. Tap 'Add App' to add any app manually.",
                                style = MaterialTheme.typography.bodySmall,
                                color = KaaoColors.TextSecondary
                            )
                        }
                    }
                }
            }
        } else {
            items(state.games, key = { it.packageName }) { game ->
                SecurityCard(containerColor = KaaoColors.SurfaceElevated) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = game.appName,
                                style = MaterialTheme.typography.titleMedium,
                                color = KaaoColors.TextPrimary
                            )
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Text(
                                    text = game.packageName,
                                    style = MaterialTheme.typography.labelSmall,
                                    color = KaaoColors.TextMuted
                                )
                                if (game.isAutoDetected) {
                                    Spacer(modifier = Modifier.width(6.dp))
                                    StatusTag("CATEGORY_GAME", KaaoColors.BoosterViolet)
                                }
                            }
                        }
                        Spacer(modifier = Modifier.width(8.dp))
                        Button(
                            onClick = {
                                if (state.config.enableBackgroundFirewall) {
                                    val consentIntent = viewModel.buildVpnConsentIntent()
                                    if (consentIntent != null) {
                                        pendingGameLaunch = game
                                        vpnConsentLauncher.launch(consentIntent)
                                        return@Button
                                    }
                                }
                                viewModel.launchBoostedGame(game)
                            },
                            colors = ButtonDefaults.buttonColors(
                                containerColor = KaaoColors.BoosterViolet,
                                contentColor = KaaoColors.TextPrimary
                            )
                        ) {
                            Icon(Icons.Outlined.PlayArrow, contentDescription = null)
                            Spacer(modifier = Modifier.width(4.dp))
                            Text("Boost")
                        }
                    }
                }
            }
        }
    }

    if (showAddGameDialog) {
        AlertDialog(
            onDismissRequest = { showAddGameDialog = false },
            containerColor = KaaoColors.SurfaceDark,
            title = { Text("Add App to Game Booster", color = KaaoColors.TextPrimary) },
            text = {
                LazyColumn(
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(max = 320.dp),
                    verticalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    items(state.launchableApps, key = { it.packageName }) { app ->
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable {
                                    viewModel.addCustomGame(app)
                                    showAddGameDialog = false
                                }
                                .padding(vertical = 8.dp),
                            horizontalArrangement = Arrangement.SpaceBetween
                        ) {
                            Column(modifier = Modifier.weight(1f)) {
                                Text(app.appName, color = KaaoColors.TextPrimary, style = MaterialTheme.typography.bodyMedium)
                                Text(app.packageName, color = KaaoColors.TextMuted, style = MaterialTheme.typography.labelSmall)
                            }
                            Text("Add", color = KaaoColors.CyberEmerald, style = MaterialTheme.typography.labelMedium)
                        }
                    }
                }
            },
            confirmButton = {
                TextButton(onClick = { showAddGameDialog = false }) { Text("Close") }
            }
        )
    }
}

@Composable
private fun TelemetryCell(
    label: String,
    value: String,
    accent: androidx.compose.ui.graphics.Color
) {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Text(
            text = label,
            style = MaterialTheme.typography.labelSmall,
            color = KaaoColors.TextMuted
        )
        Spacer(modifier = Modifier.height(2.dp))
        Text(
            text = value,
            style = MaterialTheme.typography.titleMedium,
            color = accent,
            fontWeight = FontWeight.Bold
        )
    }
}

@Composable
private fun ChecklistToggleRow(
    title: String,
    subtitle: String,
    checked: Boolean,
    permissionMissingLabel: String? = null,
    onPermissionAction: (() -> Unit)? = null,
    onCheckedChange: (Boolean) -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 8.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(text = title, style = MaterialTheme.typography.bodyMedium, color = KaaoColors.TextPrimary, fontWeight = FontWeight.Medium)
            Text(text = subtitle, style = MaterialTheme.typography.bodySmall, color = KaaoColors.TextSecondary)
            if (permissionMissingLabel != null && onPermissionAction != null) {
                TextButton(
                    onClick = onPermissionAction,
                    contentPadding = PaddingValues(0.dp)
                ) {
                    Text(permissionMissingLabel, color = KaaoColors.WarningAmber, style = MaterialTheme.typography.labelMedium)
                }
            }
        }
        Spacer(modifier = Modifier.width(8.dp))
        Switch(
            checked = checked,
            onCheckedChange = onCheckedChange,
            colors = SwitchDefaults.colors(
                checkedThumbColor = KaaoColors.ObsidianBg,
                checkedTrackColor = KaaoColors.BoosterViolet
            )
        )
    }
}
