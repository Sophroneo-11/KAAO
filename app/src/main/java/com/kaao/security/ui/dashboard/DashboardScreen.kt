package com.kaao.security.ui.dashboard

import androidx.compose.foundation.clickable
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
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.CheckCircle
import androidx.compose.material.icons.outlined.CleaningServices
import androidx.compose.material.icons.outlined.Radar
import androidx.compose.material.icons.outlined.Security
import androidx.compose.material.icons.outlined.SportsEsports
import androidx.compose.material.icons.outlined.VpnLock
import androidx.compose.material.icons.outlined.Wifi
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.kaao.security.core.util.ByteFormatters
import com.kaao.security.domain.model.AegisVpnMode
import com.kaao.security.ui.components.CyberGradientButton
import com.kaao.security.ui.components.HealthScoreGauge
import com.kaao.security.ui.components.ScoreComponentRow
import com.kaao.security.ui.components.SectionHeader
import com.kaao.security.ui.components.SecurityCard
import com.kaao.security.ui.components.StatusTag
import com.kaao.security.ui.navigation.KaaoDestination
import com.kaao.security.ui.theme.KaaoColors

@Composable
fun DashboardScreen(
    onNavigate: (KaaoDestination) -> Unit,
    viewModel: DashboardViewModel = hiltViewModel()
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    var showFormulaBreakdown by rememberSaveable { mutableStateOf(true) }

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        // Active Game Session quick-restore banner
        if (state.activeGameSession.isActive) {
            item {
                SecurityCard(
                    borderColor = KaaoColors.BoosterMagenta,
                    containerColor = KaaoColors.BoosterVioletContainer.copy(alpha = 0.5f)
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = "Game Booster Session Active",
                                style = MaterialTheme.typography.titleMedium,
                                color = KaaoColors.BoosterMagenta
                            )
                            Text(
                                text = state.activeGameSession.activeGameName ?: "Game Mode",
                                style = MaterialTheme.typography.bodySmall,
                                color = KaaoColors.TextPrimary
                            )
                        }
                        OutlinedButton(onClick = { viewModel.restoreActiveGameSession() }) {
                            Text("Restore Settings")
                        }
                    }
                }
            }
        }

        // Transparent 0-100 Health Score Hero Card + Concurrent Smart Scan CTA
        item {
            SecurityCard(
                borderColor = KaaoColors.CyberEmerald.copy(alpha = 0.35f)
            ) {
                Column(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    Text(
                        text = "DEVICE SECURITY POSTURE",
                        style = MaterialTheme.typography.labelMedium,
                        color = KaaoColors.ShieldCyan
                    )
                    Spacer(modifier = Modifier.height(10.dp))
                    HealthScoreGauge(
                        score = state.healthReport.totalScore,
                        gradeLabel = state.healthReport.gradeLabel,
                        severity = state.healthReport.severity
                    )
                    Spacer(modifier = Modifier.height(10.dp))
                    Text(
                        text = state.smartScan.summaryMessage,
                        style = MaterialTheme.typography.bodySmall,
                        color = KaaoColors.TextSecondary
                    )
                    Spacer(modifier = Modifier.height(14.dp))

                    CyberGradientButton(
                        text = if (state.smartScan.isRunning) {
                            "Running Concurrent Smart Scan..."
                        } else {
                            "Run Concurrent Smart Scan"
                        },
                        icon = Icons.Outlined.Radar,
                        brush = KaaoColors.PrimaryActionGradient,
                        isLoading = state.smartScan.isRunning,
                        onClick = { viewModel.runSmartScan() }
                    )

                    if (state.smartScan.isRunning) {
                        Spacer(modifier = Modifier.height(12.dp))
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween
                        ) {
                            ScanChip("Antivirus", state.smartScan.antivirusDone)
                            ScanChip("Stalkerware", state.smartScan.stalkerwareDone)
                            ScanChip("Wi-Fi", state.smartScan.wifiDone)
                            ScanChip("Storage", state.smartScan.storageDone)
                        }
                    }
                }
            }
        }

        // Transparent Health Score Breakdown
        item {
            SecurityCard {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable { showFormulaBreakdown = !showFormulaBreakdown },
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    SectionHeader(
                        title = "Transparent Score Breakdown",
                        trailingText = if (showFormulaBreakdown) "Hide" else "Show",
                        accentColor = KaaoColors.ShieldCyan
                    )
                }
                if (showFormulaBreakdown) {
                    Spacer(modifier = Modifier.height(12.dp))
                    state.healthReport.components.forEachIndexed { index, component ->
                        ScoreComponentRow(component)
                        if (index < state.healthReport.components.lastIndex) {
                            Spacer(modifier = Modifier.height(10.dp))
                        }
                    }
                }
            }
        }

        // Real-Time Protection Toggle Card
        item {
            SecurityCard(
                borderColor = if (state.isRealtimeShieldActive) {
                    KaaoColors.CyberEmerald.copy(alpha = 0.55f)
                } else {
                    KaaoColors.SurfaceBorder
                }
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = "Real-Time Install & Downloads Shield",
                            style = MaterialTheme.typography.titleMedium,
                            color = KaaoColors.TextPrimary
                        )
                        Spacer(modifier = Modifier.height(2.dp))
                        Text(
                            text = "Monitors new package installs & Downloads via inotify",
                            style = MaterialTheme.typography.bodySmall,
                            color = KaaoColors.TextSecondary
                        )
                    }
                    Switch(
                        checked = state.isRealtimeShieldActive,
                        onCheckedChange = { viewModel.toggleRealtimeShield(it) },
                        colors = SwitchDefaults.colors(
                            checkedThumbColor = KaaoColors.ObsidianBg,
                            checkedTrackColor = KaaoColors.CyberEmerald
                        )
                    )
                }
            }
        }

        // 2x2 Color-Coded Module Navigation Grid
        item {
            SectionHeader(title = "Protection Modules")
            Spacer(modifier = Modifier.height(8.dp))
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                ModuleQuickTile(
                    modifier = Modifier.weight(1f),
                    icon = Icons.Outlined.Security,
                    title = "Antivirus",
                    metric = "${state.threatCount} threats • ${state.stalkerwareCount} priv",
                    accent = if (state.threatCount == 0) KaaoColors.CyberEmerald else KaaoColors.ThreatCrimson,
                    onClick = { onNavigate(KaaoDestination.ANTIVIRUS) }
                )
                ModuleQuickTile(
                    modifier = Modifier.weight(1f),
                    icon = Icons.Outlined.VpnLock,
                    title = "Web Shield",
                    metric = if (state.vpnState.mode == AegisVpnMode.DNS_SHIELD) {
                        "DoH On • ${state.blockedQueriesTotal} blk"
                    } else {
                        state.vpnState.mode.label
                    },
                    accent = KaaoColors.ShieldCyan,
                    onClick = { onNavigate(KaaoDestination.WEB_SHIELD) }
                )
            }
            Spacer(modifier = Modifier.height(12.dp))
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                ModuleQuickTile(
                    modifier = Modifier.weight(1f),
                    icon = Icons.Outlined.CleaningServices,
                    title = "Deep Cleaner",
                    metric = "${ByteFormatters.formatBytes(state.reclaimableBytes)} reclaimable",
                    accent = KaaoColors.CleanerCobalt,
                    onClick = { onNavigate(KaaoDestination.CLEANER) }
                )
                ModuleQuickTile(
                    modifier = Modifier.weight(1f),
                    icon = Icons.Outlined.SportsEsports,
                    title = "Game Booster",
                    metric = if (state.activeGameSession.isActive) "Session Active" else "Zero-Root Firewall",
                    accent = KaaoColors.BoosterViolet,
                    onClick = { onNavigate(KaaoDestination.GAME_BOOSTER) }
                )
            }
        }

        // Wi-Fi Quick Posture
        item {
            SecurityCard(
                modifier = Modifier.clickable { onNavigate(KaaoDestination.WEB_SHIELD) }
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            imageVector = Icons.Outlined.Wifi,
                            contentDescription = null,
                            tint = KaaoColors.ShieldCyan
                        )
                        Spacer(modifier = Modifier.width(10.dp))
                        Column {
                            Text(
                                text = state.wifiAudit.ssid,
                                style = MaterialTheme.typography.titleMedium,
                                color = KaaoColors.TextPrimary
                            )
                            Text(
                                text = "${state.wifiAudit.protocol.label} • ${state.wifiAudit.frequencyBand}",
                                style = MaterialTheme.typography.bodySmall,
                                color = KaaoColors.TextSecondary
                            )
                        }
                    }
                    StatusTag(
                        label = "${state.wifiAudit.safetyScore}/100",
                        accent = if (state.wifiAudit.safetyScore >= 80) KaaoColors.CyberEmerald else KaaoColors.WarningAmber
                    )
                }
                if (state.smartScan.lastCompletedMillis > 0L) {
                    Spacer(modifier = Modifier.height(8.dp))
                    HorizontalDivider(color = KaaoColors.SurfaceBorder)
                    Spacer(modifier = Modifier.height(6.dp))
                    Text(
                        text = "Last full scan: ${ByteFormatters.formatTimestamp(state.smartScan.lastCompletedMillis)}",
                        style = MaterialTheme.typography.labelSmall,
                        color = KaaoColors.TextMuted
                    )
                }
            }
        }
    }
}

@Composable
private fun ScanChip(label: String, done: Boolean) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        if (done) {
            Icon(
                imageVector = Icons.Outlined.CheckCircle,
                contentDescription = null,
                tint = KaaoColors.CyberEmerald,
                modifier = Modifier.size(14.dp)
            )
        } else {
            CircularProgressIndicator(
                modifier = Modifier.size(12.dp),
                strokeWidth = 1.5.dp,
                color = KaaoColors.ShieldCyan
            )
        }
        Spacer(modifier = Modifier.width(4.dp))
        Text(
            text = label,
            style = MaterialTheme.typography.labelSmall,
            color = if (done) KaaoColors.CyberEmerald else KaaoColors.TextSecondary
        )
    }
}

@Composable
private fun ModuleQuickTile(
    modifier: Modifier,
    icon: ImageVector,
    title: String,
    metric: String,
    accent: Color,
    onClick: () -> Unit
) {
    SecurityCard(
        modifier = modifier.clickable(onClick = onClick),
        borderColor = accent.copy(alpha = 0.4f),
        containerColor = KaaoColors.SurfaceElevated
    ) {
        Icon(
            imageVector = icon,
            contentDescription = title,
            tint = accent,
            modifier = Modifier.size(24.dp)
        )
        Spacer(modifier = Modifier.height(10.dp))
        Text(
            text = title,
            style = MaterialTheme.typography.titleMedium,
            color = KaaoColors.TextPrimary
        )
        Spacer(modifier = Modifier.height(2.dp))
        Text(
            text = metric,
            style = MaterialTheme.typography.bodySmall,
            color = accent
        )
    }
}
