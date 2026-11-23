package com.kaao.security.ui.antivirus

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.CloudSync
import androidx.compose.material.icons.outlined.DeleteOutline
import androidx.compose.material.icons.outlined.GppBad
import androidx.compose.material.icons.outlined.GppGood
import androidx.compose.material.icons.outlined.Policy
import androidx.compose.material.icons.outlined.VerifiedUser
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.kaao.security.core.util.ByteFormatters
import com.kaao.security.domain.model.StalkerwareFinding
import com.kaao.security.domain.model.ThreatFinding
import com.kaao.security.ui.components.SectionHeader
import com.kaao.security.ui.components.SecurityCard
import com.kaao.security.ui.components.SeverityPill
import com.kaao.security.ui.components.StatusTag
import com.kaao.security.ui.theme.KaaoColors
import com.kaao.security.ui.theme.accentColor

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun AntivirusScreen(
    viewModel: AntivirusViewModel = hiltViewModel()
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val context = LocalContext.current
    var selectedTab by rememberSaveable { mutableIntStateOf(0) }

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        // Engine & Scan Controls Card
        item {
            SecurityCard {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column {
                        Text(
                            text = "KAAO Antivirus & Heuristic Engine",
                            style = MaterialTheme.typography.titleMedium,
                            color = KaaoColors.TextPrimary
                        )
                        Text(
                            text = "Bloom Filter (${state.signatureCount} vault sigs) • Def v${state.definitionVersion}",
                            style = MaterialTheme.typography.labelSmall,
                            color = KaaoColors.ShieldCyan
                        )
                    }
                    Icon(
                        imageVector = if (state.threats.isEmpty()) Icons.Outlined.GppGood else Icons.Outlined.GppBad,
                        contentDescription = null,
                        tint = if (state.threats.isEmpty()) KaaoColors.CyberEmerald else KaaoColors.ThreatCrimson
                    )
                }

                if (state.progress.isScanning) {
                    Spacer(modifier = Modifier.height(12.dp))
                    val fraction = if (state.progress.totalCount > 0) {
                        state.progress.scannedCount.toFloat() / state.progress.totalCount.toFloat()
                    } else {
                        0f
                    }
                    Text(
                        text = "${state.progress.stage}: ${state.progress.currentTarget}",
                        style = MaterialTheme.typography.bodySmall,
                        color = KaaoColors.TextPrimary,
                        maxLines = 1
                    )
                    Spacer(modifier = Modifier.height(6.dp))
                    LinearProgressIndicator(
                        progress = { fraction.coerceIn(0f, 1f) },
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(6.dp)
                            .clip(RoundedCornerShape(4.dp)),
                        color = KaaoColors.CyberEmerald,
                        trackColor = KaaoColors.SurfaceElevated
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = "${state.progress.scannedCount} / ${state.progress.totalCount} inspected",
                        style = MaterialTheme.typography.labelSmall,
                        color = KaaoColors.TextSecondary
                    )
                }

                Spacer(modifier = Modifier.height(14.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Button(
                        onClick = { viewModel.startQuickAppScan() },
                        enabled = !state.progress.isScanning,
                        modifier = Modifier.weight(1f),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = KaaoColors.CyberEmerald,
                            contentColor = KaaoColors.ObsidianBg
                        )
                    ) {
                        Text("Quick Scan", fontWeight = FontWeight.Bold)
                    }
                    OutlinedButton(
                        onClick = { viewModel.startDeepScanService() },
                        enabled = !state.progress.isScanning,
                        modifier = Modifier.weight(1f)
                    ) {
                        Text("Deep + APKs")
                    }
                }
                Spacer(modifier = Modifier.height(6.dp))
                OutlinedButton(
                    onClick = { viewModel.runStalkerwareAudit() },
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Icon(Icons.Outlined.Policy, contentDescription = null)
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("Audit Stalkerware Privileges Now")
                }
            }
        }

        if (!state.cloudLookupFeedback.isNullOrBlank()) {
            item {
                SecurityCard(
                    borderColor = KaaoColors.ShieldCyan,
                    containerColor = KaaoColors.ShieldCyanContainer.copy(alpha = 0.35f)
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = state.cloudLookupFeedback.orEmpty(),
                            style = MaterialTheme.typography.bodySmall,
                            color = KaaoColors.TextPrimary,
                            modifier = Modifier.weight(1f)
                        )
                        TextButton(onClick = { viewModel.clearCloudFeedback() }) {
                            Text("OK")
                        }
                    }
                }
            }
        }

        // Category Filter Tabs
        item {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                FilterChip(
                    selected = selectedTab == 0,
                    onClick = { selectedTab = 0 },
                    label = { Text("Malware & Heuristics (${state.threats.size})") }
                )
                FilterChip(
                    selected = selectedTab == 1,
                    onClick = { selectedTab = 1 },
                    label = { Text("Stalkerware Audit (${state.stalkerwareFindings.size})") }
                )
            }
        }

        if (selectedTab == 0) {
            if (state.threats.isEmpty()) {
                item {
                    SecurityCard {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(
                                imageVector = Icons.Outlined.VerifiedUser,
                                contentDescription = null,
                                tint = KaaoColors.CyberEmerald
                            )
                            Spacer(modifier = Modifier.width(12.dp))
                            Column {
                                Text(
                                    text = "No Active Malware or Suspicious APKs",
                                    style = MaterialTheme.typography.titleMedium,
                                    color = KaaoColors.CyberEmerald
                                )
                                Text(
                                    text = "All scanned packages passed Bloom filter vault & DEX heuristic analysis.",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = KaaoColors.TextSecondary
                                )
                            }
                        }
                    }
                }
            } else {
                items(state.threats, key = { it.id }) { finding ->
                    ThreatRemediationCard(
                        finding = finding,
                        onUninstall = { pkg ->
                            runCatching { context.startActivity(viewModel.buildUninstallIntent(pkg)) }
                        },
                        onVerifyCloud = { viewModel.verifyFindingInCloud(finding) },
                        onWhitelist = { pkg -> viewModel.whitelistPackage(pkg, finding.title) },
                        onDismiss = { viewModel.dismissFinding(finding.id) }
                    )
                }
            }
        } else {
            if (state.stalkerwareFindings.isEmpty()) {
                item {
                    SecurityCard {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(
                                imageVector = Icons.Outlined.VerifiedUser,
                                contentDescription = null,
                                tint = KaaoColors.CyberEmerald
                            )
                            Spacer(modifier = Modifier.width(12.dp))
                            Column {
                                Text(
                                    text = "Privilege Surface Clean",
                                    style = MaterialTheme.typography.titleMedium,
                                    color = KaaoColors.CyberEmerald
                                )
                                Text(
                                    text = "No third-party apps hold suspicious Device Admin, Accessibility, Notification Listener, or Usage Access combinations.",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = KaaoColors.TextSecondary
                                )
                            }
                        }
                    }
                }
            } else {
                items(state.stalkerwareFindings, key = { it.packageName }) { finding ->
                    StalkerwareRemediationCard(
                        finding = finding,
                        onRevokePrivilege = { priv ->
                            runCatching { context.startActivity(viewModel.buildPrivilegeRevokeIntent(priv)) }
                        },
                        onUninstall = {
                            runCatching { context.startActivity(viewModel.buildUninstallIntent(finding.packageName)) }
                        },
                        onWhitelist = {
                            viewModel.whitelistPackage(finding.packageName, finding.appName)
                        }
                    )
                }
            }
        }

        // Recent Scan History
        if (state.scanHistory.isNotEmpty()) {
            item {
                SectionHeader(title = "Recent Scan Audit Log")
                Spacer(modifier = Modifier.height(6.dp))
                SecurityCard {
                    state.scanHistory.take(5).forEachIndexed { idx, entry ->
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween
                        ) {
                            Column {
                                Text(
                                    text = entry.scanType.replace('_', ' '),
                                    style = MaterialTheme.typography.bodyMedium,
                                    color = KaaoColors.TextPrimary
                                )
                                Text(
                                    text = "${entry.scannedItems} items • ${entry.threatsFound} threats • ${entry.stalkerwareFound} privileged",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = KaaoColors.TextSecondary
                                )
                            }
                            Text(
                                text = ByteFormatters.formatTimestamp(entry.completedAtMillis),
                                style = MaterialTheme.typography.labelSmall,
                                color = KaaoColors.TextMuted
                            )
                        }
                        if (idx < minOf(state.scanHistory.size, 5) - 1) {
                            Spacer(modifier = Modifier.height(8.dp))
                            HorizontalDivider(color = KaaoColors.SurfaceBorder)
                            Spacer(modifier = Modifier.height(8.dp))
                        }
                    }
                }
            }
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun ThreatRemediationCard(
    finding: ThreatFinding,
    onUninstall: (String) -> Unit,
    onVerifyCloud: () -> Unit,
    onWhitelist: (String) -> Unit,
    onDismiss: () -> Unit
) {
    SecurityCard(borderColor = finding.severity.accentColor().copy(alpha = 0.65f)) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = finding.title,
                    style = MaterialTheme.typography.titleMedium,
                    color = KaaoColors.TextPrimary
                )
                Text(
                    text = "${finding.family} • Score ${finding.riskScore}/100",
                    style = MaterialTheme.typography.bodySmall,
                    color = finding.severity.accentColor()
                )
            }
            SeverityPill(label = finding.severity.label, severity = finding.severity)
        }
        Spacer(modifier = Modifier.height(6.dp))
        Text(
            text = "Source: ${finding.source.label} • SHA-256: ${finding.sha256.take(16)}...",
            style = MaterialTheme.typography.labelSmall,
            color = KaaoColors.TextMuted
        )
        Spacer(modifier = Modifier.height(8.dp))
        finding.reasons.forEach { reason ->
            Text(
                text = "• $reason",
                style = MaterialTheme.typography.bodySmall,
                color = KaaoColors.TextPrimary
            )
        }
        Spacer(modifier = Modifier.height(10.dp))
        FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            if (!finding.packageName.isNullOrBlank() && !finding.isSystemApp) {
                Button(
                    onClick = { onUninstall(finding.packageName) },
                    colors = ButtonDefaults.buttonColors(containerColor = KaaoColors.ThreatCrimson)
                ) {
                    Icon(Icons.Outlined.DeleteOutline, contentDescription = null)
                    Spacer(modifier = Modifier.width(4.dp))
                    Text("Uninstall")
                }
            }
            OutlinedButton(onClick = onVerifyCloud) {
                Icon(Icons.Outlined.CloudSync, contentDescription = null)
                Spacer(modifier = Modifier.width(4.dp))
                Text("Cloud Hash Check")
            }
            if (!finding.packageName.isNullOrBlank()) {
                TextButton(onClick = { onWhitelist(finding.packageName) }) {
                    Text("Trust App")
                }
            } else {
                TextButton(onClick = onDismiss) {
                    Text("Dismiss")
                }
            }
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun StalkerwareRemediationCard(
    finding: StalkerwareFinding,
    onRevokePrivilege: (com.kaao.security.domain.model.StalkerwarePrivilege) -> Unit,
    onUninstall: () -> Unit,
    onWhitelist: () -> Unit
) {
    SecurityCard(borderColor = finding.severity.accentColor().copy(alpha = 0.65f)) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = finding.appName,
                    style = MaterialTheme.typography.titleMedium,
                    color = KaaoColors.TextPrimary
                )
                Text(
                    text = "${finding.packageName} • ${finding.installerSource}",
                    style = MaterialTheme.typography.bodySmall,
                    color = KaaoColors.TextSecondary
                )
            }
            SeverityPill(label = "${finding.riskScore}/100", severity = finding.severity)
        }
        Spacer(modifier = Modifier.height(8.dp))
        FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            finding.privileges.forEach { priv ->
                StatusTag(label = priv.label, accent = KaaoColors.WarningAmber)
            }
            if (!finding.hasLauncherIcon) {
                StatusTag(label = "Hidden Icon", accent = KaaoColors.ThreatCrimson)
            }
        }
        Spacer(modifier = Modifier.height(8.dp))
        Text(
            text = finding.advisory,
            style = MaterialTheme.typography.bodySmall,
            color = KaaoColors.TextPrimary
        )
        Spacer(modifier = Modifier.height(10.dp))
        FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            finding.privileges.firstOrNull()?.let { primaryPriv ->
                Button(
                    onClick = { onRevokePrivilege(primaryPriv) },
                    colors = ButtonDefaults.buttonColors(
                        containerColor = KaaoColors.WarningAmber,
                        contentColor = KaaoColors.ObsidianBg
                    )
                ) {
                    Text("Revoke ${primaryPriv.label}")
                }
            }
            OutlinedButton(onClick = onUninstall) {
                Text("Uninstall")
            }
            TextButton(onClick = onWhitelist) {
                Text("Trust")
            }
        }
    }
}
