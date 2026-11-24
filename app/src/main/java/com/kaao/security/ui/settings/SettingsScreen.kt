package com.kaao.security.ui.settings

import android.content.Context
import android.content.ContextWrapper
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
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.AutoAwesome
import androidx.compose.material.icons.outlined.Close
import androidx.compose.material.icons.outlined.Fingerprint
import androidx.compose.material.icons.outlined.Key
import androidx.compose.material.icons.outlined.Schedule
import androidx.compose.material.icons.outlined.VerifiedUser
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.kaao.security.core.util.ByteFormatters
import com.kaao.security.domain.model.AutoScanInterval
import com.kaao.security.ui.components.CyberGradientButton
import com.kaao.security.ui.components.SectionHeader
import com.kaao.security.ui.components.SecurityCard
import com.kaao.security.ui.components.StatusTag
import com.kaao.security.ui.theme.KaaoColors

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun SettingsScreen(
    onReplayWelcome: () -> Unit = {},
    viewModel: SettingsViewModel = hiltViewModel()
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val context = LocalContext.current
    val fragmentActivity = context.findFragmentActivity()
    var vtKeyDraft by rememberSaveable { mutableStateOf("") }
    var showImportBundleDialog by rememberSaveable { mutableStateOf(false) }
    var bundleJsonDraft by rememberSaveable { mutableStateOf("") }

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        if (!state.statusBanner.isNullOrBlank()) {
            item {
                SecurityCard(
                    borderColor = KaaoColors.CyberEmerald,
                    containerColor = KaaoColors.CyberEmeraldContainer.copy(alpha = 0.4f)
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = state.statusBanner.orEmpty(),
                            style = MaterialTheme.typography.bodySmall,
                            color = KaaoColors.TextPrimary,
                            modifier = Modifier.weight(1f)
                        )
                        TextButton(onClick = { viewModel.clearBanner() }) { Text("OK") }
                    }
                }
            }
        }

        // Hardware BiometricPrompt Security Lock Card
        item {
            SecurityCard(
                borderColor = if (state.settings.biometricLockEnabled) {
                    KaaoColors.CyberEmerald.copy(alpha = 0.6f)
                } else {
                    KaaoColors.SurfaceBorder
                }
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.weight(1f)) {
                        Icon(
                            imageVector = Icons.Outlined.Fingerprint,
                            contentDescription = null,
                            tint = KaaoColors.CyberEmerald
                        )
                        Spacer(modifier = Modifier.width(10.dp))
                        Column {
                            Text(
                                text = "Biometric Security Lock",
                                style = MaterialTheme.typography.titleMedium,
                                color = KaaoColors.TextPrimary
                            )
                            Text(
                                text = "Require hardware biometrics or device PIN on launch to protect KAAO controls & SQLCipher vault",
                                style = MaterialTheme.typography.bodySmall,
                                color = KaaoColors.TextSecondary
                            )
                        }
                    }
                    Switch(
                        checked = state.settings.biometricLockEnabled,
                        onCheckedChange = { enable ->
                            viewModel.requestBiometricLockToggle(fragmentActivity, enable)
                        },
                        colors = SwitchDefaults.colors(
                            checkedThumbColor = KaaoColors.ObsidianBg,
                            checkedTrackColor = KaaoColors.CyberEmerald
                        )
                    )
                }
                Spacer(modifier = Modifier.height(8.dp))
                StatusTag(
                    label = state.biometricCapabilityLabel,
                    accent = if (state.biometricAvailable) KaaoColors.CyberEmerald else KaaoColors.WarningAmber
                )
            }
        }

        // Configurable Auto-Scan Schedule Card
        item {
            SecurityCard(borderColor = KaaoColors.AntivirusTeal.copy(alpha = 0.45f)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        imageVector = Icons.Outlined.Schedule,
                        contentDescription = null,
                        tint = KaaoColors.AntivirusTeal
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Column {
                        Text(
                            text = "Configurable Auto-Scan Schedule",
                            style = MaterialTheme.typography.titleMedium,
                            color = KaaoColors.TextPrimary
                        )
                        Text(
                            text = "Battery-safe WorkManager antivirus & stalkerware scans • Last run: ${ByteFormatters.formatTimestamp(state.settings.lastAutoScanMillis)}",
                            style = MaterialTheme.typography.bodySmall,
                            color = KaaoColors.TextSecondary
                        )
                    }
                }
                Spacer(modifier = Modifier.height(10.dp))
                FlowRow(
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    AutoScanInterval.entries.forEach { interval ->
                        FilterChip(
                            selected = state.settings.autoScanInterval == interval,
                            onClick = { viewModel.selectAutoScanInterval(interval) },
                            label = { Text(interval.label) }
                        )
                    }
                }
            }
        }

        // Real-Time Protection Controls
        item {
            SecurityCard {
                SectionHeader(title = "Real-Time Protection & Audits")
                Spacer(modifier = Modifier.height(8.dp))

                SettingSwitchRow(
                    title = "Real-Time Package Install Shield",
                    subtitle = "Dynamic PackageInstallReceiver scans newly installed & updated apps immediately",
                    checked = state.isRealtimeRunning,
                    onCheckedChange = { viewModel.toggleRealtimeShield(it) }
                )
                HorizontalDivider(color = KaaoColors.SurfaceBorder)

                SettingSwitchRow(
                    title = "Downloads Folder inotify Monitor",
                    subtitle = "FileObserver scans newly downloaded APK/DEX/ZIP files in Downloads",
                    checked = state.settings.downloadsObserverEnabled,
                    onCheckedChange = { viewModel.toggleDownloadsObserver(it) }
                )
                HorizontalDivider(color = KaaoColors.SurfaceBorder)

                SettingSwitchRow(
                    title = "Periodic Delta Package Audit",
                    subtitle = "Battery-friendly WorkManager audit via API 26+ getChangedPackages() (seq #${state.settings.lastPackageSequenceNumber})",
                    checked = state.settings.deltaPackageAuditEnabled,
                    onCheckedChange = { viewModel.toggleDeltaPackageAudit(it) }
                )
            }
        }

        // Privacy & Hash-Only Cloud Intelligence
        item {
            SecurityCard {
                SectionHeader(title = "Privacy & Hash-Only Cloud Reputation")
                Spacer(modifier = Modifier.height(8.dp))

                SettingSwitchRow(
                    title = "Opt-In Hash-Only Cloud Lookup (MalwareBazaar)",
                    subtitle = "Transmits ONLY SHA-256 digests over certificate-pinned TLS. Raw APKs & personal files are NEVER uploaded.",
                    checked = state.settings.cloudHashLookupEnabled,
                    onCheckedChange = { viewModel.toggleCloudHashLookup(it) }
                )

                Spacer(modifier = Modifier.height(10.dp))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Outlined.Key, contentDescription = null, tint = KaaoColors.ShieldCyan)
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = "Optional VirusTotal API Key",
                        style = MaterialTheme.typography.bodyMedium,
                        color = KaaoColors.TextPrimary,
                        fontWeight = FontWeight.Medium
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    StatusTag(
                        label = if (state.settings.hasVirusTotalApiKey) "Keystore Encrypted" else "Not Set",
                        accent = if (state.settings.hasVirusTotalApiKey) KaaoColors.CyberEmerald else KaaoColors.TextMuted
                    )
                }
                Spacer(modifier = Modifier.height(6.dp))
                OutlinedTextField(
                    value = vtKeyDraft,
                    onValueChange = { vtKeyDraft = it },
                    placeholder = { Text("Enter VirusTotal v3 API key") },
                    singleLine = true,
                    visualTransformation = PasswordVisualTransformation(),
                    modifier = Modifier.fillMaxWidth()
                )
                Spacer(modifier = Modifier.height(8.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(
                        onClick = {
                            viewModel.saveVirusTotalApiKey(vtKeyDraft)
                            vtKeyDraft = ""
                        },
                        enabled = vtKeyDraft.isNotBlank(),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = KaaoColors.CyberEmerald,
                            contentColor = KaaoColors.ObsidianBg
                        )
                    ) {
                        Text("Encrypt & Save Key")
                    }
                    if (state.settings.hasVirusTotalApiKey) {
                        OutlinedButton(onClick = { viewModel.saveVirusTotalApiKey("") }) {
                            Text("Clear Key")
                        }
                    }
                }
            }
        }

        // Threat Vault & Cryptography Integrity
        item {
            SecurityCard(borderColor = KaaoColors.ShieldCyan.copy(alpha = 0.4f)) {
                SectionHeader(title = "Encrypted Vault & Cryptography")
                Spacer(modifier = Modifier.height(8.dp))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Outlined.VerifiedUser, contentDescription = null, tint = KaaoColors.CyberEmerald)
                    Spacer(modifier = Modifier.width(8.dp))
                    Column {
                        Text(
                            text = "SQLCipher 4.6.1 + Android Keystore AES-256-GCM",
                            style = MaterialTheme.typography.bodyMedium,
                            color = KaaoColors.TextPrimary
                        )
                        Text(
                            text = "Keystore: ${if (state.keystoreReady) "Active" else "Fallback"} • ${state.signatureCount} sigs • Bloom ${state.bloomBitCapacity} bits",
                            style = MaterialTheme.typography.labelSmall,
                            color = KaaoColors.ShieldCyan
                        )
                        Text(
                            text = "ECDSA-P256 Def v${state.settings.definitionVersion} • Verified ${ByteFormatters.formatTimestamp(state.settings.lastDefinitionVerifiedMillis)}",
                            style = MaterialTheme.typography.labelSmall,
                            color = KaaoColors.TextMuted
                        )
                    }
                }
                Spacer(modifier = Modifier.height(10.dp))
                CyberGradientButton(
                    text = "Check Remote Signed Definitions",
                    brush = KaaoColors.ShieldGradient,
                    onClick = { viewModel.syncRemoteDefinitions() }
                )
                Spacer(modifier = Modifier.height(6.dp))
                OutlinedButton(
                    onClick = { viewModel.rebuildAndVerifyVault() },
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text("Verify ECDSA-P256 Signature & Rebuild Bloom Filter")
                }
                Spacer(modifier = Modifier.height(6.dp))
                OutlinedButton(
                    onClick = { showImportBundleDialog = true },
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text("Import Signed JSON Definition Bundle")
                }
            }
        }

        // Cleaner Whitelist Manager
        item {
            SecurityCard {
                SectionHeader(
                    title = "Cleaner Exclusion Whitelist",
                    trailingText = "${state.cleanerWhitelist.size} protected"
                )
                Spacer(modifier = Modifier.height(8.dp))
                if (state.cleanerWhitelist.isEmpty()) {
                    Text(
                        text = "No custom paths excluded yet. Tap the shield icon next to any item in Cleaner to permanently protect it.",
                        style = MaterialTheme.typography.bodySmall,
                        color = KaaoColors.TextSecondary
                    )
                } else {
                    state.cleanerWhitelist.forEach { entry ->
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    text = entry.label,
                                    style = MaterialTheme.typography.bodyMedium,
                                    color = KaaoColors.TextPrimary
                                )
                                Text(
                                    text = entry.targetValue,
                                    style = MaterialTheme.typography.labelSmall,
                                    color = KaaoColors.TextMuted,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis
                                )
                            }
                            IconButton(onClick = { viewModel.removeWhitelistEntry(entry.id) }) {
                                Icon(Icons.Outlined.Close, contentDescription = "Remove whitelist", tint = KaaoColors.TextMuted)
                            }
                        }
                    }
                }
            }
        }

        // Just-in-Time Permission Control Center
        item {
            SecurityCard {
                SectionHeader(title = "Just-in-Time Permission Center")
                Spacer(modifier = Modifier.height(8.dp))
                val perms = state.permissions
                PermissionStatusRow(
                    title = "All Files Storage Access",
                    granted = perms?.allFilesAccessGranted == true,
                    onManage = { runCatching { context.startActivity(viewModel.buildAllFilesIntent()) } }
                )
                PermissionStatusRow(
                    title = "Usage Access (App Cache & Audit)",
                    granted = perms?.usageStatsGranted == true,
                    onManage = { runCatching { context.startActivity(viewModel.buildUsageIntent()) } }
                )
                PermissionStatusRow(
                    title = "Display Over Other Apps (Game HUD)",
                    granted = perms?.overlayGranted == true,
                    onManage = { runCatching { context.startActivity(viewModel.buildOverlayIntent()) } }
                )
                PermissionStatusRow(
                    title = "Do Not Disturb Policy (Game Silence)",
                    granted = perms?.dndPolicyGranted == true,
                    onManage = { runCatching { context.startActivity(viewModel.buildDndIntent()) } }
                )
                PermissionStatusRow(
                    title = "Modify System Settings (Brightness Lock)",
                    granted = perms?.writeSettingsGranted == true,
                    onManage = { runCatching { context.startActivity(viewModel.buildWriteSettingsIntent()) } }
                )
            }
        }

        // Replay Animated Welcome Page Card
        item {
            SecurityCard {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.weight(1f)) {
                        Icon(
                            imageVector = Icons.Outlined.AutoAwesome,
                            contentDescription = null,
                            tint = KaaoColors.BoosterViolet
                        )
                        Spacer(modifier = Modifier.width(10.dp))
                        Column {
                            Text(
                                text = "KAAO Welcome Tour",
                                style = MaterialTheme.typography.titleMedium,
                                color = KaaoColors.TextPrimary
                            )
                            Text(
                                text = "Replay the animated KAAO capability overview & quick launch screen",
                                style = MaterialTheme.typography.bodySmall,
                                color = KaaoColors.TextSecondary
                            )
                        }
                    }
                    OutlinedButton(onClick = onReplayWelcome) {
                        Text("Replay")
                    }
                }
            }
        }
    }

    if (showImportBundleDialog) {
        AlertDialog(
            onDismissRequest = { showImportBundleDialog = false },
            containerColor = KaaoColors.SurfaceDark,
            title = {
                Text(
                    text = "Import Signed Definition Bundle",
                    color = KaaoColors.TextPrimary
                )
            },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(
                        text = "Paste a KAAO SignedDefinitionBundle JSON payload. Signatures are verified with SHA256withECDSA (NIST P-256) and monotonic anti-rollback before updating the vault.",
                        style = MaterialTheme.typography.bodySmall,
                        color = KaaoColors.TextSecondary
                    )
                    OutlinedTextField(
                        value = bundleJsonDraft,
                        onValueChange = { bundleJsonDraft = it },
                        placeholder = { Text("{\"version\": ..., \"ecdsaP256SignatureBase64\": \"...\"}") },
                        minLines = 4,
                        maxLines = 8,
                        modifier = Modifier.fillMaxWidth()
                    )
                }
            },
            confirmButton = {
                Button(
                    onClick = {
                        viewModel.importSignedDefinitionBundle(bundleJsonDraft)
                        bundleJsonDraft = ""
                        showImportBundleDialog = false
                    },
                    enabled = bundleJsonDraft.isNotBlank(),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = KaaoColors.CyberEmerald,
                        contentColor = KaaoColors.ObsidianBg
                    )
                ) {
                    Text("Verify & Apply")
                }
            },
            dismissButton = {
                TextButton(onClick = { showImportBundleDialog = false }) {
                    Text("Cancel")
                }
            }
        )
    }
}

private tailrec fun Context.findFragmentActivity(): FragmentActivity? = when (this) {
    is FragmentActivity -> this
    is ContextWrapper -> baseContext.findFragmentActivity()
    else -> null
}

@Composable
private fun SettingSwitchRow(
    title: String,
    subtitle: String,
    checked: Boolean,
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
        }
        Spacer(modifier = Modifier.width(8.dp))
        Switch(
            checked = checked,
            onCheckedChange = onCheckedChange,
            colors = SwitchDefaults.colors(
                checkedThumbColor = KaaoColors.ObsidianBg,
                checkedTrackColor = KaaoColors.CyberEmerald
            )
        )
    }
}

@Composable
private fun PermissionStatusRow(
    title: String,
    granted: Boolean,
    onManage: () -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 6.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(
            text = title,
            style = MaterialTheme.typography.bodySmall,
            color = KaaoColors.TextPrimary,
            modifier = Modifier.weight(1f)
        )
        StatusTag(
            label = if (granted) "Granted" else "Optional",
            accent = if (granted) KaaoColors.CyberEmerald else KaaoColors.TextSecondary
        )
        Spacer(modifier = Modifier.width(6.dp))
        TextButton(onClick = onManage, contentPadding = PaddingValues(horizontal = 8.dp)) {
            Text("Manage")
        }
    }
}
