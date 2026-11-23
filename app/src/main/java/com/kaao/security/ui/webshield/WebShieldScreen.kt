package com.kaao.security.ui.webshield

import android.app.Activity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
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
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Close
import androidx.compose.material.icons.outlined.Refresh
import androidx.compose.material.icons.outlined.VpnLock
import androidx.compose.material.icons.outlined.Wifi
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
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.kaao.security.core.util.ByteFormatters
import com.kaao.security.domain.model.AegisVpnMode
import com.kaao.security.domain.model.DohProvider
import com.kaao.security.ui.components.SectionHeader
import com.kaao.security.ui.components.SecurityCard
import com.kaao.security.ui.components.StatusTag
import com.kaao.security.ui.theme.KaaoColors

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun WebShieldScreen(
    viewModel: WebShieldViewModel = hiltViewModel()
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    var customDomainInput by rememberSaveable { mutableStateOf("") }

    val vpnConsentLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            viewModel.startDnsShield()
        }
    }

    val isDnsActive = state.vpnState.mode == AegisVpnMode.DNS_SHIELD

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        // Aegis Zero-Root DNS Shield Master Card
        item {
            SecurityCard(
                borderColor = if (isDnsActive) KaaoColors.CyberEmerald else KaaoColors.SurfaceBorder
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.weight(1f)) {
                        Icon(
                            imageVector = Icons.Outlined.VpnLock,
                            contentDescription = null,
                            tint = if (isDnsActive) KaaoColors.CyberEmerald else KaaoColors.ShieldCyan
                        )
                        Spacer(modifier = Modifier.width(10.dp))
                        Column {
                            Text(
                                text = "Aegis Zero-Root DoH Shield",
                                style = MaterialTheme.typography.titleMedium,
                                color = KaaoColors.TextPrimary
                            )
                            Text(
                                text = "Split-routed RFC 8484 DNS-over-HTTPS sinkhole",
                                style = MaterialTheme.typography.bodySmall,
                                color = KaaoColors.TextSecondary
                            )
                        }
                    }
                    Switch(
                        checked = isDnsActive,
                        onCheckedChange = { enable ->
                            if (enable) {
                                val consent = viewModel.buildVpnConsentIntent()
                                if (consent != null) {
                                    vpnConsentLauncher.launch(consent)
                                } else {
                                    viewModel.startDnsShield()
                                }
                            } else {
                                viewModel.stopVpn()
                            }
                        },
                        colors = SwitchDefaults.colors(
                            checkedThumbColor = KaaoColors.ObsidianBg,
                            checkedTrackColor = KaaoColors.CyberEmerald
                        )
                    )
                }

                Spacer(modifier = Modifier.height(10.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    StatusTag(
                        label = state.vpnState.mode.label,
                        accent = if (isDnsActive) KaaoColors.CyberEmerald else KaaoColors.TextSecondary
                    )
                    Text(
                        text = "${state.vpnState.queriesProcessed} session • ${state.totalBlocked} total blocked",
                        style = MaterialTheme.typography.labelSmall,
                        color = KaaoColors.ShieldCyan
                    )
                }

                Spacer(modifier = Modifier.height(12.dp))
                Text(
                    text = "Encrypted Upstream Resolver (Certificate-Pinned)",
                    style = MaterialTheme.typography.labelMedium,
                    color = KaaoColors.TextSecondary
                )
                Spacer(modifier = Modifier.height(6.dp))
                FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    DohProvider.entries.forEach { provider ->
                        FilterChip(
                            selected = state.settings.dohProvider == provider,
                            onClick = { viewModel.selectDohProvider(provider) },
                            label = { Text(provider.displayName) }
                        )
                    }
                }

                Spacer(modifier = Modifier.height(10.dp))
                Text(
                    text = "Sinkhole Filter Categories",
                    style = MaterialTheme.typography.labelMedium,
                    color = KaaoColors.TextSecondary
                )
                Spacer(modifier = Modifier.height(6.dp))
                FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    FilterChip(
                        selected = state.settings.blockPhishing,
                        onClick = {
                            viewModel.updateFilterCategories(
                                phishing = !state.settings.blockPhishing,
                                malware = state.settings.blockMalware,
                                adware = state.settings.blockAdware
                            )
                        },
                        label = { Text("Phishing") }
                    )
                    FilterChip(
                        selected = state.settings.blockMalware,
                        onClick = {
                            viewModel.updateFilterCategories(
                                phishing = state.settings.blockPhishing,
                                malware = !state.settings.blockMalware,
                                adware = state.settings.blockAdware
                            )
                        },
                        label = { Text("Malware & C2") }
                    )
                    FilterChip(
                        selected = state.settings.blockAdware,
                        onClick = {
                            viewModel.updateFilterCategories(
                                phishing = state.settings.blockPhishing,
                                malware = state.settings.blockMalware,
                                adware = !state.settings.blockAdware
                            )
                        },
                        label = { Text("Adware & Trackers") }
                    )
                }
            }
        }

        // Wi-Fi Security Inspector Card
        item {
            SecurityCard {
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
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = "Wi-Fi Security Inspector",
                            style = MaterialTheme.typography.titleMedium,
                            color = KaaoColors.TextPrimary
                        )
                    }
                    IconButton(onClick = { viewModel.inspectWifi() }) {
                        Icon(
                            imageVector = Icons.Outlined.Refresh,
                            contentDescription = "Re-inspect Wi-Fi",
                            tint = KaaoColors.ShieldCyan
                        )
                    }
                }

                val wifi = state.wifiAudit
                Spacer(modifier = Modifier.height(8.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = wifi.ssid,
                            style = MaterialTheme.typography.titleMedium,
                            color = KaaoColors.TextPrimary
                        )
                        Text(
                            text = "Protocol: ${wifi.protocol.label} • ${wifi.frequencyBand} • ${wifi.linkSpeedMbps} Mbps",
                            style = MaterialTheme.typography.bodySmall,
                            color = KaaoColors.TextSecondary
                        )
                    }
                    StatusTag(
                        label = "${wifi.safetyScore}/100",
                        accent = when {
                            wifi.safetyScore >= 80 -> KaaoColors.CyberEmerald
                            wifi.safetyScore >= 55 -> KaaoColors.WarningAmber
                            else -> KaaoColors.ThreatCrimson
                        }
                    )
                }

                Spacer(modifier = Modifier.height(8.dp))
                FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    StatusTag(
                        label = if (wifi.isCaptivePortal) "Captive Portal Detected" else "No Captive Portal",
                        accent = if (wifi.isCaptivePortal) KaaoColors.WarningAmber else KaaoColors.CyberEmerald
                    )
                    StatusTag(
                        label = if (wifi.hasSuspiciousDnsOverride) "DNS Override Warning" else "DNS Clean",
                        accent = if (wifi.hasSuspiciousDnsOverride) KaaoColors.ThreatCrimson else KaaoColors.CyberEmerald
                    )
                    StatusTag(
                        label = if (wifi.isPrivateDnsActive) "Private DNS On" else "Private DNS Off",
                        accent = if (wifi.isPrivateDnsActive) KaaoColors.ShieldCyan else KaaoColors.TextSecondary
                    )
                }

                if (wifi.dnsServers.isNotEmpty()) {
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        text = "Active DNS: ${wifi.dnsServers.joinToString(", ")}",
                        style = MaterialTheme.typography.labelSmall,
                        color = KaaoColors.TextMuted
                    )
                }
                if (wifi.advisories.isNotEmpty()) {
                    Spacer(modifier = Modifier.height(8.dp))
                    wifi.advisories.forEach { advisory ->
                        Text(
                            text = "• $advisory",
                            style = MaterialTheme.typography.bodySmall,
                            color = KaaoColors.TextPrimary
                        )
                    }
                }
            }
        }

        // Custom Domain Block / Allow Rules
        item {
            SecurityCard {
                SectionHeader(title = "Custom Domain Rules")
                Spacer(modifier = Modifier.height(8.dp))
                OutlinedTextField(
                    value = customDomainInput,
                    onValueChange = { customDomainInput = it },
                    placeholder = { Text("example.com") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
                Spacer(modifier = Modifier.height(8.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Button(
                        onClick = {
                            viewModel.addCustomRule(customDomainInput, allow = false)
                            customDomainInput = ""
                        },
                        modifier = Modifier.weight(1f),
                        colors = ButtonDefaults.buttonColors(containerColor = KaaoColors.ThreatCrimson)
                    ) {
                        Text("Block Domain")
                    }
                    OutlinedButton(
                        onClick = {
                            viewModel.addCustomRule(customDomainInput, allow = true)
                            customDomainInput = ""
                        },
                        modifier = Modifier.weight(1f)
                    ) {
                        Text("Allow Domain")
                    }
                }
                if (state.customRules.isNotEmpty()) {
                    Spacer(modifier = Modifier.height(10.dp))
                    state.customRules.forEach { rule ->
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.weight(1f)) {
                                StatusTag(
                                    label = if (rule.category == "CUSTOM_ALLOW") "ALLOW" else "BLOCK",
                                    accent = if (rule.category == "CUSTOM_ALLOW") KaaoColors.CyberEmerald else KaaoColors.ThreatCrimson
                                )
                                Spacer(modifier = Modifier.width(8.dp))
                                Text(
                                    text = rule.domain,
                                    style = MaterialTheme.typography.bodySmall,
                                    color = KaaoColors.TextPrimary,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis
                                )
                            }
                            IconButton(onClick = { viewModel.removeCustomRule(rule.domain) }) {
                                Icon(Icons.Outlined.Close, contentDescription = "Remove rule", tint = KaaoColors.TextMuted)
                            }
                        }
                    }
                }
            }
        }

        // Live DNS Query Log
        item {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = "Live DNS Query Log (${state.recentQueries.size})",
                    style = MaterialTheme.typography.titleMedium,
                    color = KaaoColors.TextPrimary
                )
                if (state.recentQueries.isNotEmpty()) {
                    TextButton(onClick = { viewModel.clearLogs() }) {
                        Text("Clear")
                    }
                }
            }
        }

        if (state.recentQueries.isEmpty()) {
            item {
                SecurityCard {
                    Text(
                        text = "Enable Aegis DoH Shield to monitor and filter DNS lookups locally in real time.",
                        style = MaterialTheme.typography.bodySmall,
                        color = KaaoColors.TextSecondary
                    )
                }
            }
        } else {
            items(state.recentQueries.take(40), key = { it.id }) { event ->
                SecurityCard(containerColor = KaaoColors.SurfaceElevated) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = event.domain,
                                style = MaterialTheme.typography.bodyMedium,
                                color = KaaoColors.TextPrimary,
                                fontWeight = FontWeight.Medium,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis
                            )
                            Text(
                                text = "${event.queryType} • ${event.latencyMs}ms • ${ByteFormatters.formatShortTime(event.timestampMillis)}",
                                style = MaterialTheme.typography.labelSmall,
                                color = KaaoColors.TextMuted
                            )
                        }
                        Spacer(modifier = Modifier.width(8.dp))
                        Column(horizontalAlignment = Alignment.End) {
                            StatusTag(
                                label = if (event.blocked) "BLOCKED (${event.category})" else "ALLOWED",
                                accent = if (event.blocked) KaaoColors.ThreatCrimson else KaaoColors.CyberEmerald
                            )
                            TextButton(
                                onClick = { viewModel.addCustomRule(event.domain, allow = event.blocked) },
                                contentPadding = PaddingValues(0.dp)
                            ) {
                                Text(
                                    text = if (event.blocked) "Allow" else "Block",
                                    style = MaterialTheme.typography.labelSmall
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}
