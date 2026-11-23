package com.kaao.security.ui.theme

import androidx.compose.ui.graphics.Color
import com.kaao.security.domain.model.ThreatSeverity

object KaaoColors {
    val ObsidianBg = Color(0xFF0A0E17)
    val SurfaceDark = Color(0xFF111827)
    val SurfaceElevated = Color(0xFF182234)
    val SurfaceBorder = Color(0xFF263449)

    val CyberEmerald = Color(0xFF00E5A0)
    val CyberEmeraldContainer = Color(0xFF063A2B)
    val ShieldCyan = Color(0xFF38BDF8)
    val ShieldCyanContainer = Color(0xFF0A2E44)
    val BoosterViolet = Color(0xFFA855F7)
    val BoosterVioletContainer = Color(0xFF2D1647)

    val WarningAmber = Color(0xFFF59E0B)
    val WarningAmberContainer = Color(0xFF3E2A06)
    val ThreatCrimson = Color(0xFFEF4444)
    val ThreatCrimsonContainer = Color(0xFF451217)

    val TextPrimary = Color(0xFFF1F5F9)
    val TextSecondary = Color(0xFF94A3B8)
    val TextMuted = Color(0xFF64748B)
}

fun ThreatSeverity.accentColor(): Color = when (this) {
    ThreatSeverity.SAFE -> KaaoColors.CyberEmerald
    ThreatSeverity.LOW -> KaaoColors.ShieldCyan
    ThreatSeverity.MEDIUM -> KaaoColors.WarningAmber
    ThreatSeverity.HIGH -> Color(0xFFF97316)
    ThreatSeverity.CRITICAL -> KaaoColors.ThreatCrimson
}

fun ThreatSeverity.containerColor(): Color = when (this) {
    ThreatSeverity.SAFE -> KaaoColors.CyberEmeraldContainer
    ThreatSeverity.LOW -> KaaoColors.ShieldCyanContainer
    ThreatSeverity.MEDIUM -> KaaoColors.WarningAmberContainer
    ThreatSeverity.HIGH -> Color(0xFF431E09)
    ThreatSeverity.CRITICAL -> KaaoColors.ThreatCrimsonContainer
}
