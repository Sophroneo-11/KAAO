package com.kaao.security.ui.theme

import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import com.kaao.security.domain.model.ThreatSeverity

/**
 * KAAO v1.1 Vivid Multi-Module Cyber Color System on Deep Obsidian (#070B12).
 * - Antivirus: Emerald (#00F0A8) -> Teal (#00C4B4)
 * - Storage Cleaner: Cobalt (#3B82F6) -> Cyan (#06B6D4)
 * - Game Booster: Neon Violet (#A855F7) -> Magenta (#EC4899)
 * - Web Shield: Cyber Cyan (#00E5FF) -> Sky (#0EA5E9)
 */
object KaaoColors {
    // Deep Obsidian Canvas & Elevated Surfaces
    val ObsidianBg = Color(0xFF070B12)
    val SurfaceDark = Color(0xFF0E1525)
    val SurfaceElevated = Color(0xFF141E33)
    val SurfaceBorder = Color(0xFF22314A)

    // Antivirus — Emerald / Teal
    val CyberEmerald = Color(0xFF00F0A8)
    val AntivirusTeal = Color(0xFF00C4B4)
    val CyberEmeraldContainer = Color(0xFF06342A)

    // Storage Cleaner — Cobalt / Cyan
    val CleanerCobalt = Color(0xFF3B82F6)
    val CleanerCyan = Color(0xFF06B6D4)
    val CleanerContainer = Color(0xFF0B2748)

    // Game Booster — Neon Violet / Magenta
    val BoosterViolet = Color(0xFFA855F7)
    val BoosterMagenta = Color(0xFFEC4899)
    val BoosterVioletContainer = Color(0xFF2F1246)

    // Web Shield — Cyber Cyan
    val ShieldCyan = Color(0xFF00E5FF)
    val ShieldSky = Color(0xFF0EA5E9)
    val ShieldCyanContainer = Color(0xFF062F44)

    // Status & Severity Accents
    val WarningAmber = Color(0xFFF59E0B)
    val WarningAmberContainer = Color(0xFF3E2A06)
    val ThreatCrimson = Color(0xFFFF4D6D)
    val ThreatCrimsonContainer = Color(0xFF471221)

    // Typography
    val TextPrimary = Color(0xFFF8FAFC)
    val TextSecondary = Color(0xFF94A3B8)
    val TextMuted = Color(0xFF64748B)

    // Module Gradients
    val AntivirusGradient: Brush = Brush.horizontalGradient(listOf(CyberEmerald, AntivirusTeal))
    val CleanerGradient: Brush = Brush.horizontalGradient(listOf(CleanerCobalt, CleanerCyan))
    val BoosterGradient: Brush = Brush.horizontalGradient(listOf(BoosterViolet, BoosterMagenta))
    val ShieldGradient: Brush = Brush.horizontalGradient(listOf(ShieldCyan, ShieldSky))
    val BrandWordmarkGradient: Brush = Brush.horizontalGradient(
        listOf(CyberEmerald, ShieldCyan, BoosterViolet, BoosterMagenta)
    )
    val PrimaryActionGradient: Brush = Brush.horizontalGradient(
        listOf(CyberEmerald, ShieldCyan)
    )
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
