package com.kaao.security.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable

private val KaaoDarkColorScheme = darkColorScheme(
    primary = KaaoColors.CyberEmerald,
    onPrimary = KaaoColors.ObsidianBg,
    primaryContainer = KaaoColors.CyberEmeraldContainer,
    onPrimaryContainer = KaaoColors.CyberEmerald,
    secondary = KaaoColors.ShieldCyan,
    onSecondary = KaaoColors.ObsidianBg,
    secondaryContainer = KaaoColors.ShieldCyanContainer,
    onSecondaryContainer = KaaoColors.ShieldCyan,
    tertiary = KaaoColors.BoosterViolet,
    onTertiary = KaaoColors.TextPrimary,
    tertiaryContainer = KaaoColors.BoosterVioletContainer,
    onTertiaryContainer = KaaoColors.BoosterViolet,
    background = KaaoColors.ObsidianBg,
    onBackground = KaaoColors.TextPrimary,
    surface = KaaoColors.SurfaceDark,
    onSurface = KaaoColors.TextPrimary,
    surfaceVariant = KaaoColors.SurfaceElevated,
    onSurfaceVariant = KaaoColors.TextSecondary,
    outline = KaaoColors.SurfaceBorder,
    error = KaaoColors.ThreatCrimson,
    onError = KaaoColors.TextPrimary,
    errorContainer = KaaoColors.ThreatCrimsonContainer,
    onErrorContainer = KaaoColors.ThreatCrimson
)

@Composable
fun KaaoTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = KaaoDarkColorScheme,
        typography = KaaoTypography,
        content = content
    )
}
