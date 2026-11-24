package com.kaao.security.ui.navigation

import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.CleaningServices
import androidx.compose.material.icons.outlined.Dashboard
import androidx.compose.material.icons.outlined.Security
import androidx.compose.material.icons.outlined.Settings
import androidx.compose.material.icons.outlined.SportsEsports
import androidx.compose.material.icons.outlined.VpnLock
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import com.kaao.security.ui.theme.KaaoColors

enum class KaaoDestination(
    val route: String,
    val label: String,
    val icon: ImageVector,
    val accentColor: Color,
    val indicatorContainer: Color,
    val showInBottomBar: Boolean = true
) {
    WELCOME(
        route = "welcome",
        label = "Welcome",
        icon = Icons.Outlined.Security,
        accentColor = KaaoColors.CyberEmerald,
        indicatorContainer = KaaoColors.CyberEmeraldContainer,
        showInBottomBar = false
    ),
    DASHBOARD(
        route = "dashboard",
        label = "Home",
        icon = Icons.Outlined.Dashboard,
        accentColor = KaaoColors.CyberEmerald,
        indicatorContainer = KaaoColors.CyberEmeraldContainer
    ),
    ANTIVIRUS(
        route = "antivirus",
        label = "Scan",
        icon = Icons.Outlined.Security,
        accentColor = KaaoColors.AntivirusTeal,
        indicatorContainer = KaaoColors.CyberEmeraldContainer
    ),
    CLEANER(
        route = "cleaner",
        label = "Cleaner",
        icon = Icons.Outlined.CleaningServices,
        accentColor = KaaoColors.CleanerCobalt,
        indicatorContainer = KaaoColors.CleanerContainer
    ),
    GAME_BOOSTER(
        route = "booster",
        label = "Booster",
        icon = Icons.Outlined.SportsEsports,
        accentColor = KaaoColors.BoosterViolet,
        indicatorContainer = KaaoColors.BoosterVioletContainer
    ),
    WEB_SHIELD(
        route = "shield",
        label = "Shield",
        icon = Icons.Outlined.VpnLock,
        accentColor = KaaoColors.ShieldCyan,
        indicatorContainer = KaaoColors.ShieldCyanContainer
    ),
    SETTINGS(
        route = "settings",
        label = "Settings",
        icon = Icons.Outlined.Settings,
        accentColor = KaaoColors.ShieldCyan,
        indicatorContainer = KaaoColors.ShieldCyanContainer,
        showInBottomBar = false
    )
}
