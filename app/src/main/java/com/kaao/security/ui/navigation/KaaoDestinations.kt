package com.kaao.security.ui.navigation

import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.CleaningServices
import androidx.compose.material.icons.outlined.Dashboard
import androidx.compose.material.icons.outlined.Security
import androidx.compose.material.icons.outlined.Settings
import androidx.compose.material.icons.outlined.SportsEsports
import androidx.compose.material.icons.outlined.VpnLock
import androidx.compose.ui.graphics.vector.ImageVector

enum class KaaoDestination(
    val route: String,
    val label: String,
    val icon: ImageVector,
    val showInBottomBar: Boolean = true
) {
    DASHBOARD("dashboard", "Home", Icons.Outlined.Dashboard),
    ANTIVIRUS("antivirus", "Scan", Icons.Outlined.Security),
    CLEANER("cleaner", "Cleaner", Icons.Outlined.CleaningServices),
    GAME_BOOSTER("booster", "Booster", Icons.Outlined.SportsEsports),
    WEB_SHIELD("shield", "Shield", Icons.Outlined.VpnLock),
    SETTINGS("settings", "Settings", Icons.Outlined.Settings, showInBottomBar = false)
}
