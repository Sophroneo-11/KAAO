package com.kaao.security

import android.Manifest
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.SystemBarStyle
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.ArrowBack
import androidx.compose.material.icons.outlined.Settings
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationBarItemDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.navigation.NavGraph.Companion.findStartDestination
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import com.kaao.security.core.permission.PermissionManager
import com.kaao.security.ui.antivirus.AntivirusScreen
import com.kaao.security.ui.cleaner.CleanerScreen
import com.kaao.security.ui.dashboard.DashboardScreen
import com.kaao.security.ui.gamebooster.GameBoosterScreen
import com.kaao.security.ui.navigation.KaaoDestination
import com.kaao.security.ui.settings.SettingsScreen
import com.kaao.security.ui.theme.KaaoColors
import com.kaao.security.ui.theme.KaaoTheme
import com.kaao.security.ui.webshield.WebShieldScreen
import dagger.hilt.android.AndroidEntryPoint
import javax.inject.Inject

@AndroidEntryPoint
class MainActivity : ComponentActivity() {

    @Inject lateinit var permissionManager: PermissionManager

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge(
            statusBarStyle = SystemBarStyle.dark(android.graphics.Color.TRANSPARENT),
            navigationBarStyle = SystemBarStyle.dark(android.graphics.Color.TRANSPARENT)
        )
        setContent {
            KaaoTheme {
                KaaoAppScaffold(permissionManager = permissionManager)
            }
        }
    }
}

@Composable
private fun KaaoAppScaffold(permissionManager: PermissionManager) {
    val navController = rememberNavController()
    val backStackEntry by navController.currentBackStackEntryAsState()
    val currentRoute = backStackEntry?.destination?.route ?: KaaoDestination.DASHBOARD.route
    val currentDest = KaaoDestination.entries.firstOrNull { it.route == currentRoute }
        ?: KaaoDestination.DASHBOARD

    // Request notification permission softly on Android 13+ so threat alerts & shield status can display
    val notifPermLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.RequestPermission()
    ) { }

    LaunchedEffect(Unit) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU && !permissionManager.hasNotificationPermission()) {
            notifPermLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
    }

    val navigateTo: (KaaoDestination) -> Unit = { dest ->
        if (dest == KaaoDestination.SETTINGS) {
            navController.navigate(dest.route) { launchSingleTop = true }
        } else {
            navController.navigate(dest.route) {
                popUpTo(navController.graph.findStartDestination().id) {
                    saveState = true
                }
                launchSingleTop = true
                restoreState = true
            }
        }
    }

    Scaffold(
        modifier = Modifier.fillMaxSize(),
        containerColor = KaaoColors.ObsidianBg,
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        text = if (currentDest == KaaoDestination.DASHBOARD) "KAAO Security" else currentDest.label,
                        style = MaterialTheme.typography.titleLarge,
                        fontWeight = FontWeight.Bold,
                        color = KaaoColors.TextPrimary
                    )
                },
                navigationIcon = {
                    if (currentDest == KaaoDestination.SETTINGS) {
                        IconButton(onClick = { navController.popBackStack() }) {
                            Icon(
                                imageVector = Icons.AutoMirrored.Outlined.ArrowBack,
                                contentDescription = "Back",
                                tint = KaaoColors.TextPrimary
                            )
                        }
                    }
                },
                actions = {
                    if (currentDest != KaaoDestination.SETTINGS) {
                        IconButton(onClick = { navigateTo(KaaoDestination.SETTINGS) }) {
                            Icon(
                                imageVector = Icons.Outlined.Settings,
                                contentDescription = "Settings & Privacy",
                                tint = KaaoColors.TextSecondary
                            )
                        }
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = KaaoColors.ObsidianBg
                )
            )
        },
        bottomBar = {
            if (currentDest.showInBottomBar) {
                NavigationBar(
                    containerColor = KaaoColors.SurfaceDark,
                    contentColor = KaaoColors.TextPrimary
                ) {
                    KaaoDestination.entries.filter { it.showInBottomBar }.forEach { dest ->
                        val selected = currentDest == dest
                        NavigationBarItem(
                            selected = selected,
                            onClick = { navigateTo(dest) },
                            icon = { Icon(dest.icon, contentDescription = dest.label) },
                            label = { Text(dest.label, style = MaterialTheme.typography.labelSmall) },
                            colors = NavigationBarItemDefaults.colors(
                                selectedIconColor = KaaoColors.CyberEmerald,
                                selectedTextColor = KaaoColors.CyberEmerald,
                                indicatorColor = KaaoColors.CyberEmeraldContainer,
                                unselectedIconColor = KaaoColors.TextSecondary,
                                unselectedTextColor = KaaoColors.TextSecondary
                            )
                        )
                    }
                }
            }
        }
    ) { innerPadding ->
        Box(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
        ) {
            NavHost(
                navController = navController,
                startDestination = KaaoDestination.DASHBOARD.route
            ) {
                composable(KaaoDestination.DASHBOARD.route) {
                    DashboardScreen(onNavigate = navigateTo)
                }
                composable(KaaoDestination.ANTIVIRUS.route) {
                    AntivirusScreen()
                }
                composable(KaaoDestination.CLEANER.route) {
                    CleanerScreen()
                }
                composable(KaaoDestination.GAME_BOOSTER.route) {
                    GameBoosterScreen()
                }
                composable(KaaoDestination.WEB_SHIELD.route) {
                    WebShieldScreen()
                }
                composable(KaaoDestination.SETTINGS.route) {
                    SettingsScreen()
                }
            }
        }
    }
}
