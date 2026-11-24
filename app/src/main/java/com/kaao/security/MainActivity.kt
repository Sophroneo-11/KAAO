package com.kaao.security

import android.Manifest
import android.os.Build
import android.os.Bundle
import androidx.activity.SystemBarStyle
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.ArrowBack
import androidx.compose.material.icons.outlined.Fingerprint
import androidx.compose.material.icons.outlined.Settings
import androidx.compose.material3.CircularProgressIndicator
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
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation.NavGraph.Companion.findStartDestination
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import com.kaao.security.core.permission.PermissionManager
import com.kaao.security.core.security.BiometricLockManager
import com.kaao.security.data.local.prefs.KaaoPreferencesRepository
import com.kaao.security.ui.antivirus.AntivirusScreen
import com.kaao.security.ui.cleaner.CleanerScreen
import com.kaao.security.ui.components.CyberGradientButton
import com.kaao.security.ui.dashboard.DashboardScreen
import com.kaao.security.ui.gamebooster.GameBoosterScreen
import com.kaao.security.ui.navigation.KaaoDestination
import com.kaao.security.ui.settings.SettingsScreen
import com.kaao.security.ui.theme.KaaoColors
import com.kaao.security.ui.theme.KaaoTheme
import com.kaao.security.ui.webshield.WebShieldScreen
import com.kaao.security.ui.welcome.PulsingKaaoShieldCrest
import com.kaao.security.ui.welcome.WelcomeScreen
import dagger.hilt.android.AndroidEntryPoint
import javax.inject.Inject

@AndroidEntryPoint
class MainActivity : FragmentActivity() {

    @Inject lateinit var permissionManager: PermissionManager
    @Inject lateinit var prefs: KaaoPreferencesRepository
    @Inject lateinit var biometricLockManager: BiometricLockManager

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge(
            statusBarStyle = SystemBarStyle.dark(android.graphics.Color.TRANSPARENT),
            navigationBarStyle = SystemBarStyle.dark(android.graphics.Color.TRANSPARENT)
        )
        setContent {
            KaaoTheme {
                KaaoRootHost(
                    activity = this,
                    permissionManager = permissionManager,
                    prefs = prefs,
                    biometricLockManager = biometricLockManager
                )
            }
        }
    }
}

@Composable
private fun KaaoRootHost(
    activity: FragmentActivity,
    permissionManager: PermissionManager,
    prefs: KaaoPreferencesRepository,
    biometricLockManager: BiometricLockManager
) {
    val settings by prefs.settingsFlow.collectAsStateWithLifecycle(initialValue = null)
    var isSessionUnlocked by rememberSaveable { mutableStateOf(false) }
    var lockError by remember { mutableStateOf<String?>(null) }

    val loadedSettings = settings
    if (loadedSettings == null) {
        Box(
            modifier = Modifier
                .fillMaxSize()
                .background(KaaoColors.ObsidianBg),
            contentAlignment = Alignment.Center
        ) {
            CircularProgressIndicator(color = KaaoColors.CyberEmerald)
        }
        return
    }

    // Hardware BiometricPrompt Security Lock gate
    val needsUnlock = loadedSettings.biometricLockEnabled &&
        !isSessionUnlocked &&
        biometricLockManager.canAuthenticate()

    if (needsUnlock) {
        LaunchedEffect(Unit) {
            biometricLockManager.authenticate(
                activity = activity,
                onSuccess = {
                    lockError = null
                    isSessionUnlocked = true
                },
                onError = { err -> lockError = err }
            )
        }
        BiometricLockOverlay(
            errorMessage = lockError,
            onRequestUnlock = {
                lockError = null
                biometricLockManager.authenticate(
                    activity = activity,
                    onSuccess = {
                        lockError = null
                        isSessionUnlocked = true
                    },
                    onError = { err -> lockError = err }
                )
            }
        )
        return
    }

    KaaoAppScaffold(
        startDestination = if (loadedSettings.onboardingCompleted) {
            KaaoDestination.DASHBOARD.route
        } else {
            KaaoDestination.WELCOME.route
        },
        permissionManager = permissionManager
    )
}

@Composable
private fun BiometricLockOverlay(
    errorMessage: String?,
    onRequestUnlock: () -> Unit
) {
    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(
                Brush.verticalGradient(listOf(KaaoColors.SurfaceDark, KaaoColors.ObsidianBg))
            )
            .padding(28.dp),
        contentAlignment = Alignment.Center
    ) {
        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center
        ) {
            PulsingKaaoShieldCrest(modifier = Modifier.size(132.dp))
            Spacer(modifier = Modifier.height(16.dp))
            Text(
                text = "KAAO Vault Locked",
                style = MaterialTheme.typography.headlineSmall,
                color = KaaoColors.TextPrimary,
                fontWeight = FontWeight.Bold
            )
            Spacer(modifier = Modifier.height(6.dp))
            Text(
                text = "Authenticate with hardware biometrics or device PIN to access security controls.",
                style = MaterialTheme.typography.bodySmall,
                color = KaaoColors.TextSecondary,
                textAlign = TextAlign.Center
            )
            if (!errorMessage.isNullOrBlank()) {
                Spacer(modifier = Modifier.height(10.dp))
                Text(
                    text = errorMessage,
                    style = MaterialTheme.typography.bodySmall,
                    color = KaaoColors.ThreatCrimson,
                    textAlign = TextAlign.Center
                )
            }
            Spacer(modifier = Modifier.height(24.dp))
            CyberGradientButton(
                text = "Unlock KAAO",
                icon = Icons.Outlined.Fingerprint,
                brush = KaaoColors.PrimaryActionGradient,
                onClick = onRequestUnlock
            )
        }
    }
}

@Composable
private fun KaaoAppScaffold(
    startDestination: String,
    permissionManager: PermissionManager
) {
    val navController = rememberNavController()
    val backStackEntry by navController.currentBackStackEntryAsState()
    val currentRoute = backStackEntry?.destination?.route ?: startDestination
    val currentDest = KaaoDestination.entries.firstOrNull { it.route == currentRoute }
        ?: KaaoDestination.DASHBOARD

    val notifPermLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.RequestPermission()
    ) { }

    LaunchedEffect(currentDest) {
        if (currentDest != KaaoDestination.WELCOME &&
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            !permissionManager.hasNotificationPermission()
        ) {
            notifPermLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
    }

    val navigateTo: (KaaoDestination) -> Unit = { dest ->
        when (dest) {
            KaaoDestination.SETTINGS, KaaoDestination.WELCOME -> {
                navController.navigate(dest.route) { launchSingleTop = true }
            }

            else -> {
                navController.navigate(dest.route) {
                    popUpTo(navController.graph.findStartDestination().id) {
                        saveState = true
                    }
                    launchSingleTop = true
                    restoreState = true
                }
            }
        }
    }

    Scaffold(
        modifier = Modifier.fillMaxSize(),
        containerColor = KaaoColors.ObsidianBg,
        topBar = {
            if (currentDest != KaaoDestination.WELCOME) {
                TopAppBar(
                    title = {
                        if (currentDest == KaaoDestination.DASHBOARD) {
                            Text(
                                text = "KAAO",
                                style = TextStyle(
                                    brush = KaaoColors.BrandWordmarkGradient,
                                    fontSize = 22.sp,
                                    fontWeight = FontWeight.ExtraBold,
                                    letterSpacing = 3.sp
                                )
                            )
                        } else {
                            Text(
                                text = currentDest.label,
                                style = MaterialTheme.typography.titleLarge,
                                fontWeight = FontWeight.Bold,
                                color = currentDest.accentColor
                            )
                        }
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
            }
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
                                selectedIconColor = dest.accentColor,
                                selectedTextColor = dest.accentColor,
                                indicatorColor = dest.indicatorContainer,
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
                startDestination = startDestination
            ) {
                composable(KaaoDestination.WELCOME.route) {
                    WelcomeScreen(
                        onFinished = {
                            navController.navigate(KaaoDestination.DASHBOARD.route) {
                                popUpTo(KaaoDestination.WELCOME.route) { inclusive = true }
                                launchSingleTop = true
                            }
                        }
                    )
                }
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
                    SettingsScreen(
                        onReplayWelcome = { navigateTo(KaaoDestination.WELCOME) }
                    )
                }
            }
        }
    }
}
