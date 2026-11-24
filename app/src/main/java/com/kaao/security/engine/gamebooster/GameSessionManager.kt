package com.kaao.security.engine.gamebooster

import android.app.NotificationManager
import android.content.ContentResolver
import android.content.Context
import android.content.Intent
import android.provider.Settings
import androidx.core.content.ContextCompat
import com.kaao.security.core.permission.PermissionManager
import com.kaao.security.data.local.prefs.KaaoPreferencesRepository
import com.kaao.security.data.local.prefs.SavedSystemSnapshot
import com.kaao.security.domain.model.AegisVpnMode
import com.kaao.security.domain.model.GameApp
import com.kaao.security.domain.model.GameBoostConfig
import com.kaao.security.domain.model.GameSessionState
import com.kaao.security.engine.network.AegisVpnController
import com.kaao.security.service.GameOverlayService
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Manages reversible Game Booster optimizations without fake RAM-killing gimmicks.
 * Snapshots DND interruption filter, screen brightness/mode, master auto-sync, and VPN state
 * to DataStore before launching a game and cleanly restores them when the session ends.
 */
@Singleton
class GameSessionManager @Inject constructor(
    @ApplicationContext private val context: Context,
    private val permissionManager: PermissionManager,
    private val prefs: KaaoPreferencesRepository,
    private val vpnController: AegisVpnController,
    private val gameDetector: GameDetector
) {
    private val _sessionState = MutableStateFlow(GameSessionState())
    val sessionState: StateFlow<GameSessionState> = _sessionState.asStateFlow()

    suspend fun recoverActiveSnapshotIfAny() = withContext(Dispatchers.IO) {
        val snap = prefs.getSavedSystemSnapshot()
        if (snap.hasActiveSnapshot && snap.activeGamePackage != null) {
            _sessionState.value = GameSessionState(
                isActive = true,
                activePackage = snap.activeGamePackage,
                activeGameName = snap.activeGameName ?: snap.activeGamePackage,
                startedAtMillis = System.currentTimeMillis(),
                appliedFirewall = vpnController.vpnState.value.mode == AegisVpnMode.GAME_FIREWALL,
                appliedDnd = snap.previousDndFilter != -1,
                appliedBrightness = snap.previousBrightness != -1,
                appliedSyncPause = true,
                appliedHud = true
            )
        }
    }

    suspend fun startBoostedSession(
        game: GameApp,
        config: GameBoostConfig
    ): Boolean = withContext(Dispatchers.IO) {
        val notificationManager =
            context.getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager
        val currentDnd = if (permissionManager.hasDndPolicyPermission() && notificationManager != null) {
            notificationManager.currentInterruptionFilter
        } else {
            -1
        }
        val currentBrightness = runCatching {
            Settings.System.getInt(context.contentResolver, Settings.System.SCREEN_BRIGHTNESS)
        }.getOrDefault(-1)
        val currentBrightnessMode = runCatching {
            Settings.System.getInt(context.contentResolver, Settings.System.SCREEN_BRIGHTNESS_MODE)
        }.getOrDefault(-1)
        val currentMasterSync = runCatching {
            ContentResolver.getMasterSyncAutomatically()
        }.getOrDefault(true)
        val dnsWasOn = vpnController.vpnState.value.mode == AegisVpnMode.DNS_SHIELD

        prefs.saveSystemSnapshot(
            SavedSystemSnapshot(
                hasActiveSnapshot = true,
                activeGamePackage = game.packageName,
                activeGameName = game.appName,
                previousDndFilter = currentDnd,
                previousBrightness = currentBrightness,
                previousBrightnessMode = currentBrightnessMode,
                previousMasterSync = currentMasterSync,
                previousDnsShieldWasOn = dnsWasOn
            )
        )

        var appliedDnd = false
        if (config.enableDndSilence && permissionManager.hasDndPolicyPermission() && notificationManager != null) {
            appliedDnd = runCatching {
                notificationManager.setInterruptionFilter(NotificationManager.INTERRUPTION_FILTER_PRIORITY)
                true
            }.getOrDefault(false)
        }

        var appliedBrightness = false
        if (config.lockBrightness && permissionManager.hasWriteSettingsPermission()) {
            appliedBrightness = runCatching {
                Settings.System.putInt(
                    context.contentResolver,
                    Settings.System.SCREEN_BRIGHTNESS_MODE,
                    Settings.System.SCREEN_BRIGHTNESS_MODE_MANUAL
                )
                val targetValue = ((config.targetBrightnessPercent.coerceIn(15, 100) / 100f) * 255f).toInt()
                Settings.System.putInt(
                    context.contentResolver,
                    Settings.System.SCREEN_BRIGHTNESS,
                    targetValue.coerceIn(20, 255)
                )
                true
            }.getOrDefault(false)
        }

        var appliedSync = false
        if (config.pauseAutoSync && currentMasterSync) {
            appliedSync = runCatching {
                ContentResolver.setMasterSyncAutomatically(false)
                true
            }.getOrDefault(false)
        }

        var appliedFirewall = false
        if (config.enableBackgroundFirewall && permissionManager.isVpnConsentGranted()) {
            val exceptions = prefs.getSettings().gameFirewallExceptionPackages
            vpnController.startGameFirewall(game.packageName, game.appName, exceptions)
            appliedFirewall = true
        }

        var appliedHud = false
        if (config.showFloatingHud) {
            val hudIntent = Intent(context, GameOverlayService::class.java).apply {
                action = GameOverlayService.ACTION_START_HUD
                putExtra(GameOverlayService.EXTRA_GAME_NAME, game.appName)
                putExtra(GameOverlayService.EXTRA_GAME_PACKAGE, game.packageName)
            }
            ContextCompat.startForegroundService(context, hudIntent)
            appliedHud = true
        }

        gameDetector.recordGameLaunched(game.packageName, game.appName)
        _sessionState.value = GameSessionState(
            isActive = true,
            activePackage = game.packageName,
            activeGameName = game.appName,
            startedAtMillis = System.currentTimeMillis(),
            appliedFirewall = appliedFirewall,
            appliedDnd = appliedDnd,
            appliedBrightness = appliedBrightness,
            appliedSyncPause = appliedSync,
            appliedHud = appliedHud
        )

        // Launch the game activity
        val launchIntent = context.packageManager.getLaunchIntentForPackage(game.packageName)
        if (launchIntent != null) {
            launchIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            context.startActivity(launchIntent)
            true
        } else {
            false
        }
    }

    suspend fun endSessionAndRestore() = withContext(Dispatchers.IO) {
        val snap = prefs.getSavedSystemSnapshot()

        // 1. Restore DND
        if (snap.previousDndFilter != -1 && permissionManager.hasDndPolicyPermission()) {
            val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager
            val validFilter = when (snap.previousDndFilter) {
                NotificationManager.INTERRUPTION_FILTER_ALL -> NotificationManager.INTERRUPTION_FILTER_ALL
                NotificationManager.INTERRUPTION_FILTER_PRIORITY -> NotificationManager.INTERRUPTION_FILTER_PRIORITY
                NotificationManager.INTERRUPTION_FILTER_NONE -> NotificationManager.INTERRUPTION_FILTER_NONE
                NotificationManager.INTERRUPTION_FILTER_ALARMS -> NotificationManager.INTERRUPTION_FILTER_ALARMS
                else -> NotificationManager.INTERRUPTION_FILTER_ALL
            }
            runCatching { nm?.setInterruptionFilter(validFilter) }
        }

        // 2. Restore brightness & mode
        if (permissionManager.hasWriteSettingsPermission()) {
            if (snap.previousBrightnessMode != -1) {
                runCatching {
                    Settings.System.putInt(
                        context.contentResolver,
                        Settings.System.SCREEN_BRIGHTNESS_MODE,
                        snap.previousBrightnessMode
                    )
                }
            }
            if (snap.previousBrightness != -1) {
                runCatching {
                    Settings.System.putInt(
                        context.contentResolver,
                        Settings.System.SCREEN_BRIGHTNESS,
                        snap.previousBrightness
                    )
                }
            }
        }

        // 3. Restore Master Auto-Sync
        if (snap.hasActiveSnapshot) {
            runCatching { ContentResolver.setMasterSyncAutomatically(snap.previousMasterSync) }
        }

        // 4. Restore VPN (return to split-routed DNS Shield if it was on previously, else stop VPN)
        if (vpnController.vpnState.value.mode == AegisVpnMode.GAME_FIREWALL) {
            if (snap.previousDnsShieldWasOn) {
                vpnController.startDnsShield()
            } else {
                vpnController.stopVpn()
            }
        }

        // 5. Stop Floating HUD Overlay
        val stopHud = Intent(context, GameOverlayService::class.java).apply {
            action = GameOverlayService.ACTION_STOP_HUD
        }
        runCatching { context.startService(stopHud) }

        prefs.clearSystemSnapshot()
        _sessionState.value = GameSessionState(isActive = false)
    }
}
