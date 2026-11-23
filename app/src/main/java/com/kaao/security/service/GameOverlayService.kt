package com.kaao.security.service

import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.graphics.Color
import android.graphics.PixelFormat
import android.graphics.drawable.GradientDrawable
import android.os.Build
import android.os.IBinder
import android.provider.Settings
import android.util.TypedValue
import android.view.Gravity
import android.view.MotionEvent
import android.view.View
import android.view.WindowManager
import android.widget.LinearLayout
import android.widget.TextView
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import com.kaao.security.R
import com.kaao.security.core.notification.KaaoNotificationChannels
import com.kaao.security.domain.model.DeviceTelemetry
import com.kaao.security.engine.gamebooster.DeviceTelemetryCollector
import com.kaao.security.engine.gamebooster.GameSessionManager
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.Locale
import javax.inject.Inject

/**
 * Lightweight draggable Game Booster Telemetry HUD Overlay (foregroundServiceType="specialUse").
 * Gracefully falls back to a rich notification with a Restore action if SYSTEM_ALERT_WINDOW is not granted.
 */
@AndroidEntryPoint
class GameOverlayService : Service() {

    @Inject lateinit var telemetryCollector: DeviceTelemetryCollector
    @Inject lateinit var gameSessionManager: GameSessionManager

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private var telemetryJob: Job? = null
    private var windowManager: WindowManager? = null
    private var hudRootView: View? = null
    private var metricsTextView: TextView? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP_HUD -> {
                removeOverlayView()
                ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
                stopSelf()
                return START_NOT_STICKY
            }

            ACTION_RESTORE_AND_STOP -> {
                serviceScope.launch {
                    gameSessionManager.endSessionAndRestore()
                    removeOverlayView()
                    ServiceCompat.stopForeground(this@GameOverlayService, ServiceCompat.STOP_FOREGROUND_REMOVE)
                    stopSelf()
                }
                return START_NOT_STICKY
            }

            else -> {
                val gameName = intent?.getStringExtra(EXTRA_GAME_NAME) ?: "Game Session"
                promoteForeground(gameName)
                if (Settings.canDrawOverlays(this)) {
                    attachFloatingHud(gameName)
                }
                startTelemetryUpdates()
                return START_STICKY
            }
        }
    }

    override fun onDestroy() {
        telemetryJob?.cancel()
        removeOverlayView()
        serviceScope.cancel()
        super.onDestroy()
    }

    private fun promoteForeground(gameName: String) {
        val restoreIntent = Intent(this, GameOverlayService::class.java).apply {
            action = ACTION_RESTORE_AND_STOP
        }
        val restorePending = PendingIntent.getService(
            this,
            99,
            restoreIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val notif = NotificationCompat.Builder(this, KaaoNotificationChannels.CHANNEL_GAME)
            .setSmallIcon(R.drawable.ic_kaao_shield_notif)
            .setContentTitle("KAAO Game Booster: $gameName")
            .setContentText("Tap Restore when done to revert DND, brightness, sync & firewall")
            .setOngoing(true)
            .setSilent(true)
            .setContentIntent(KaaoNotificationChannels.buildLaunchAppPendingIntent(this, 40))
            .addAction(0, "Restore & Exit", restorePending)
            .build()

        val fgType = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
        } else {
            0
        }
        ServiceCompat.startForeground(this, KaaoNotificationChannels.NOTIF_ID_GAME_HUD, notif, fgType)
    }

    @android.annotation.SuppressLint("ClickableViewAccessibility")
    private fun attachFloatingHud(gameName: String) {
        if (hudRootView != null) return
        val wm = getSystemService(WINDOW_SERVICE) as? WindowManager ?: return
        windowManager = wm

        val density = resources.displayMetrics.density
        val padH = (12 * density).toInt()
        val padV = (7 * density).toInt()

        val container = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(padH, padV, padH, padV)
            background = GradientDrawable().apply {
                setColor(Color.argb(225, 13, 19, 33))
                cornerRadius = 24f * density
                setStroke((1.5f * density).toInt(), Color.rgb(0, 229, 160))
            }
        }

        val metricsTv = TextView(this).apply {
            text = "KAAO • $gameName"
            setTextColor(Color.rgb(226, 232, 240))
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 11.5f)
            typeface = android.graphics.Typeface.MONOSPACE
        }
        metricsTextView = metricsTv

        val restoreBtn = TextView(this).apply {
            text = "  ✕"
            setTextColor(Color.rgb(248, 113, 113))
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 13f)
            setPadding((6 * density).toInt(), 0, 0, 0)
            setOnClickListener {
                serviceScope.launch {
                    gameSessionManager.endSessionAndRestore()
                    removeOverlayView()
                    ServiceCompat.stopForeground(this@GameOverlayService, ServiceCompat.STOP_FOREGROUND_REMOVE)
                    stopSelf()
                }
            }
        }

        container.addView(metricsTv)
        container.addView(restoreBtn)

        val params = WindowManager.LayoutParams(
            WindowManager.LayoutParams.WRAP_CONTENT,
            WindowManager.LayoutParams.WRAP_CONTENT,
            WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY,
            WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE or WindowManager.LayoutParams.FLAG_LAYOUT_IN_SCREEN,
            PixelFormat.TRANSLUCENT
        ).apply {
            gravity = Gravity.TOP or Gravity.START
            x = (16 * density).toInt()
            y = (72 * density).toInt()
        }

        // Draggable pill gesture
        var initialX = 0
        var initialY = 0
        var initialTouchX = 0f
        var initialTouchY = 0f

        container.setOnTouchListener { view, event ->
            when (event.action) {
                MotionEvent.ACTION_DOWN -> {
                    initialX = params.x
                    initialY = params.y
                    initialTouchX = event.rawX
                    initialTouchY = event.rawY
                    true
                }

                MotionEvent.ACTION_MOVE -> {
                    params.x = initialX + (event.rawX - initialTouchX).toInt()
                    params.y = initialY + (event.rawY - initialTouchY).toInt()
                    runCatching { wm.updateViewLayout(view, params) }
                    true
                }

                MotionEvent.ACTION_UP -> {
                    view.performClick()
                    true
                }

                else -> false
            }
        }

        runCatching {
            wm.addView(container, params)
            hudRootView = container
        }
    }

    private fun startTelemetryUpdates() {
        telemetryJob?.cancel()
        telemetryJob = serviceScope.launch {
            telemetryCollector.observeTelemetry(intervalMs = 2500L).collect { t ->
                withContext(Dispatchers.Main.immediate) {
                    renderTelemetry(t)
                }
            }
        }
    }

    private fun renderTelemetry(t: DeviceTelemetry) {
        val pingText = t.tcpPingMs?.let { "${it}ms" } ?: "--ms"
        val tempText = String.format(Locale.US, "%.1f°C", t.batteryTempCelsius)
        metricsTextView?.text = "KAAO │ $pingText │ $tempText │ RAM ${t.ramUsagePercent}% │ ${t.batteryPercent}%"
    }

    private fun removeOverlayView() {
        hudRootView?.let { view ->
            runCatching { windowManager?.removeView(view) }
        }
        hudRootView = null
        metricsTextView = null
    }

    companion object {
        const val ACTION_START_HUD = "com.kaao.security.action.START_HUD"
        const val ACTION_STOP_HUD = "com.kaao.security.action.STOP_HUD"
        const val ACTION_RESTORE_AND_STOP = "com.kaao.security.action.RESTORE_AND_STOP"
        const val EXTRA_GAME_NAME = "extra_game_name"
        const val EXTRA_GAME_PACKAGE = "extra_game_package"
    }
}
