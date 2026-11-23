package com.kaao.security.service

import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.Environment
import android.os.IBinder
import androidx.core.app.ServiceCompat
import androidx.core.content.ContextCompat
import com.kaao.security.core.notification.KaaoNotificationChannels
import com.kaao.security.core.permission.PermissionManager
import com.kaao.security.data.local.prefs.KaaoPreferencesRepository
import com.kaao.security.domain.model.ThreatFinding
import com.kaao.security.domain.model.ThreatSource
import com.kaao.security.engine.antivirus.AntivirusRepository
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * Real-Time Protection Foreground Service (foregroundServiceType="specialUse").
 * Dynamically registers PackageInstallReceiver and monitors Downloads via inotify FileObserver.
 */
@AndroidEntryPoint
class RealtimeMonitorService : Service() {

    @Inject lateinit var antivirusRepository: AntivirusRepository
    @Inject lateinit var prefs: KaaoPreferencesRepository
    @Inject lateinit var permissionManager: PermissionManager

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var packageInstallReceiver: PackageInstallReceiver? = null
    private var downloadsObserver: DownloadsFileObserver? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopMonitoring()
            ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
            stopSelf()
            return START_NOT_STICKY
        }

        val notification = KaaoNotificationChannels.buildOngoingShieldNotification(
            context = this,
            title = "KAAO Real-Time Protection Active",
            subtitle = "Monitoring new app installs & Downloads folder"
        )
        val fgType = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
        } else {
            0
        }
        ServiceCompat.startForeground(this, KaaoNotificationChannels.NOTIF_ID_REALTIME, notification, fgType)

        startMonitoring()
        return START_STICKY
    }

    override fun onDestroy() {
        stopMonitoring()
        serviceScope.cancel()
        super.onDestroy()
    }

    private fun startMonitoring() {
        if (packageInstallReceiver == null) {
            val receiver = PackageInstallReceiver { pkgName ->
                serviceScope.launch {
                    val finding = antivirusRepository.scanSinglePackage(
                        packageName = pkgName,
                        source = ThreatSource.REALTIME_INSTALL_SHIELD
                    )
                    if (finding != null) {
                        postThreatNotification(finding)
                    }
                }
            }
            val filter = IntentFilter().apply {
                addAction(Intent.ACTION_PACKAGE_ADDED)
                addAction(Intent.ACTION_PACKAGE_REPLACED)
                addDataScheme("package")
            }
            ContextCompat.registerReceiver(this, receiver, filter, ContextCompat.RECEIVER_EXPORTED)
            packageInstallReceiver = receiver
        }

        serviceScope.launch {
            val settings = prefs.getSettings()
            if (settings.downloadsObserverEnabled && downloadsObserver == null) {
                val downloadsDir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
                if (downloadsDir != null && downloadsDir.exists()) {
                    val observer = DownloadsFileObserver.create(downloadsDir) { file ->
                        serviceScope.launch {
                            val finding = antivirusRepository.scanSingleFile(
                                file = file,
                                source = ThreatSource.DOWNLOADS_OBSERVER
                            )
                            if (finding != null) {
                                postThreatNotification(finding)
                            }
                        }
                    }
                    observer.start()
                    downloadsObserver = observer
                }
            }
        }
        _isRunning.value = true
    }

    private fun stopMonitoring() {
        packageInstallReceiver?.let { receiver ->
            runCatching { unregisterReceiver(receiver) }
        }
        packageInstallReceiver = null
        downloadsObserver?.stop()
        downloadsObserver = null
        _isRunning.value = false
    }

    private fun postThreatNotification(finding: ThreatFinding) {
        if (!permissionManager.hasNotificationPermission()) return
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager ?: return
        val notif = KaaoNotificationChannels.buildThreatAlertNotification(
            context = this,
            title = "KAAO Threat Detected: ${finding.title}",
            details = "${finding.family} (${finding.severity.label}) • ${finding.reasons.firstOrNull().orEmpty()}"
        )
        val notifId = KaaoNotificationChannels.NOTIF_ID_THREAT_BASE + (finding.id.hashCode() and 0x0FFF)
        nm.notify(notifId, notif)
    }

    companion object {
        const val ACTION_START = "com.kaao.security.action.REALTIME_START"
        const val ACTION_STOP = "com.kaao.security.action.REALTIME_STOP"

        private val _isRunning = MutableStateFlow(false)
        val isRunning: StateFlow<Boolean> = _isRunning.asStateFlow()

        fun start(context: Context) {
            val intent = Intent(context, RealtimeMonitorService::class.java).apply {
                action = ACTION_START
            }
            ContextCompat.startForegroundService(context, intent)
        }

        fun stop(context: Context) {
            val intent = Intent(context, RealtimeMonitorService::class.java).apply {
                action = ACTION_STOP
            }
            context.startService(intent)
        }
    }
}
