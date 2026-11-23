package com.kaao.security.service

import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import androidx.core.content.ContextCompat
import com.kaao.security.R
import com.kaao.security.core.notification.KaaoNotificationChannels
import com.kaao.security.engine.antivirus.AntivirusRepository
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * Foreground service (foregroundServiceType="dataSync") keeping deep APK + Downloads scans
 * alive reliably under Android 14/15 background execution limits.
 */
@AndroidEntryPoint
class DeepScanForegroundService : Service() {

    @Inject lateinit var antivirusRepository: AntivirusRepository

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val notification = NotificationCompat.Builder(this, KaaoNotificationChannels.CHANNEL_SCAN)
            .setSmallIcon(R.drawable.ic_kaao_shield_notif)
            .setContentTitle("KAAO Deep Security Scan")
            .setContentText("Analyzing installed apps, DEX heuristics & Downloads...")
            .setOngoing(true)
            .setSilent(true)
            .setProgress(0, 0, true)
            .setContentIntent(KaaoNotificationChannels.buildLaunchAppPendingIntent(this, 30))
            .build()

        val fgType = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC
        } else {
            0
        }
        ServiceCompat.startForeground(this, KaaoNotificationChannels.NOTIF_ID_SCAN, notification, fgType)

        serviceScope.launch {
            try {
                antivirusRepository.runDeepDownloadsAndApkScan()
            } finally {
                ServiceCompat.stopForeground(
                    this@DeepScanForegroundService,
                    ServiceCompat.STOP_FOREGROUND_REMOVE
                )
                stopSelf()
            }
        }
        return START_NOT_STICKY
    }

    override fun onDestroy() {
        serviceScope.cancel()
        super.onDestroy()
    }

    companion object {
        fun startDeepScan(context: Context) {
            val intent = Intent(context, DeepScanForegroundService::class.java)
            ContextCompat.startForegroundService(context, intent)
        }
    }
}
