package com.kaao.security.worker

import android.app.NotificationManager
import android.content.Context
import androidx.hilt.work.HiltWorker
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import com.kaao.security.core.notification.KaaoNotificationChannels
import com.kaao.security.core.permission.PermissionManager
import com.kaao.security.data.local.prefs.KaaoPreferencesRepository
import com.kaao.security.domain.model.AutoScanInterval
import com.kaao.security.engine.antivirus.AntivirusRepository
import dagger.assisted.Assisted
import dagger.assisted.AssistedInject
import java.util.concurrent.TimeUnit

/**
 * Configurable periodic background antivirus & stalkerware auto-scan worker.
 */
@HiltWorker
class ScheduledAutoScanWorker @AssistedInject constructor(
    @Assisted private val appContext: Context,
    @Assisted workerParams: WorkerParameters,
    private val antivirusRepository: AntivirusRepository,
    private val prefs: KaaoPreferencesRepository,
    private val permissionManager: PermissionManager
) : CoroutineWorker(appContext, workerParams) {

    override suspend fun doWork(): Result {
        val settings = prefs.getSettings()
        if (settings.autoScanInterval == AutoScanInterval.OFF) return Result.success()

        val findings = antivirusRepository.runInstalledAppsScan(includeSystemApps = false)
        prefs.updateLastAutoScanMillis(System.currentTimeMillis())

        if (findings.isNotEmpty() && permissionManager.hasNotificationPermission()) {
            val nm = appContext.getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager
            val top = findings.first()
            val notif = KaaoNotificationChannels.buildThreatAlertNotification(
                context = appContext,
                title = "Scheduled Scan Found ${findings.size} Threat(s)",
                details = "${top.title}: ${top.family} (${top.severity.label}). Open KAAO for guided remediation."
            )
            nm?.notify(KaaoNotificationChannels.NOTIF_ID_THREAT_BASE + 777, notif)
        }
        return Result.success()
    }

    companion object {
        const val UNIQUE_WORK_NAME = "kaao_scheduled_auto_scan"

        fun applySchedule(context: Context, interval: AutoScanInterval) {
            val wm = WorkManager.getInstance(context)
            if (interval == AutoScanInterval.OFF || interval.intervalHours <= 0L) {
                wm.cancelUniqueWork(UNIQUE_WORK_NAME)
                return
            }
            val constraints = Constraints.Builder()
                .setRequiresBatteryNotLow(true)
                .build()

            val request = PeriodicWorkRequestBuilder<ScheduledAutoScanWorker>(
                interval.intervalHours,
                TimeUnit.HOURS
            )
                .setConstraints(constraints)
                .build()

            wm.enqueueUniquePeriodicWork(
                UNIQUE_WORK_NAME,
                ExistingPeriodicWorkPolicy.UPDATE,
                request
            )
        }
    }
}
