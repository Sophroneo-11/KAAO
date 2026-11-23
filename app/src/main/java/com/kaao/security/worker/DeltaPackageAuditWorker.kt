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
import com.kaao.security.domain.model.ThreatSource
import com.kaao.security.engine.antivirus.AntivirusRepository
import dagger.assisted.Assisted
import dagger.assisted.AssistedInject
import java.util.concurrent.TimeUnit

/**
 * Periodic battery-friendly WorkManager delta package auditor using API 26+ PackageManager.getChangedPackages().
 * Only inspects packages installed or updated since the last persisted sequence number.
 */
@HiltWorker
class DeltaPackageAuditWorker @AssistedInject constructor(
    @Assisted private val appContext: Context,
    @Assisted workerParams: WorkerParameters,
    private val antivirusRepository: AntivirusRepository,
    private val prefs: KaaoPreferencesRepository,
    private val permissionManager: PermissionManager
) : CoroutineWorker(appContext, workerParams) {

    override suspend fun doWork(): Result {
        val settings = prefs.getSettings()
        if (!settings.deltaPackageAuditEnabled) return Result.success()

        val lastSeq = settings.lastPackageSequenceNumber
        val changed = runCatching {
            appContext.packageManager.getChangedPackages(lastSeq)
        }.getOrNull() ?: return Result.success()

        val packagesToAudit = changed.packageNames.orEmpty().distinct()
        var threatsDetected = 0

        for (pkg in packagesToAudit) {
            val finding = antivirusRepository.scanSinglePackage(
                packageName = pkg,
                source = ThreatSource.REALTIME_INSTALL_SHIELD
            )
            if (finding != null) {
                threatsDetected++
                if (permissionManager.hasNotificationPermission()) {
                    val nm = appContext.getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager
                    val notif = KaaoNotificationChannels.buildThreatAlertNotification(
                        context = appContext,
                        title = "Delta Audit Alert: ${finding.title}",
                        details = "${finding.family} (${finding.severity.label}) detected during background delta audit."
                    )
                    nm?.notify(
                        KaaoNotificationChannels.NOTIF_ID_THREAT_BASE + (pkg.hashCode() and 0x0FFF),
                        notif
                    )
                }
            }
        }

        prefs.updatePackageSequenceNumber(changed.sequenceNumber)
        return Result.success()
    }

    companion object {
        const val UNIQUE_WORK_NAME = "kaao_delta_package_audit"

        fun schedulePeriodic(context: Context) {
            val constraints = Constraints.Builder()
                .setRequiresBatteryNotLow(true)
                .build()

            val request = PeriodicWorkRequestBuilder<DeltaPackageAuditWorker>(
                6,
                TimeUnit.HOURS
            )
                .setConstraints(constraints)
                .build()

            WorkManager.getInstance(context).enqueueUniquePeriodicWork(
                UNIQUE_WORK_NAME,
                ExistingPeriodicWorkPolicy.KEEP,
                request
            )
        }

        fun cancel(context: Context) {
            WorkManager.getInstance(context).cancelUniqueWork(UNIQUE_WORK_NAME)
        }
    }
}
