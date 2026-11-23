package com.kaao.security.worker

import android.content.Context
import androidx.hilt.work.HiltWorker
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import com.kaao.security.engine.antivirus.DefinitionFeedRepository
import dagger.assisted.Assisted
import dagger.assisted.AssistedInject
import java.util.concurrent.TimeUnit

/**
 * Periodically pulls ECDSA-P256 signed threat & DNS definitions over certificate-pinned TLS
 * when the device is connected and battery is not low.
 */
@HiltWorker
class DefinitionUpdateWorker @AssistedInject constructor(
    @Assisted appContext: Context,
    @Assisted workerParams: WorkerParameters,
    private val definitionFeedRepository: DefinitionFeedRepository
) : CoroutineWorker(appContext, workerParams) {

    override suspend fun doWork(): Result {
        definitionFeedRepository.syncFromRemoteFeed()
        return Result.success()
    }

    companion object {
        const val UNIQUE_WORK_NAME = "kaao_remote_definition_sync"

        fun schedulePeriodic(context: Context) {
            val constraints = Constraints.Builder()
                .setRequiredNetworkType(NetworkType.CONNECTED)
                .setRequiresBatteryNotLow(true)
                .build()

            val request = PeriodicWorkRequestBuilder<DefinitionUpdateWorker>(24, TimeUnit.HOURS)
                .setConstraints(constraints)
                .build()

            WorkManager.getInstance(context).enqueueUniquePeriodicWork(
                UNIQUE_WORK_NAME,
                ExistingPeriodicWorkPolicy.KEEP,
                request
            )
        }
    }
}
