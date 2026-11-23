package com.kaao.security.worker

import android.content.Context
import androidx.hilt.work.HiltWorker
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import com.kaao.security.data.local.db.CloudReputationCacheDao
import com.kaao.security.engine.antivirus.AntivirusRepository
import dagger.assisted.Assisted
import dagger.assisted.AssistedInject
import java.util.concurrent.TimeUnit

@HiltWorker
class SignatureIntegrityWorker @AssistedInject constructor(
    @Assisted appContext: Context,
    @Assisted workerParams: WorkerParameters,
    private val antivirusRepository: AntivirusRepository,
    private val cloudCacheDao: CloudReputationCacheDao
) : CoroutineWorker(appContext, workerParams) {

    override suspend fun doWork(): Result {
        antivirusRepository.initializeVaultAndBloomFilter()
        val cutoff = System.currentTimeMillis() - (7L * 24L * 60L * 60L * 1000L)
        cloudCacheDao.pruneExpired(cutoff)
        return Result.success()
    }

    companion object {
        const val UNIQUE_WORK_NAME = "kaao_signature_integrity"

        fun schedulePeriodic(context: Context) {
            val request = PeriodicWorkRequestBuilder<SignatureIntegrityWorker>(24, TimeUnit.HOURS)
                .build()
            WorkManager.getInstance(context).enqueueUniquePeriodicWork(
                UNIQUE_WORK_NAME,
                ExistingPeriodicWorkPolicy.KEEP,
                request
            )
        }
    }
}
