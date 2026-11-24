package com.kaao.security

import android.app.Application
import androidx.hilt.work.HiltWorkerFactory
import androidx.work.Configuration
import com.kaao.security.core.notification.KaaoNotificationChannels
import com.kaao.security.data.local.prefs.KaaoPreferencesRepository
import com.kaao.security.engine.antivirus.AntivirusRepository
import com.kaao.security.engine.gamebooster.GameSessionManager
import com.kaao.security.engine.network.AegisVpnController
import com.kaao.security.worker.DefinitionUpdateWorker
import com.kaao.security.worker.DeltaPackageAuditWorker
import com.kaao.security.worker.ScheduledAutoScanWorker
import com.kaao.security.worker.SignatureIntegrityWorker
import dagger.hilt.android.HiltAndroidApp
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import javax.inject.Inject

@HiltAndroidApp
class KaaoApplication : Application(), Configuration.Provider {

    @Inject lateinit var workerFactory: HiltWorkerFactory
    @Inject lateinit var antivirusRepository: AntivirusRepository
    @Inject lateinit var vpnController: AegisVpnController
    @Inject lateinit var gameSessionManager: GameSessionManager
    @Inject lateinit var prefs: KaaoPreferencesRepository

    private val appScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    override val workManagerConfiguration: Configuration
        get() = Configuration.Builder()
            .setWorkerFactory(workerFactory)
            .build()

    override fun onCreate() {
        super.onCreate()
        KaaoNotificationChannels.registerAll(this)

        appScope.launch {
            antivirusRepository.initializeVaultAndBloomFilter()
            vpnController.reloadMatcherRules()
            gameSessionManager.recoverActiveSnapshotIfAny()

            val settings = prefs.getSettings()
            if (settings.deltaPackageAuditEnabled) {
                DeltaPackageAuditWorker.schedulePeriodic(this@KaaoApplication)
            }
            ScheduledAutoScanWorker.applySchedule(this@KaaoApplication, settings.autoScanInterval)
            SignatureIntegrityWorker.schedulePeriodic(this@KaaoApplication)
            DefinitionUpdateWorker.schedulePeriodic(this@KaaoApplication)
        }
    }
}
