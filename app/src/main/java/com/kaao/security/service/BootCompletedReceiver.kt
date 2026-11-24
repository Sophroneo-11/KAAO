package com.kaao.security.service

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import com.kaao.security.data.local.prefs.KaaoPreferencesRepository
import com.kaao.security.worker.DeltaPackageAuditWorker
import com.kaao.security.worker.ScheduledAutoScanWorker
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import javax.inject.Inject

@AndroidEntryPoint
class BootCompletedReceiver : BroadcastReceiver() {

    @Inject lateinit var prefs: KaaoPreferencesRepository

    override fun onReceive(context: Context, intent: Intent?) {
        val action = intent?.action ?: return
        if (action != Intent.ACTION_BOOT_COMPLETED && action != Intent.ACTION_MY_PACKAGE_REPLACED) {
            return
        }
        val pendingResult = goAsync()
        CoroutineScope(SupervisorJob() + Dispatchers.IO).launch {
            try {
                val settings = prefs.getSettings()
                if (settings.deltaPackageAuditEnabled) {
                    DeltaPackageAuditWorker.schedulePeriodic(context)
                }
                ScheduledAutoScanWorker.applySchedule(context, settings.autoScanInterval)
                if (settings.realtimeShieldEnabled) {
                    runCatching { RealtimeMonitorService.start(context) }
                }
            } finally {
                pendingResult.finish()
            }
        }
    }
}
