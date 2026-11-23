package com.kaao.security.engine.cleaner

import android.app.usage.StorageStatsManager
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Process
import android.os.storage.StorageManager
import com.kaao.security.core.permission.PermissionManager
import com.kaao.security.domain.model.AppStorageInfo
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Analyzes per-app storage & cache breakdown via StorageStatsManager (when PACKAGE_USAGE_STATS is granted),
 * with a graceful APK-size fallback when Usage Access is not yet enabled.
 */
@Singleton
class AppStorageAnalyzer @Inject constructor(
    @ApplicationContext private val context: Context,
    private val permissionManager: PermissionManager
) {
    suspend fun analyzeAppStorage(limit: Int = 40): List<AppStorageInfo> = withContext(Dispatchers.IO) {
        val pm = context.packageManager
        val hasUsageStats = permissionManager.hasUsageStatsPermission()
        val statsManager = if (hasUsageStats) {
            context.getSystemService(Context.STORAGE_STATS_SERVICE) as? StorageStatsManager
        } else {
            null
        }
        val userHandle = Process.myUserHandle()

        val apps = runCatching {
            pm.getInstalledApplications(PackageManager.GET_META_DATA)
        }.getOrDefault(emptyList()).filter { app ->
            (app.flags and ApplicationInfo.FLAG_SYSTEM) == 0 ||
                (app.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0
        }

        val results = mutableListOf<AppStorageInfo>()
        for (app in apps) {
            val label = runCatching { pm.getApplicationLabel(app).toString() }.getOrDefault(app.packageName)
            if (statsManager != null) {
                val stats = runCatching {
                    statsManager.queryStatsForPackage(
                        StorageManager.UUID_DEFAULT,
                        app.packageName,
                        userHandle
                    )
                }.getOrNull()

                if (stats != null) {
                    val appBytes = stats.appBytes
                    val dataBytes = stats.dataBytes
                    val cacheBytes = stats.cacheBytes
                    results.add(
                        AppStorageInfo(
                            packageName = app.packageName,
                            appName = label,
                            appBytes = appBytes,
                            dataBytes = dataBytes,
                            cacheBytes = cacheBytes,
                            totalBytes = appBytes + dataBytes,
                            isExactStats = true
                        )
                    )
                    continue
                }
            }

            // Graceful fallback when Usage Access isn't granted
            val apkSize = runCatching { File(app.sourceDir).length() }.getOrDefault(0L)
            results.add(
                AppStorageInfo(
                    packageName = app.packageName,
                    appName = label,
                    appBytes = apkSize,
                    dataBytes = 0L,
                    cacheBytes = 0L,
                    totalBytes = apkSize,
                    isExactStats = false
                )
            )
        }

        results.sortedWith(
            compareByDescending<AppStorageInfo> { it.cacheBytes }
                .thenByDescending { it.totalBytes }
        ).take(limit)
    }
}
