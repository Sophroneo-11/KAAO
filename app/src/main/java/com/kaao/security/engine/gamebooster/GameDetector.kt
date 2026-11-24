package com.kaao.security.engine.gamebooster

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import com.kaao.security.data.local.db.GameProfileDao
import com.kaao.security.data.local.db.GameProfileEntity
import com.kaao.security.domain.model.GameApp
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class GameDetector @Inject constructor(
    @ApplicationContext private val context: Context,
    private val gameProfileDao: GameProfileDao
) {
    suspend fun loadGameLibrary(): List<GameApp> = withContext(Dispatchers.IO) {
        val pm = context.packageManager
        val savedProfiles = gameProfileDao.getAll().associateBy { it.packageName }
        val installed = runCatching {
            pm.getInstalledApplications(PackageManager.GET_META_DATA)
        }.getOrDefault(emptyList())

        val result = mutableListOf<GameApp>()
        for (app in installed) {
            if (app.packageName == context.packageName) continue
            if (pm.getLaunchIntentForPackage(app.packageName) == null) continue

            val isCategoryGame = app.category == ApplicationInfo.CATEGORY_GAME
            @Suppress("DEPRECATION")
            val isLegacyGame = (app.flags and ApplicationInfo.FLAG_IS_GAME) != 0
            val isCustom = savedProfiles[app.packageName]?.isCustomAdded == true

            if (isCategoryGame || isLegacyGame || isCustom) {
                val label = runCatching { pm.getApplicationLabel(app).toString() }.getOrDefault(app.packageName)
                val version = runCatching { pm.getPackageInfo(app.packageName, 0).versionName.orEmpty() }
                    .getOrDefault("")
                result.add(
                    GameApp(
                        packageName = app.packageName,
                        appName = label,
                        isAutoDetected = isCategoryGame || isLegacyGame,
                        versionName = version
                    )
                )
            }
        }
        result.sortedBy { it.appName.lowercase() }
    }

    suspend fun loadAllLaunchableApps(): List<GameApp> = withContext(Dispatchers.IO) {
        val pm = context.packageManager
        val installed = runCatching {
            pm.getInstalledApplications(PackageManager.GET_META_DATA)
        }.getOrDefault(emptyList())

        installed.mapNotNull { app ->
            if (app.packageName == context.packageName) return@mapNotNull null
            if ((app.flags and ApplicationInfo.FLAG_SYSTEM) != 0) return@mapNotNull null
            if (pm.getLaunchIntentForPackage(app.packageName) == null) return@mapNotNull null
            val label = runCatching { pm.getApplicationLabel(app).toString() }.getOrDefault(app.packageName)
            val version = runCatching { pm.getPackageInfo(app.packageName, 0).versionName.orEmpty() }
                .getOrDefault("")
            GameApp(
                packageName = app.packageName,
                appName = label,
                isAutoDetected = app.category == ApplicationInfo.CATEGORY_GAME,
                versionName = version
            )
        }.sortedBy { it.appName.lowercase() }
    }

    suspend fun addCustomGame(packageName: String, appName: String) = withContext(Dispatchers.IO) {
        gameProfileDao.upsert(
            GameProfileEntity(
                packageName = packageName,
                appName = appName,
                isCustomAdded = true,
                lastLaunchedMillis = 0L
            )
        )
    }

    suspend fun removeCustomGame(packageName: String) = withContext(Dispatchers.IO) {
        gameProfileDao.delete(packageName)
    }

    suspend fun recordGameLaunched(packageName: String, appName: String) = withContext(Dispatchers.IO) {
        val existing = gameProfileDao.getAll().firstOrNull { it.packageName == packageName }
        gameProfileDao.upsert(
            GameProfileEntity(
                packageName = packageName,
                appName = appName,
                isCustomAdded = existing?.isCustomAdded ?: false,
                lastLaunchedMillis = System.currentTimeMillis()
            )
        )
    }

    suspend fun loadFirewallExceptionCandidates(
        selectedPackages: Set<String>
    ): List<com.kaao.security.domain.model.FirewallExceptionApp> = withContext(Dispatchers.IO) {
        val pm = context.packageManager
        val installed = runCatching {
            pm.getInstalledApplications(PackageManager.GET_META_DATA)
        }.getOrDefault(emptyList())

        installed.mapNotNull { app ->
            if (app.packageName == context.packageName) return@mapNotNull null
            if (pm.getLaunchIntentForPackage(app.packageName) == null) return@mapNotNull null
            val isVoiceChat = isKnownVoiceChatPackage(app.packageName)
            val isUserApp = (app.flags and ApplicationInfo.FLAG_SYSTEM) == 0
            if (!isVoiceChat && !isUserApp && app.packageName !in selectedPackages) {
                return@mapNotNull null
            }
            val label = runCatching { pm.getApplicationLabel(app).toString() }.getOrDefault(app.packageName)
            com.kaao.security.domain.model.FirewallExceptionApp(
                packageName = app.packageName,
                appName = label,
                isVoiceChatRecommended = isVoiceChat,
                isSelected = app.packageName in selectedPackages
            )
        }.sortedWith(
            compareByDescending<com.kaao.security.domain.model.FirewallExceptionApp> { it.isVoiceChatRecommended }
                .thenByDescending { it.isSelected }
                .thenBy { it.appName.lowercase() }
        )
    }

    companion object {
        val KNOWN_VOICE_CHAT_PACKAGES = setOf(
            "com.discord",
            "com.whatsapp",
            "com.whatsapp.w4b",
            "org.telegram.messenger",
            "org.telegram.plus",
            "org.thoughtcrime.securesms", // Signal
            "com.teamspeak.ts3client",
            "com.skype.raider",
            "com.viber.voip",
            "jp.naver.line.android",
            "com.facebook.orca", // Messenger
            "us.zoom.videomeetings",
            "com.google.android.apps.tachyon" // Meet
        )

        fun isKnownVoiceChatPackage(packageName: String): Boolean =
            packageName in KNOWN_VOICE_CHAT_PACKAGES
    }
}
