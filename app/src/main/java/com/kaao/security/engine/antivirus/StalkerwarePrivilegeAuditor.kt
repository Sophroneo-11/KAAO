package com.kaao.security.engine.antivirus

import android.accessibilityservice.AccessibilityServiceInfo
import android.app.AppOpsManager
import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import android.provider.Settings
import android.view.accessibility.AccessibilityManager
import com.kaao.security.domain.model.StalkerwareFinding
import com.kaao.security.domain.model.StalkerwarePrivilege
import com.kaao.security.domain.model.ThreatSeverity
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Active Stalkerware Privilege Auditor.
 * Audits live Device Admins, Accessibility Services, Notification Listeners, and Usage Access holders,
 * correlating non-Play sideloaded installer sources and hidden launcher icons.
 */
@Singleton
class StalkerwarePrivilegeAuditor @Inject constructor(
    @ApplicationContext private val context: Context
) {
    suspend fun auditActivePrivileges(
        whitelistedPackages: Set<String> = emptySet()
    ): List<StalkerwareFinding> = withContext(Dispatchers.IO) {
        val pm = context.packageManager
        val selfPkg = context.packageName

        val privilegeMap = LinkedHashMap<String, MutableSet<StalkerwarePrivilege>>()

        // 1. Active Device Administrators
        val dpm = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as? DevicePolicyManager
        runCatching { dpm?.activeAdmins.orEmpty() }.getOrDefault(emptyList()).forEach { admin ->
            privilegeMap.getOrPut(admin.packageName) { LinkedHashSet() }
                .add(StalkerwarePrivilege.DEVICE_ADMIN)
        }

        // 2. Active Accessibility Services
        val am = context.getSystemService(Context.ACCESSIBILITY_SERVICE) as? AccessibilityManager
        runCatching {
            am?.getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_ALL_MASK).orEmpty()
        }.getOrDefault(emptyList()).forEach { info ->
            val pkg = info.resolveInfo?.serviceInfo?.packageName
            if (!pkg.isNullOrBlank()) {
                privilegeMap.getOrPut(pkg) { LinkedHashSet() }
                    .add(StalkerwarePrivilege.ACCESSIBILITY_SERVICE)
            }
        }
        parseSecureComponentPackages(Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES).forEach { pkg ->
            privilegeMap.getOrPut(pkg) { LinkedHashSet() }
                .add(StalkerwarePrivilege.ACCESSIBILITY_SERVICE)
        }

        // 3. Enabled Notification Listeners
        parseSecureComponentPackages("enabled_notification_listeners").forEach { pkg ->
            privilegeMap.getOrPut(pkg) { LinkedHashSet() }
                .add(StalkerwarePrivilege.NOTIFICATION_LISTENER)
        }

        // 4. Apps granted Usage Access
        val appOps = context.getSystemService(Context.APP_OPS_SERVICE) as? AppOpsManager
        val installedApps = runCatching {
            pm.getInstalledApplications(PackageManager.GET_META_DATA)
        }.getOrDefault(emptyList())

        if (appOps != null) {
            for (app in installedApps) {
                if (isCoreSystemApp(app) || app.packageName == selfPkg) continue
                val allowed = runCatching {
                    val mode = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                        appOps.unsafeCheckOpNoThrow(
                            AppOpsManager.OPSTR_GET_USAGE_STATS,
                            app.uid,
                            app.packageName
                        )
                    } else {
                        @Suppress("DEPRECATION")
                        appOps.checkOpNoThrow(
                            AppOpsManager.OPSTR_GET_USAGE_STATS,
                            app.uid,
                            app.packageName
                        )
                    }
                    mode == AppOpsManager.MODE_ALLOWED
                }.getOrDefault(false)

                if (allowed) {
                    privilegeMap.getOrPut(app.packageName) { LinkedHashSet() }
                        .add(StalkerwarePrivilege.USAGE_ACCESS)
                }
            }
        }

        val findings = mutableListOf<StalkerwareFinding>()
        for ((pkg, privileges) in privilegeMap) {
            if (pkg == selfPkg || pkg in whitelistedPackages) continue
            val appInfo = runCatching { pm.getApplicationInfo(pkg, 0) }.getOrNull() ?: continue
            if (isCoreSystemApp(appInfo)) continue

            val appName = runCatching { pm.getApplicationLabel(appInfo).toString() }.getOrDefault(pkg)
            val installer = resolveInstallerSource(pm, pkg)
            val isSideloaded = installer == "Sideloaded / Unknown"
            val hasLauncherIcon = pm.getLaunchIntentForPackage(pkg) != null

            var score = privileges.sumOf { it.riskPoints }
            if (isSideloaded) score += 20
            if (!hasLauncherIcon) score += 20
            if (privileges.size >= 2) score += 15
            val clampedScore = score.coerceIn(0, 100)

            val severity = when {
                clampedScore >= 75 -> ThreatSeverity.CRITICAL
                clampedScore >= 55 -> ThreatSeverity.HIGH
                clampedScore >= 30 -> ThreatSeverity.MEDIUM
                else -> ThreatSeverity.LOW
            }

            val advisory = buildString {
                append("Holds ${privileges.joinToString { it.label }}.")
                if (isSideloaded) append(" Installed outside trusted app stores.")
                if (!hasLauncherIcon) append(" Hides its icon from the app launcher.")
            }

            findings.add(
                StalkerwareFinding(
                    packageName = pkg,
                    appName = appName,
                    privileges = privileges.toList(),
                    riskScore = clampedScore,
                    severity = severity,
                    installerSource = installer,
                    hasLauncherIcon = hasLauncherIcon,
                    advisory = advisory
                )
            )
        }

        findings.sortedByDescending { it.riskScore }
    }

    private fun parseSecureComponentPackages(settingKey: String): Set<String> {
        val raw = runCatching {
            Settings.Secure.getString(context.contentResolver, settingKey)
        }.getOrNull().orEmpty()
        if (raw.isBlank()) return emptySet()

        return raw.split(':')
            .mapNotNull { token -> ComponentName.unflattenFromString(token)?.packageName }
            .toSet()
    }

    private fun resolveInstallerSource(pm: PackageManager, packageName: String): String {
        val installerPkg = runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                pm.getInstallSourceInfo(packageName).installingPackageName
            } else {
                @Suppress("DEPRECATION")
                pm.getInstallerPackageName(packageName)
            }
        }.getOrNull()

        return when (installerPkg) {
            "com.android.vending" -> "Google Play Store"
            "com.sec.android.app.samsungapps" -> "Samsung Galaxy Store"
            "com.amazon.venezia" -> "Amazon Appstore"
            "org.fdroid.fdroid" -> "F-Droid"
            null, "" -> "Sideloaded / Unknown"
            else -> installerPkg
        }
    }

    private fun isCoreSystemApp(appInfo: ApplicationInfo): Boolean {
        val isSystem = (appInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0
        val isUpdatedSystem = (appInfo.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0
        return isSystem && !isUpdatedSystem
    }
}
