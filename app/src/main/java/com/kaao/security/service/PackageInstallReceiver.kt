package com.kaao.security.service

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/**
 * Dynamically registered receiver for real-time package installation and replacement monitoring.
 */
class PackageInstallReceiver(
    private val onPackageChanged: (String) -> Unit
) : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent?) {
        val action = intent?.action ?: return
        if (action == Intent.ACTION_PACKAGE_ADDED || action == Intent.ACTION_PACKAGE_REPLACED) {
            val packageName = intent.data?.schemeSpecificPart
            if (!packageName.isNullOrBlank() && packageName != context.packageName) {
                onPackageChanged(packageName)
            }
        }
    }
}
