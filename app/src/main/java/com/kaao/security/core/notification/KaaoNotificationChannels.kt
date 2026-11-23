package com.kaao.security.core.notification

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import androidx.core.app.NotificationCompat
import com.kaao.security.MainActivity
import com.kaao.security.R

object KaaoNotificationChannels {
    const val CHANNEL_SHIELD = "kaao_shield_ongoing"
    const val CHANNEL_THREATS = "kaao_threat_alerts"
    const val CHANNEL_SCAN = "kaao_deep_scan"
    const val CHANNEL_GAME = "kaao_game_booster"

    const val NOTIF_ID_VPN = 1001
    const val NOTIF_ID_REALTIME = 1002
    const val NOTIF_ID_SCAN = 1003
    const val NOTIF_ID_GAME_HUD = 1004
    const val NOTIF_ID_THREAT_BASE = 2000

    fun registerAll(context: Context) {
        val manager = context.getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager
            ?: return

        val channels = listOf(
            NotificationChannel(
                CHANNEL_SHIELD,
                context.getString(R.string.notif_channel_shield),
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = context.getString(R.string.notif_channel_shield_desc)
                setShowBadge(false)
            },
            NotificationChannel(
                CHANNEL_THREATS,
                context.getString(R.string.notif_channel_threats),
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = context.getString(R.string.notif_channel_threats_desc)
                enableVibration(true)
            },
            NotificationChannel(
                CHANNEL_SCAN,
                context.getString(R.string.notif_channel_scan),
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = context.getString(R.string.notif_channel_scan_desc)
                setShowBadge(false)
            },
            NotificationChannel(
                CHANNEL_GAME,
                context.getString(R.string.notif_channel_game),
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = context.getString(R.string.notif_channel_game_desc)
                setShowBadge(false)
            }
        )
        manager.createNotificationChannels(channels)
    }

    fun buildLaunchAppPendingIntent(context: Context, requestCode: Int = 0): PendingIntent {
        val intent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        return PendingIntent.getActivity(
            context,
            requestCode,
            intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
    }

    fun buildOngoingShieldNotification(
        context: Context,
        title: String,
        subtitle: String
    ): Notification {
        return NotificationCompat.Builder(context, CHANNEL_SHIELD)
            .setSmallIcon(R.drawable.ic_kaao_shield_notif)
            .setContentTitle(title)
            .setContentText(subtitle)
            .setOngoing(true)
            .setSilent(true)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setContentIntent(buildLaunchAppPendingIntent(context, 10))
            .build()
    }

    fun buildThreatAlertNotification(
        context: Context,
        title: String,
        details: String
    ): Notification {
        return NotificationCompat.Builder(context, CHANNEL_THREATS)
            .setSmallIcon(R.drawable.ic_kaao_shield_notif)
            .setContentTitle(title)
            .setContentText(details)
            .setStyle(NotificationCompat.BigTextStyle().bigText(details))
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setCategory(NotificationCompat.CATEGORY_ALARM)
            .setAutoCancel(true)
            .setContentIntent(buildLaunchAppPendingIntent(context, 20))
            .build()
    }
}
