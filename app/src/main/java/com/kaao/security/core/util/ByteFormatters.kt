package com.kaao.security.core.util

import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import kotlin.math.ln
import kotlin.math.pow

object ByteFormatters {

    fun formatBytes(bytes: Long): String {
        if (bytes < 0L) return "0 B"
        if (bytes < 1024L) return "$bytes B"
        val exp = (ln(bytes.toDouble()) / ln(1024.0)).toInt().coerceAtMost(4)
        val unit = "KMGT"[exp - 1]
        val value = bytes / 1024.0.pow(exp.toDouble())
        return String.format(Locale.US, "%.1f %sB", value, unit)
    }

    fun formatTimestamp(epochMillis: Long): String {
        if (epochMillis <= 0L) return "Never"
        val formatter = SimpleDateFormat("MMM dd, HH:mm", Locale.US)
        return formatter.format(Date(epochMillis))
    }

    fun formatShortTime(epochMillis: Long): String {
        if (epochMillis <= 0L) return "--:--"
        val formatter = SimpleDateFormat("HH:mm:ss", Locale.US)
        return formatter.format(Date(epochMillis))
    }
}
