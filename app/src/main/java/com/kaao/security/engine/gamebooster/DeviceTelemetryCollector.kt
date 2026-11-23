package com.kaao.security.engine.gamebooster

import android.app.ActivityManager
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.BatteryManager
import android.os.Build
import android.os.PowerManager
import android.os.SystemClock
import com.kaao.security.domain.model.DeviceTelemetry
import com.kaao.security.domain.model.ThreatSeverity
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.isActive
import kotlinx.coroutines.withContext
import java.net.InetSocketAddress
import java.net.Socket
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class DeviceTelemetryCollector @Inject constructor(
    @ApplicationContext private val context: Context
) {
    fun observeTelemetry(intervalMs: Long = 2500L): Flow<DeviceTelemetry> = flow {
        while (currentCoroutineContext().isActive) {
            emit(sampleOnce())
            delay(intervalMs)
        }
    }.flowOn(Dispatchers.IO)

    suspend fun sampleOnce(): DeviceTelemetry = withContext(Dispatchers.IO) {
        val (thermalLabel, thermalSeverity, headroom) = readThermalState()
        val (batteryPct, batteryTempC, isCharging) = readBatteryState()
        val (availRam, totalRam, ramPct) = readRamState()
        val pingMs = measureTcpPingMs()

        DeviceTelemetry(
            thermalStatusLabel = thermalLabel,
            thermalSeverity = thermalSeverity,
            thermalHeadroom = headroom,
            batteryPercent = batteryPct,
            batteryTempCelsius = batteryTempC,
            isCharging = isCharging,
            availableRamBytes = availRam,
            totalRamBytes = totalRam,
            ramUsagePercent = ramPct,
            tcpPingMs = pingMs,
            updatedAtMillis = System.currentTimeMillis()
        )
    }

    private fun readThermalState(): Triple<String, ThreatSeverity, Float?> {
        val pm = context.getSystemService(Context.POWER_SERVICE) as? PowerManager
            ?: return Triple("Nominal", ThreatSeverity.SAFE, null)

        val headroom = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            runCatching { pm.getThermalHeadroom(5) }.getOrNull()?.takeIf { !it.isNaN() && it >= 0f }
        } else {
            null
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            return when (pm.currentThermalStatus) {
                PowerManager.THERMAL_STATUS_NONE -> Triple("Cool", ThreatSeverity.SAFE, headroom)
                PowerManager.THERMAL_STATUS_LIGHT -> Triple("Warm", ThreatSeverity.LOW, headroom)
                PowerManager.THERMAL_STATUS_MODERATE -> Triple("Moderate", ThreatSeverity.MEDIUM, headroom)
                PowerManager.THERMAL_STATUS_SEVERE -> Triple("Hot (Throttling)", ThreatSeverity.HIGH, headroom)
                PowerManager.THERMAL_STATUS_CRITICAL,
                PowerManager.THERMAL_STATUS_EMERGENCY,
                PowerManager.THERMAL_STATUS_SHUTDOWN -> Triple("Critical Heat", ThreatSeverity.CRITICAL, headroom)
                else -> Triple("Nominal", ThreatSeverity.SAFE, headroom)
            }
        }
        return Triple("Nominal", ThreatSeverity.SAFE, headroom)
    }

    private fun readBatteryState(): Triple<Int, Float, Boolean> {
        val batteryIntent = runCatching {
            context.registerReceiver(null, IntentFilter(Intent.ACTION_BATTERY_CHANGED))
        }.getOrNull() ?: return Triple(100, 28.0f, false)

        val level = batteryIntent.getIntExtra(BatteryManager.EXTRA_LEVEL, 100)
        val scale = batteryIntent.getIntExtra(BatteryManager.EXTRA_SCALE, 100).coerceAtLeast(1)
        val pct = ((level * 100f) / scale).toInt().coerceIn(0, 100)

        val tempTenths = batteryIntent.getIntExtra(BatteryManager.EXTRA_TEMPERATURE, 280)
        val tempC = tempTenths / 10f

        val status = batteryIntent.getIntExtra(BatteryManager.EXTRA_STATUS, -1)
        val charging = status == BatteryManager.BATTERY_STATUS_CHARGING ||
            status == BatteryManager.BATTERY_STATUS_FULL

        return Triple(pct, tempC, charging)
    }

    private fun readRamState(): Triple<Long, Long, Int> {
        val am = context.getSystemService(Context.ACTIVITY_SERVICE) as? ActivityManager
            ?: return Triple(0L, 0L, 0)
        val memInfo = ActivityManager.MemoryInfo()
        am.getMemoryInfo(memInfo)
        val total = memInfo.totalMem.coerceAtLeast(1L)
        val avail = memInfo.availMem.coerceIn(0L, total)
        val usedPct = (((total - avail).toDouble() / total.toDouble()) * 100.0).toInt().coerceIn(0, 100)
        return Triple(avail, total, usedPct)
    }

    private fun measureTcpPingMs(): Long? {
        for ((host, port) in PING_TARGETS) {
            val measured = runCatching {
                Socket().use { socket ->
                    val start = SystemClock.elapsedRealtime()
                    socket.connect(InetSocketAddress(host, port), TCP_TIMEOUT_MS)
                    SystemClock.elapsedRealtime() - start
                }
            }.getOrNull()
            if (measured != null) return measured
        }
        return null
    }

    companion object {
        private const val TCP_TIMEOUT_MS = 1200
        private val PING_TARGETS = listOf(
            "1.1.1.1" to 443,
            "8.8.8.8" to 443
        )
    }
}
