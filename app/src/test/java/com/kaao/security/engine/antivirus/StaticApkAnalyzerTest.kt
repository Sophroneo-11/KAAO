package com.kaao.security.engine.antivirus

import com.kaao.security.domain.model.ThreatSeverity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.io.FileOutputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

class StaticApkAnalyzerTest {

    @get:Rule
    val tempFolder = TemporaryFolder()

    private val analyzer = StaticApkAnalyzer()

    private fun createSyntheticApk(name: String, entries: Map<String, ByteArray>): File {
        val file = tempFolder.newFile(name)
        ZipOutputStream(FileOutputStream(file)).use { zos ->
            for ((entryName, bytes) in entries) {
                zos.putNextEntry(ZipEntry(entryName))
                zos.write(bytes)
                zos.closeEntry()
            }
        }
        return file
    }

    @Test
    fun cleanApkScoresSafeWithZeroReasons() {
        val dexHeader = byteArrayOf(0x64, 0x65, 0x78, 0x0A, 0x30, 0x33, 0x35, 0x00) +
            "Lcom/example/Calculator;".toByteArray()
        val manifest = "android.permission.INTERNET".toByteArray()
        val apk = createSyntheticApk(
            "clean.apk",
            mapOf(
                "AndroidManifest.xml" to manifest,
                "classes.dex" to dexHeader
            )
        )

        val result = analyzer.analyzeApk(apk)
        assertNotNull(result)
        result!!
        assertEquals(ThreatSeverity.SAFE, result.severity)
        assertEquals(0, result.riskScore)
        assertEquals(1, result.dexCount)
        assertEquals(0, result.hiddenAssetCount)
    }

    @Test
    fun maliciousApkWithOverlayAccessibilityDynamicDexAndHiddenPayloadFlagsCritical() {
        val manifest = listOf(
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.READ_SMS",
            "android.permission.RECEIVE_BOOT_COMPLETED"
        ).joinToString("\u0000").toByteArray()

        val dexPayload = byteArrayOf(0x64, 0x65, 0x78, 0x0A, 0x30, 0x33, 0x39, 0x00) +
            "Ldalvik/system/DexClassLoader; SmsManager sendTextMessage performGlobalAction AccessibilityNodeInfo".toByteArray()

        // Hidden DEX masquerading as a PNG image
        val fakePngHoldingDex = byteArrayOf(0x64, 0x65, 0x78, 0x0A, 0x30, 0x33, 0x35, 0x00, 0x11, 0x22)

        val apk = createSyntheticApk(
            "dropper.apk",
            mapOf(
                "AndroidManifest.xml" to manifest,
                "classes.dex" to dexPayload,
                "assets/splash_icon.png" to fakePngHoldingDex
            )
        )

        val result = analyzer.analyzeApk(apk)
        assertNotNull(result)
        result!!
        assertEquals(ThreatSeverity.CRITICAL, result.severity)
        assertTrue("Expected high risk score >= 75, got ${result.riskScore}", result.riskScore >= 75)
        assertEquals(1, result.hiddenAssetCount)
        assertTrue(result.reasons.any { it.contains("masquerading", ignoreCase = true) })
    }
}
