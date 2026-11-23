package com.kaao.security.engine.antivirus

import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder

class BinaryAxmlScannerTest {

    private fun buildBinaryAxmlWithStringPool(strings: List<String>, utf8: Boolean): ByteArray {
        val poolData = ByteArrayOutputStream()
        val offsets = IntArray(strings.size)

        strings.forEachIndexed { index, s ->
            offsets[index] = poolData.size()
            if (utf8) {
                val utf8Bytes = s.toByteArray(Charsets.UTF_8)
                poolData.write(s.length and 0x7F)
                poolData.write(utf8Bytes.size and 0x7F)
                poolData.write(utf8Bytes)
                poolData.write(0)
            } else {
                val utf16Bytes = s.toByteArray(Charsets.UTF_16LE)
                poolData.write(s.length and 0xFF)
                poolData.write((s.length ushr 8) and 0xFF)
                poolData.write(utf16Bytes)
                poolData.write(0)
                poolData.write(0)
            }
        }

        val dataBytes = poolData.toByteArray()
        val headerSize = 28
        val stringsStart = headerSize + strings.size * 4
        val chunkSize = stringsStart + dataBytes.size
        val totalSize = 8 + chunkSize

        val buf = ByteBuffer.allocate(totalSize).order(ByteOrder.LITTLE_ENDIAN)
        // Root RES_XML_TYPE
        buf.putShort(0x0003)
        buf.putShort(8)
        buf.putInt(totalSize)
        // RES_STRING_POOL_TYPE
        buf.putShort(0x0001)
        buf.putShort(headerSize.toShort())
        buf.putInt(chunkSize)
        buf.putInt(strings.size) // stringCount
        buf.putInt(0)            // styleCount
        buf.putInt(if (utf8) (1 shl 8) else 0) // flags
        buf.putInt(stringsStart)
        buf.putInt(0)            // stylesStart
        offsets.forEach { buf.putInt(it) }
        buf.put(dataBytes)
        return buf.array()
    }

    @Test
    fun extractsUtf8StringsFromValidBinaryAxmlPool() {
        val axml = buildBinaryAxmlWithStringPool(
            listOf("android.permission.BIND_ACCESSIBILITY_SERVICE", "android.permission.READ_SMS"),
            utf8 = true
        )
        val extracted = BinaryAxmlScanner.extractStrings(axml)
        assertTrue("android.permission.BIND_ACCESSIBILITY_SERVICE" in extracted)
        assertTrue("android.permission.READ_SMS" in extracted)
    }

    @Test
    fun extractsUtf16StringsFromValidBinaryAxmlPool() {
        val axml = buildBinaryAxmlWithStringPool(
            listOf("android.permission.SYSTEM_ALERT_WINDOW", "android.permission.BIND_DEVICE_ADMIN"),
            utf8 = false
        )
        val extracted = BinaryAxmlScanner.extractStrings(axml)
        assertTrue("android.permission.SYSTEM_ALERT_WINDOW" in extracted)
        assertTrue("android.permission.BIND_DEVICE_ADMIN" in extracted)
    }
}
