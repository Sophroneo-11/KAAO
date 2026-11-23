package com.kaao.security.engine.antivirus

import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Lightweight, resilient parser for Android binary XML (AXML) string pools inside AndroidManifest.xml.
 * Safely handles both UTF-8 and UTF-16LE ResStringPool encodings and tolerates obfuscated/malformed headers.
 */
object BinaryAxmlScanner {

    private const val RES_XML_TYPE = 0x0003
    private const val RES_STRING_POOL_TYPE = 0x0001
    private const val UTF8_FLAG = 1 shl 8

    fun extractStrings(axmlBytes: ByteArray): Set<String> {
        val result = LinkedHashSet<String>()
        if (axmlBytes.size < 16) return result

        runCatching {
            val buf = ByteBuffer.wrap(axmlBytes).order(ByteOrder.LITTLE_ENDIAN)
            val rootType = buf.short.toInt() and 0xFFFF
            val rootHeaderSize = buf.short.toInt() and 0xFFFF
            buf.int // file size

            if (rootType == RES_XML_TYPE && rootHeaderSize in 8 until axmlBytes.size) {
                var offset = rootHeaderSize
                while (offset + 8 <= axmlBytes.size) {
                    val chunkType = readUInt16LE(axmlBytes, offset)
                    val headerSize = readUInt16LE(axmlBytes, offset + 2)
                    val chunkSize = readUInt32LE(axmlBytes, offset + 4)
                    if (chunkSize < 8 || offset + chunkSize > axmlBytes.size) break

                    if (chunkType == RES_STRING_POOL_TYPE && headerSize >= 28 && offset + 28 <= axmlBytes.size) {
                        parseStringPool(axmlBytes, offset, chunkSize, result)
                        break
                    }
                    offset += chunkSize
                }
            }
        }

        // Fallback/supplemental ASCII extraction for malformed or plain-text manifests
        if (result.isEmpty()) {
            extractPrintableAsciiStrings(axmlBytes, result)
        }
        return result
    }

    private fun parseStringPool(
        data: ByteArray,
        chunkStart: Int,
        chunkSize: Int,
        out: MutableSet<String>
    ) {
        val stringCount = readUInt32LE(data, chunkStart + 8)
        val flags = readUInt32LE(data, chunkStart + 16)
        val stringsStart = readUInt32LE(data, chunkStart + 20)
        val isUtf8 = (flags and UTF8_FLAG) != 0
        val poolDataStart = chunkStart + stringsStart
        val chunkEnd = chunkStart + chunkSize

        if (stringCount <= 0 || stringCount > 100_000 || poolDataStart >= chunkEnd) return

        val offsetsBase = chunkStart + 28
        for (i in 0 until stringCount) {
            val offsetPos = offsetsBase + i * 4
            if (offsetPos + 4 > chunkEnd) break
            val relOffset = readUInt32LE(data, offsetPos)
            val strPos = poolDataStart + relOffset
            if (strPos < poolDataStart || strPos >= chunkEnd) continue

            val decoded = if (isUtf8) {
                readUtf8String(data, strPos, chunkEnd)
            } else {
                readUtf16String(data, strPos, chunkEnd)
            }
            if (!decoded.isNullOrBlank()) {
                out.add(decoded)
            }
        }
    }

    private fun readUtf8String(data: ByteArray, start: Int, limit: Int): String? {
        var pos = start
        if (pos >= limit) return null
        // Skip UTF-16 char length varint
        val first = data[pos].toInt() and 0xFF
        pos += if ((first and 0x80) != 0) 2 else 1
        if (pos >= limit) return null
        // Read UTF-8 byte length varint
        val b0 = data[pos].toInt() and 0xFF
        val byteLen = if ((b0 and 0x80) != 0) {
            if (pos + 1 >= limit) return null
            val b1 = data[pos + 1].toInt() and 0xFF
            pos += 2
            ((b0 and 0x7F) shl 8) or b1
        } else {
            pos += 1
            b0
        }
        if (byteLen <= 0 || pos + byteLen > limit) return null
        return String(data, pos, byteLen, Charsets.UTF_8)
    }

    private fun readUtf16String(data: ByteArray, start: Int, limit: Int): String? {
        var pos = start
        if (pos + 2 > limit) return null
        val first = readUInt16LE(data, pos)
        val charLen = if ((first and 0x8000) != 0) {
            if (pos + 4 > limit) return null
            val second = readUInt16LE(data, pos + 2)
            pos += 4
            ((first and 0x7FFF) shl 16) or second
        } else {
            pos += 2
            first
        }
        val byteLen = charLen * 2
        if (charLen <= 0 || pos + byteLen > limit) return null
        return String(data, pos, byteLen, Charsets.UTF_16LE)
    }

    private fun extractPrintableAsciiStrings(data: ByteArray, out: MutableSet<String>) {
        val sb = StringBuilder()
        for (b in data) {
            val c = b.toInt() and 0xFF
            if (c in 32..126) {
                sb.append(c.toChar())
            } else {
                if (sb.length >= 6) out.add(sb.toString())
                sb.clear()
            }
        }
        if (sb.length >= 6) out.add(sb.toString())
    }

    private fun readUInt16LE(data: ByteArray, offset: Int): Int =
        (data[offset].toInt() and 0xFF) or ((data[offset + 1].toInt() and 0xFF) shl 8)

    private fun readUInt32LE(data: ByteArray, offset: Int): Int =
        (data[offset].toInt() and 0xFF) or
            ((data[offset + 1].toInt() and 0xFF) shl 8) or
            ((data[offset + 2].toInt() and 0xFF) shl 16) or
            ((data[offset + 3].toInt() and 0xFF) shl 24)
}
