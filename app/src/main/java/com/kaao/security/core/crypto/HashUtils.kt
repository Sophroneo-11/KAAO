package com.kaao.security.core.crypto

import java.io.File
import java.io.FileInputStream
import java.io.InputStream
import java.io.RandomAccessFile
import java.security.MessageDigest

object HashUtils {

    private const val STREAM_BUFFER_SIZE = 64 * 1024
    private const val PARTIAL_CHUNK_SIZE = 4 * 1024
    private val HEX_CHARS = "0123456789abcdef".toCharArray()

    fun sha256Bytes(data: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(data)

    fun sha256Hex(data: ByteArray): String = toHex(sha256Bytes(data))

    fun sha256Hex(text: String): String = sha256Hex(text.toByteArray(Charsets.UTF_8))

    fun sha256Stream(inputStream: InputStream): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        val buffer = ByteArray(STREAM_BUFFER_SIZE)
        while (true) {
            val read = inputStream.read(buffer)
            if (read <= 0) break
            digest.update(buffer, 0, read)
        }
        return digest.digest()
    }

    fun sha256File(file: File): ByteArray? = runCatching {
        FileInputStream(file).use { sha256Stream(it) }
    }.getOrNull()

    fun sha256FileHex(file: File): String? = sha256File(file)?.let(::toHex)

    /**
     * Stage-2 duplicate finder hash: hashes file size + up to 3 strategic 4 KiB slices
     * (head, middle, tail) to reject non-duplicates with minimal disk I/O.
     */
    fun partialSha256FileHex(file: File): String? = runCatching {
        val length = file.length()
        if (length <= PARTIAL_CHUNK_SIZE * 3L) {
            return sha256FileHex(file)
        }
        val digest = MessageDigest.getInstance("SHA-256")
        digest.update(length.toString().toByteArray(Charsets.UTF_8))
        val buffer = ByteArray(PARTIAL_CHUNK_SIZE)
        RandomAccessFile(file, "r").use { raf ->
            // Head slice
            raf.seek(0L)
            val headRead = raf.read(buffer)
            if (headRead > 0) digest.update(buffer, 0, headRead)

            // Middle slice
            val midOffset = (length / 2L) - (PARTIAL_CHUNK_SIZE / 2L)
            raf.seek(midOffset.coerceAtLeast(0L))
            val midRead = raf.read(buffer)
            if (midRead > 0) digest.update(buffer, 0, midRead)

            // Tail slice
            val tailOffset = (length - PARTIAL_CHUNK_SIZE).coerceAtLeast(0L)
            raf.seek(tailOffset)
            val tailRead = raf.read(buffer)
            if (tailRead > 0) digest.update(buffer, 0, tailRead)
        }
        toHex(digest.digest())
    }.getOrNull()

    fun toHex(bytes: ByteArray): String {
        val result = CharArray(bytes.size * 2)
        for (i in bytes.indices) {
            val v = bytes[i].toInt() and 0xFF
            result[i * 2] = HEX_CHARS[v ushr 4]
            result[i * 2 + 1] = HEX_CHARS[v and 0x0F]
        }
        return String(result)
    }

    fun fromHex(hex: String): ByteArray {
        val clean = hex.trim().lowercase()
        require(clean.length % 2 == 0) { "Hex string must have even length" }
        val result = ByteArray(clean.length / 2)
        for (i in result.indices) {
            val hi = Character.digit(clean[i * 2], 16)
            val lo = Character.digit(clean[i * 2 + 1], 16)
            require(hi >= 0 && lo >= 0) { "Invalid hex character in SHA-256 digest" }
            result[i] = ((hi shl 4) or lo).toByte()
        }
        return result
    }
}
