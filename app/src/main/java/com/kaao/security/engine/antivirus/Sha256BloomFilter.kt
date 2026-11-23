package com.kaao.security.engine.antivirus

import com.kaao.security.core.crypto.HashUtils
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.util.concurrent.atomic.AtomicReference
import javax.inject.Inject
import javax.inject.Singleton
import kotlin.math.ceil
import kotlin.math.ln
import kotlin.math.max

/**
 * Lock-free SHA-256 Bloom Filter backed by an immutable snapshot inside AtomicReference.
 * Uses Kirsch-Mitzenmacher double hashing directly over the 32-byte SHA-256 digest (zero extra hashing).
 */
@Singleton
class Sha256BloomFilter @Inject constructor() {

    data class BloomSnapshot(
        val bits: LongArray,
        val bitSize: Int,
        val hashCount: Int,
        val insertedCount: Int
    ) {
        fun mightContain(sha256Bytes: ByteArray): Boolean {
            if (bitSize <= 0 || insertedCount == 0 || sha256Bytes.size < 16) return false
            val h1 = readLongBigEndian(sha256Bytes, 0)
            val h2 = readLongBigEndian(sha256Bytes, 8) or 1L
            for (i in 0 until hashCount) {
                val combined = (h1 + i.toLong() * h2) and Long.MAX_VALUE
                val bitIndex = (combined % bitSize.toLong()).toInt()
                val word = bits[bitIndex ushr 6]
                if ((word and (1L shl (bitIndex and 63))) == 0L) {
                    return false
                }
            }
            return true
        }

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is BloomSnapshot) return false
            return bitSize == other.bitSize &&
                hashCount == other.hashCount &&
                insertedCount == other.insertedCount &&
                bits.contentEquals(other.bits)
        }

        override fun hashCode(): Int {
            var result = bits.contentHashCode()
            result = 31 * result + bitSize
            result = 31 * result + hashCount
            result = 31 * result + insertedCount
            return result
        }
    }

    private val snapshotRef = AtomicReference(
        BloomSnapshot(LongArray(0), bitSize = 0, hashCount = 0, insertedCount = 0)
    )

    val itemCount: Int
        get() = snapshotRef.get().insertedCount

    val bitCapacity: Int
        get() = snapshotRef.get().bitSize

    fun rebuildFromHexHashes(
        sha256HexList: Collection<String>,
        falsePositiveRate: Double = DEFAULT_FPR
    ): BloomSnapshot {
        val expectedItems = max(sha256HexList.size, MIN_CAPACITY)
        val clampedFpr = falsePositiveRate.coerceIn(0.00001, 0.1)
        val rawBits = ceil(-(expectedItems * ln(clampedFpr)) / (LN2 * LN2)).toInt()
        val bitSize = max(rawBits, 1024)
        val wordCount = (bitSize + 63) ushr 6
        val actualBitSize = wordCount * 64
        val hashCount = ceil((actualBitSize.toDouble() / expectedItems.toDouble()) * LN2)
            .toInt()
            .coerceIn(3, 16)

        val bits = LongArray(wordCount)
        var validInserted = 0

        for (hex in sha256HexList) {
            val bytes = runCatching { HashUtils.fromHex(hex) }.getOrNull() ?: continue
            if (bytes.size < 16) continue
            val h1 = readLongBigEndian(bytes, 0)
            val h2 = readLongBigEndian(bytes, 8) or 1L
            for (i in 0 until hashCount) {
                val combined = (h1 + i.toLong() * h2) and Long.MAX_VALUE
                val bitIndex = (combined % actualBitSize.toLong()).toInt()
                bits[bitIndex ushr 6] = bits[bitIndex ushr 6] or (1L shl (bitIndex and 63))
            }
            validInserted++
        }

        val newSnapshot = BloomSnapshot(
            bits = bits,
            bitSize = actualBitSize,
            hashCount = hashCount,
            insertedCount = validInserted
        )
        snapshotRef.set(newSnapshot)
        return newSnapshot
    }

    fun mightContainHex(sha256Hex: String): Boolean {
        val bytes = runCatching { HashUtils.fromHex(sha256Hex) }.getOrNull() ?: return false
        return snapshotRef.get().mightContain(bytes)
    }

    fun mightContainBytes(sha256Bytes: ByteArray): Boolean =
        snapshotRef.get().mightContain(sha256Bytes)

    fun serialize(output: OutputStream) {
        val snap = snapshotRef.get()
        val dos = DataOutputStream(output)
        dos.writeInt(MAGIC)
        dos.writeInt(snap.bitSize)
        dos.writeInt(snap.hashCount)
        dos.writeInt(snap.insertedCount)
        dos.writeInt(snap.bits.size)
        for (word in snap.bits) {
            dos.writeLong(word)
        }
        dos.flush()
    }

    fun deserializeAndSwap(input: InputStream): Boolean = runCatching {
        val dis = DataInputStream(input)
        val magic = dis.readInt()
        if (magic != MAGIC) return false
        val bitSize = dis.readInt()
        val hashCount = dis.readInt()
        val insertedCount = dis.readInt()
        val wordCount = dis.readInt()
        if (wordCount < 0 || wordCount > 10_000_000 || bitSize != wordCount * 64) return false
        val bits = LongArray(wordCount) { dis.readLong() }
        snapshotRef.set(BloomSnapshot(bits, bitSize, hashCount, insertedCount))
        true
    }.getOrDefault(false)

    companion object {
        private const val MAGIC = 0x4B41414F // "KAAO"
        private const val DEFAULT_FPR = 0.001
        private const val MIN_CAPACITY = 256
        private const val LN2 = 0.6931471805599453

        private fun readLongBigEndian(bytes: ByteArray, offset: Int): Long {
            var value = 0L
            for (i in 0 until 8) {
                value = (value shl 8) or (bytes[offset + i].toLong() and 0xFFL)
            }
            return value
        }
    }
}
