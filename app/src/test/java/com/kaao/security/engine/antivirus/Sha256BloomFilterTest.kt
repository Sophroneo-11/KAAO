package com.kaao.security.engine.antivirus

import com.kaao.security.core.crypto.HashUtils
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream

class Sha256BloomFilterTest {

    @Test
    fun insertedHashesHaveZeroFalseNegativesAndLowFalsePositives() {
        val filter = Sha256BloomFilter()
        val inserted = (0 until 1000).map { i -> HashUtils.sha256Hex("malware-sample-$i") }

        val snapshot = filter.rebuildFromHexHashes(inserted, falsePositiveRate = 0.001)
        assertEquals(1000, snapshot.insertedCount)
        assertTrue(snapshot.bitSize >= 1024)

        for (hash in inserted) {
            assertTrue("Expected zero false negatives for $hash", filter.mightContainHex(hash))
        }

        var falsePositives = 0
        val probeCount = 2000
        for (i in 0 until probeCount) {
            val probe = HashUtils.sha256Hex("benign-app-$i")
            if (filter.mightContainHex(probe)) {
                falsePositives++
            }
        }
        assertTrue("False positive rate too high: $falsePositives / $probeCount", falsePositives < 20)
    }

    @Test
    fun serializeAndDeserializeRoundTripPreservesMembership() {
        val original = Sha256BloomFilter()
        val eicar = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
        val second = HashUtils.sha256Hex("trojan-dropper-v2")
        original.rebuildFromHexHashes(listOf(eicar, second))

        val baos = ByteArrayOutputStream()
        original.serialize(baos)

        val restored = Sha256BloomFilter()
        assertFalse(restored.mightContainHex(eicar))
        assertTrue(restored.deserializeAndSwap(ByteArrayInputStream(baos.toByteArray())))
        assertEquals(2, restored.itemCount)
        assertTrue(restored.mightContainHex(eicar))
        assertTrue(restored.mightContainHex(second))
        assertFalse(restored.mightContainHex(HashUtils.sha256Hex("clean-file")))
    }
}
