package com.kaao.security.engine.cleaner

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

class DuplicateFileFinderTest {

    @get:Rule
    val tempFolder = TemporaryFolder()

    private val finder = DuplicateFileFinder()

    @Test
    fun threeStageDuplicateFinderDistinguishesPartialCollisionsAndRespectsWhitelist() {
        val baseSize = 32 * 1024 // 32 KiB (> 3 * 4 KiB partial window)
        val payloadA = ByteArray(baseSize) { (it % 251).toByte() }
        val payloadSameHeadMidTailDiffInterior = payloadA.copyOf().apply {
            // Mutate byte outside head (0..4095), mid (14336..18431), and tail (28672..32767)
            this[6000] = (this[6000].toInt() xor 0xFF).toByte()
        }
        val payloadDiffMid = payloadA.copyOf().apply {
            this[16000] = (this[16000].toInt() xor 0xAA).toByte()
        }

        val orig = File(tempFolder.root, "photo_original.jpg").apply {
            writeBytes(payloadA)
            setLastModified(1_000_000L)
        }
        val dupCopy = File(tempFolder.root, "photo_copy.jpg").apply {
            writeBytes(payloadA)
            setLastModified(2_000_000L)
        }
        val stage3Reject = File(tempFolder.root, "stage3_diff.jpg").apply {
            writeBytes(payloadSameHeadMidTailDiffInterior)
        }
        val stage2Reject = File(tempFolder.root, "stage2_diff.jpg").apply {
            writeBytes(payloadDiffMid)
        }
        val uniqueSize = File(tempFolder.root, "unique.jpg").apply {
            writeBytes(ByteArray(baseSize + 17) { 7 })
        }
        val whitelistedDup = File(tempFolder.root, "protected_copy.jpg").apply {
            writeBytes(payloadA)
        }

        val results = finder.findDuplicates(
            files = listOf(orig, dupCopy, stage3Reject, stage2Reject, uniqueSize, whitelistedDup),
            whitelistedPaths = setOf(whitelistedDup.absolutePath),
            minSizeBytes = 1024L
        )

        // Only orig and dupCopy should remain (whitelistedDup excluded, stage2 & stage3 rejected)
        assertEquals(2, results.size)
        val originalItem = results.first { it.path == orig.absolutePath }
        val duplicateItem = results.first { it.path == dupCopy.absolutePath }

        assertTrue(originalItem.isSuggestedOriginal)
        assertFalse(originalItem.isSelected)
        assertFalse(duplicateItem.isSuggestedOriginal)
        assertTrue(duplicateItem.isSelected)
        assertEquals(originalItem.duplicateGroupId, duplicateItem.duplicateGroupId)
    }
}
