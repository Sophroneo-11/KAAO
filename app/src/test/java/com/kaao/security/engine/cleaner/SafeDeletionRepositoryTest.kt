package com.kaao.security.engine.cleaner

import android.content.Context
import com.kaao.security.data.local.db.WhitelistDao
import com.kaao.security.domain.model.CleanableItem
import com.kaao.security.domain.model.CleanerCategory
import io.mockk.mockk
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

class SafeDeletionRepositoryTest {

    @get:Rule
    val tempFolder = TemporaryFolder()

    @Test
    fun deletesApprovedFileWhileBlockingWhitelistedAndSystemPaths() {
        val repo = SafeDeletionRepository(
            context = mockk<Context>(relaxed = true),
            whitelistDao = mockk<WhitelistDao>(relaxed = true)
        )

        val deletable = File(tempFolder.root, "junk.tmp").apply { writeBytes(ByteArray(2048) { 1 }) }
        val whitelisted = File(tempFolder.root, "keep.tmp").apply { writeBytes(ByteArray(1024) { 2 }) }

        val items = listOf(
            CleanableItem(
                id = "1",
                name = deletable.name,
                path = deletable.absolutePath,
                sizeBytes = deletable.length(),
                lastModifiedMillis = 1L,
                category = CleanerCategory.TEMP_AND_LOGS,
                isSelected = true
            ),
            CleanableItem(
                id = "2",
                name = whitelisted.name,
                path = whitelisted.absolutePath,
                sizeBytes = whitelisted.length(),
                lastModifiedMillis = 1L,
                category = CleanerCategory.TEMP_AND_LOGS,
                isSelected = true
            ),
            CleanableItem(
                id = "3",
                name = "build.prop",
                path = "/system/build.prop",
                sizeBytes = 512L,
                lastModifiedMillis = 1L,
                category = CleanerCategory.TEMP_AND_LOGS,
                isSelected = true
            )
        )

        val result = repo.executeDeletion(
            items = items,
            whitelistedPaths = setOf(whitelisted.absolutePath)
        )

        assertEquals(1, result.deletedCount)
        assertEquals(2048L, result.reclaimedBytes)
        assertEquals(2, result.skippedWhitelistedCount)
        assertFalse(deletable.exists())
        assertTrue(whitelisted.exists())
        assertTrue(repo.isProtectedSystemPath("/system/bin/sh"))
        assertTrue(repo.isProtectedSystemPath("/data/system/packages.xml"))
    }
}
