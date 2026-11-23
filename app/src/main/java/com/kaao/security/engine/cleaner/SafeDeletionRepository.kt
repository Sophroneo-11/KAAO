package com.kaao.security.engine.cleaner

import android.content.Context
import android.net.Uri
import com.kaao.security.data.local.db.WhitelistDao
import com.kaao.security.data.local.db.WhitelistEntryEntity
import com.kaao.security.domain.model.CleanableItem
import com.kaao.security.domain.model.DeletionResult
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.withContext
import java.io.File
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Explicit user-confirmed safe deletion repository.
 * Enforces exclusion whitelist and hard-blocks critical system paths to guarantee zero unintended deletions.
 */
@Singleton
class SafeDeletionRepository @Inject constructor(
    @ApplicationContext private val context: Context,
    private val whitelistDao: WhitelistDao
) {
    val cleanerWhitelistFlow: Flow<List<WhitelistEntryEntity>> =
        whitelistDao.observeByType(StorageScanner.WHITELIST_TYPE_PATH)

    suspend fun addPathToWhitelist(path: String, label: String) = withContext(Dispatchers.IO) {
        whitelistDao.upsert(
            WhitelistEntryEntity(
                entryType = StorageScanner.WHITELIST_TYPE_PATH,
                targetValue = path,
                label = label,
                addedAtMillis = System.currentTimeMillis()
            )
        )
    }

    suspend fun removeWhitelistEntry(id: Long) = withContext(Dispatchers.IO) {
        whitelistDao.deleteById(id)
    }

    /**
     * Deletes ONLY items explicitly approved by the user in the confirmation modal.
     * Re-verifies exclusion whitelist and protected system paths right before every delete call.
     */
    suspend fun deleteConfirmedItems(
        approvedItems: List<CleanableItem>,
        userExplicitlyConfirmed: Boolean
    ): DeletionResult = withContext(Dispatchers.IO) {
        if (!userExplicitlyConfirmed || approvedItems.isEmpty()) {
            return@withContext DeletionResult(0, 0L, 0, 0)
        }

        val whitelistedPaths = whitelistDao.getByType(StorageScanner.WHITELIST_TYPE_PATH)
            .map { it.targetValue }
            .toSet()

        executeDeletion(approvedItems, whitelistedPaths)
    }

    internal fun executeDeletion(
        items: List<CleanableItem>,
        whitelistedPaths: Set<String>
    ): DeletionResult {
        var deletedCount = 0
        var reclaimedBytes = 0L
        var skippedWhitelisted = 0
        var failedCount = 0
        val pendingMediaUris = mutableListOf<Uri>()

        // Delete regular files first, then empty folders deepest-first
        val ordered = items.sortedWith(
            compareBy<CleanableItem> { it.sizeBytes == 0L }.thenByDescending { it.path.length }
        )

        for (item in ordered) {
            if (isWhitelisted(item.path, whitelistedPaths) || isProtectedSystemPath(item.path)) {
                skippedWhitelisted++
                continue
            }

            val contentUri = item.contentUri
            if (contentUri != null) {
                val deletedRows = runCatching {
                    context.contentResolver.delete(contentUri, null, null)
                }.getOrElse { -1 }

                when {
                    deletedRows > 0 -> {
                        deletedCount++
                        reclaimedBytes += item.sizeBytes
                    }

                    deletedRows == -1 -> {
                        // On API 30+, non-owned MediaStore items require MediaStore.createDeleteRequest
                        pendingMediaUris.add(contentUri)
                    }

                    else -> failedCount++
                }
            } else {
                val file = File(item.path)
                val deleted = runCatching {
                    if (!file.exists()) {
                        false
                    } else if (file.isDirectory) {
                        file.listFiles().isNullOrEmpty() && file.delete()
                    } else {
                        file.delete()
                    }
                }.getOrDefault(false)

                if (deleted) {
                    deletedCount++
                    reclaimedBytes += item.sizeBytes
                } else {
                    failedCount++
                }
            }
        }

        return DeletionResult(
            deletedCount = deletedCount,
            reclaimedBytes = reclaimedBytes,
            skippedWhitelistedCount = skippedWhitelisted,
            failedCount = failedCount,
            pendingMediaStoreUris = pendingMediaUris
        )
    }

    internal fun isProtectedSystemPath(path: String): Boolean {
        val normalized = path.trim().lowercase()
        return PROTECTED_PREFIXES.any { normalized == it || normalized.startsWith("$it/") }
    }

    private fun isWhitelisted(path: String, whitelist: Set<String>): Boolean =
        whitelist.any { entry -> path == entry || path.startsWith("$entry/") }

    companion object {
        private val PROTECTED_PREFIXES = listOf(
            "/system",
            "/vendor",
            "/product",
            "/proc",
            "/sys",
            "/dev",
            "/data/system"
        )
    }
}
