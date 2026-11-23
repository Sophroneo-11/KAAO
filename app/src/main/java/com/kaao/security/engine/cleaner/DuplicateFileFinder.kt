package com.kaao.security.engine.cleaner

import com.kaao.security.core.crypto.HashUtils
import com.kaao.security.domain.model.CleanableItem
import com.kaao.security.domain.model.CleanerCategory
import java.io.File
import javax.inject.Inject
import javax.inject.Singleton

/**
 * 3-Stage Duplicate File Finder:
 * Stage 1: Exact file size grouping (O(n), zero file reads).
 * Stage 2: Fast 3-region partial SHA-256 (head + middle + tail 4 KiB) to filter collisions.
 * Stage 3: Full streaming SHA-256 to guarantee byte-for-byte identity before proposing removal.
 */
@Singleton
class DuplicateFileFinder @Inject constructor() {

    fun findDuplicates(
        files: List<File>,
        whitelistedPaths: Set<String> = emptySet(),
        minSizeBytes: Long = MIN_DUPLICATE_SIZE_BYTES
    ): List<CleanableItem> {
        // Stage 1: Group by exact byte size
        val bySize = LinkedHashMap<Long, MutableList<File>>()
        for (file in files) {
            if (!file.isFile || !file.canRead()) continue
            val size = file.length()
            if (size < minSizeBytes) continue
            if (isWhitelisted(file.absolutePath, whitelistedPaths)) continue
            bySize.getOrPut(size) { mutableListOf() }.add(file)
        }

        val sizeCandidates = bySize.values.filter { it.size >= 2 }
        if (sizeCandidates.isEmpty()) return emptyList()

        // Stage 2: Partial 3-region SHA-256
        val byPartialHash = LinkedHashMap<String, MutableList<File>>()
        for (group in sizeCandidates) {
            for (file in group) {
                val partialHash = HashUtils.partialSha256FileHex(file) ?: continue
                byPartialHash.getOrPut("${file.length()}:$partialHash") { mutableListOf() }.add(file)
            }
        }

        val partialCandidates = byPartialHash.values.filter { it.size >= 2 }
        if (partialCandidates.isEmpty()) return emptyList()

        // Stage 3: Full streaming SHA-256 verification
        val byFullHash = LinkedHashMap<String, MutableList<File>>()
        for (group in partialCandidates) {
            for (file in group) {
                val fullHash = HashUtils.sha256FileHex(file) ?: continue
                byFullHash.getOrPut(fullHash) { mutableListOf() }.add(file)
            }
        }

        val verifiedItems = mutableListOf<CleanableItem>()
        for ((fullHash, copies) in byFullHash) {
            if (copies.size < 2) continue
            // Keep oldest (or shortest path) copy as suggested original
            val sorted = copies.sortedWith(compareBy<File> { it.lastModified() }.thenBy { it.absolutePath.length })
            val shortGroup = fullHash.take(8)
            sorted.forEachIndexed { index, file ->
                val isOriginal = index == 0
                verifiedItems.add(
                    CleanableItem(
                        id = "dup:${file.absolutePath}",
                        name = file.name,
                        path = file.absolutePath,
                        sizeBytes = file.length(),
                        lastModifiedMillis = file.lastModified(),
                        category = CleanerCategory.DUPLICATES,
                        duplicateGroupId = shortGroup,
                        isSuggestedOriginal = isOriginal,
                        detailBadge = if (isOriginal) "Original (#$shortGroup)" else "Duplicate (#$shortGroup)",
                        isSelected = !isOriginal
                    )
                )
            }
        }
        return verifiedItems.sortedWith(
            compareByDescending<CleanableItem> { it.sizeBytes }
                .thenBy { it.duplicateGroupId }
                .thenBy { !it.isSuggestedOriginal }
        )
    }

    private fun isWhitelisted(path: String, whitelist: Set<String>): Boolean {
        return whitelist.any { entry -> path == entry || path.startsWith("$entry/") }
    }

    companion object {
        const val MIN_DUPLICATE_SIZE_BYTES = 1024L // 1 KiB minimum
    }
}
