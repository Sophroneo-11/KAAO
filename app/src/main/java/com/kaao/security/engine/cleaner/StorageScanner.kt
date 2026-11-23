package com.kaao.security.engine.cleaner

import android.content.ContentUris
import android.content.Context
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.os.StatFs
import android.provider.MediaStore
import com.kaao.security.core.crypto.HashUtils
import com.kaao.security.core.permission.PermissionManager
import com.kaao.security.core.permission.StorageScanMode
import com.kaao.security.data.local.db.WhitelistDao
import com.kaao.security.domain.model.CleanableItem
import com.kaao.security.domain.model.CleanerCategory
import com.kaao.security.domain.model.CleanerScanResult
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext
import java.io.File
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class StorageScanner @Inject constructor(
    @ApplicationContext private val context: Context,
    private val permissionManager: PermissionManager,
    private val duplicateFileFinder: DuplicateFileFinder,
    private val appStorageAnalyzer: AppStorageAnalyzer,
    private val whitelistDao: WhitelistDao
) {
    private val _scanResult = MutableStateFlow(CleanerScanResult())
    val scanResult: StateFlow<CleanerScanResult> = _scanResult.asStateFlow()

    private val _isScanning = MutableStateFlow(false)
    val isScanning: StateFlow<Boolean> = _isScanning.asStateFlow()

    suspend fun runFullStorageScan(): CleanerScanResult = withContext(Dispatchers.IO) {
        _isScanning.value = true
        try {
            val (totalBytes, availBytes) = readStorageCapacity()
            val whitelistedPaths = whitelistDao.getByType(WHITELIST_TYPE_PATH)
                .map { it.targetValue }
                .toSet()

            val mode = permissionManager.getSnapshot().storageScanMode
            val items = mutableListOf<CleanableItem>()
            var scannedCount = 0

            when (mode) {
                StorageScanMode.ALL_FILES -> {
                    val root = Environment.getExternalStorageDirectory()
                    if (root != null && root.exists() && root.canRead()) {
                        val (allFilesItems, count) = scanFileSystemRoot(root, whitelistedPaths)
                        items.addAll(allFilesItems)
                        scannedCount = count
                    }
                }

                StorageScanMode.MEDIA_STORE_FALLBACK -> {
                    val (mediaItems, count) = scanViaMediaStoreFallback(whitelistedPaths)
                    items.addAll(mediaItems)
                    scannedCount = count
                }

                StorageScanMode.LIMITED_NO_PERMISSION -> {
                    // Still inspect app-external cache/downloads safely when no storage grant exists
                    context.externalCacheDir?.let { cacheDir ->
                        val (cacheItems, count) = scanFileSystemRoot(cacheDir, whitelistedPaths)
                        items.addAll(cacheItems)
                        scannedCount = count
                    }
                }
            }

            val appStorage = appStorageAnalyzer.analyzeAppStorage()
            val reclaimable = items
                .filter { !it.isSuggestedOriginal }
                .sumOf { it.sizeBytes }

            val result = CleanerScanResult(
                items = items,
                appStorage = appStorage,
                totalStorageBytes = totalBytes,
                availableStorageBytes = availBytes,
                reclaimableBytes = reclaimable,
                scannedFilesCount = scannedCount,
                scannedAtMillis = System.currentTimeMillis()
            )
            _scanResult.value = result
            result
        } finally {
            _isScanning.value = false
        }
    }

    fun updateCachedResult(result: CleanerScanResult) {
        _scanResult.value = result
    }

    private fun scanFileSystemRoot(
        root: File,
        whitelistedPaths: Set<String>
    ): Pair<List<CleanableItem>, Int> {
        val allRegularFiles = mutableListOf<File>()
        val emptyFolders = mutableListOf<File>()
        val leftoverApks = mutableListOf<CleanableItem>()
        val tempAndLogs = mutableListOf<CleanableItem>()
        val largeAndMessaging = mutableListOf<CleanableItem>()

        // Walk bottom-up to accurately detect empty folders
        val stack = ArrayDeque<File>()
        val visitedDirs = mutableListOf<File>()
        stack.addLast(root)
        var scannedFiles = 0

        while (stack.isNotEmpty() && scannedFiles < MAX_FILES_WALKED) {
            val dir = stack.removeLast()
            val path = dir.absolutePath
            if (shouldSkipDirectory(path, whitelistedPaths)) continue
            visitedDirs.add(dir)

            val children = dir.listFiles() ?: continue
            for (child in children) {
                if (scannedFiles >= MAX_FILES_WALKED) break
                val childPath = child.absolutePath
                if (isWhitelisted(childPath, whitelistedPaths)) continue

                if (child.isDirectory) {
                    if (!child.name.startsWith(".")) {
                        stack.addLast(child)
                    }
                } else if (child.isFile && child.canRead()) {
                    scannedFiles++
                    allRegularFiles.add(child)
                    classifyRegularFile(child, leftoverApks, tempAndLogs, largeAndMessaging)
                }
            }
        }

        // Bottom-up empty folder check
        val flaggedEmptySet = HashSet<String>()
        for (dir in visitedDirs.asReversed()) {
            if (dir == root) continue
            val children = dir.listFiles() ?: continue
            val effectivelyEmpty = children.isEmpty() ||
                children.all { it.isDirectory && it.absolutePath in flaggedEmptySet }
            if (effectivelyEmpty) {
                flaggedEmptySet.add(dir.absolutePath)
                emptyFolders.add(dir)
            }
        }

        val duplicateItems = duplicateFileFinder.findDuplicates(allRegularFiles, whitelistedPaths)
        val duplicatePaths = duplicateItems.map { it.path }.toSet()

        val emptyFolderItems = emptyFolders.take(150).map { folder ->
            CleanableItem(
                id = "empty:${folder.absolutePath}",
                name = folder.name,
                path = folder.absolutePath,
                sizeBytes = 0L,
                lastModifiedMillis = folder.lastModified(),
                category = CleanerCategory.EMPTY_FOLDERS,
                detailBadge = "0 files",
                isSelected = true
            )
        }

        val merged = buildList {
            addAll(duplicateItems)
            addAll(leftoverApks.filterNot { it.path in duplicatePaths })
            addAll(tempAndLogs.filterNot { it.path in duplicatePaths })
            addAll(emptyFolderItems)
            addAll(
                largeAndMessaging
                    .filterNot { it.path in duplicatePaths }
                    .sortedByDescending { it.sizeBytes }
                    .take(120)
            )
        }
        return merged to scannedFiles
    }

    private fun classifyRegularFile(
        file: File,
        apksOut: MutableList<CleanableItem>,
        tempOut: MutableList<CleanableItem>,
        largeOut: MutableList<CleanableItem>
    ) {
        val ext = file.extension.lowercase()
        val size = file.length()
        val lowerPath = file.absolutePath.lowercase()

        if (ext in APK_EXTENSIONS) {
            val installedBadge = checkApkInstalledBadge(file)
            apksOut.add(
                CleanableItem(
                    id = "apk:${file.absolutePath}",
                    name = file.name,
                    path = file.absolutePath,
                    sizeBytes = size,
                    lastModifiedMillis = file.lastModified(),
                    category = CleanerCategory.LEFTOVER_APKS,
                    detailBadge = installedBadge,
                    isSelected = installedBadge == "Already Installed"
                )
            )
            return
        }

        if (ext in TEMP_LOG_EXTENSIONS || file.name.endsWith("~")) {
            tempOut.add(
                CleanableItem(
                    id = "tmp:${file.absolutePath}",
                    name = file.name,
                    path = file.absolutePath,
                    sizeBytes = size,
                    lastModifiedMillis = file.lastModified(),
                    category = CleanerCategory.TEMP_AND_LOGS,
                    detailBadge = ".${ext.ifBlank { "tmp" }}",
                    isSelected = true
                )
            )
            return
        }

        val isMessagingMedia = MESSAGING_PATH_MARKERS.any { lowerPath.contains(it) }
        if (size >= LARGE_FILE_THRESHOLD_BYTES || (isMessagingMedia && size >= MESSAGING_MEDIA_MIN_BYTES)) {
            val badge = if (isMessagingMedia) "Messaging Media" else "Large File"
            largeOut.add(
                CleanableItem(
                    id = "large:${file.absolutePath}",
                    name = file.name,
                    path = file.absolutePath,
                    sizeBytes = size,
                    lastModifiedMillis = file.lastModified(),
                    category = CleanerCategory.LARGE_AND_MESSAGING,
                    detailBadge = badge,
                    isSelected = false // Never auto-select user media
                )
            )
        }
    }

    private fun checkApkInstalledBadge(file: File): String {
        val pm = context.packageManager
        val archiveInfo = runCatching {
            pm.getPackageArchiveInfo(file.absolutePath, 0)
        }.getOrNull() ?: return "Installer APK"

        val installed = runCatching {
            pm.getPackageInfo(archiveInfo.packageName, 0)
        }.getOrNull()
        return if (installed != null) "Already Installed" else "Not Installed"
    }

    private data class MediaEntry(
        val uri: Uri,
        val name: String,
        val displayPath: String,
        val sizeBytes: Long,
        val dateModifiedMs: Long
    )

    /**
     * Graceful MediaStore fallback when MANAGE_EXTERNAL_STORAGE is not granted.
     * Supports 3-stage duplicate detection (size -> stream SHA-256) and large/messaging media discovery.
     */
    private fun scanViaMediaStoreFallback(whitelistedPaths: Set<String>): Pair<List<CleanableItem>, Int> {
        val collections = buildList {
            add(MediaStore.Images.Media.EXTERNAL_CONTENT_URI)
            add(MediaStore.Video.Media.EXTERNAL_CONTENT_URI)
            add(MediaStore.Audio.Media.EXTERNAL_CONTENT_URI)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                add(MediaStore.Downloads.EXTERNAL_CONTENT_URI)
            }
        }

        val projection = buildList {
            add(MediaStore.MediaColumns._ID)
            add(MediaStore.MediaColumns.DISPLAY_NAME)
            add(MediaStore.MediaColumns.SIZE)
            add(MediaStore.MediaColumns.DATE_MODIFIED)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                add(MediaStore.MediaColumns.RELATIVE_PATH)
            }
        }.toTypedArray()

        val entries = mutableListOf<MediaEntry>()
        for (collection in collections) {
            runCatching {
                context.contentResolver.query(
                    collection,
                    projection,
                    "${MediaStore.MediaColumns.SIZE} > ?",
                    arrayOf("1024"),
                    "${MediaStore.MediaColumns.SIZE} DESC"
                )?.use { cursor ->
                    val idIdx = cursor.getColumnIndexOrThrow(MediaStore.MediaColumns._ID)
                    val nameIdx = cursor.getColumnIndexOrThrow(MediaStore.MediaColumns.DISPLAY_NAME)
                    val sizeIdx = cursor.getColumnIndexOrThrow(MediaStore.MediaColumns.SIZE)
                    val modIdx = cursor.getColumnIndexOrThrow(MediaStore.MediaColumns.DATE_MODIFIED)
                    val relIdx = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                        cursor.getColumnIndex(MediaStore.MediaColumns.RELATIVE_PATH)
                    } else {
                        -1
                    }

                    var count = 0
                    while (cursor.moveToNext() && count < 1500) {
                        count++
                        val id = cursor.getLong(idIdx)
                        val name = cursor.getString(nameIdx) ?: continue
                        val size = cursor.getLong(sizeIdx)
                        val modMs = cursor.getLong(modIdx) * 1000L
                        val relPath = if (relIdx >= 0) cursor.getString(relIdx).orEmpty() else ""
                        val displayPath = "$relPath$name"
                        if (isWhitelisted(displayPath, whitelistedPaths)) continue
                        val uri = ContentUris.withAppendedId(collection, id)
                        entries.add(MediaEntry(uri, name, displayPath, size, modMs))
                    }
                }
            }
        }

        val items = mutableListOf<CleanableItem>()

        // MediaStore Duplicate Finding (size grouping -> SHA-256 stream verification)
        val sameSizeGroups = entries.groupBy { it.sizeBytes }.values.filter { it.size >= 2 }
        val byHash = LinkedHashMap<String, MutableList<MediaEntry>>()
        for (group in sameSizeGroups) {
            for (entry in group) {
                val hash = runCatching {
                    context.contentResolver.openInputStream(entry.uri)?.use { stream ->
                        HashUtils.toHex(HashUtils.sha256Stream(stream))
                    }
                }.getOrNull() ?: continue
                byHash.getOrPut(hash) { mutableListOf() }.add(entry)
            }
        }

        val dupUris = HashSet<Uri>()
        for ((hash, copies) in byHash) {
            if (copies.size < 2) continue
            val sorted = copies.sortedBy { it.dateModifiedMs }
            val shortGroup = hash.take(8)
            sorted.forEachIndexed { idx, entry ->
                dupUris.add(entry.uri)
                val isOriginal = idx == 0
                items.add(
                    CleanableItem(
                        id = "msdup:${entry.uri}",
                        name = entry.name,
                        path = entry.displayPath,
                        sizeBytes = entry.sizeBytes,
                        lastModifiedMillis = entry.dateModifiedMs,
                        category = CleanerCategory.DUPLICATES,
                        contentUri = entry.uri,
                        duplicateGroupId = shortGroup,
                        isSuggestedOriginal = isOriginal,
                        detailBadge = if (isOriginal) "Original (#$shortGroup)" else "Duplicate (#$shortGroup)",
                        isSelected = !isOriginal
                    )
                )
            }
        }

        // Large & Messaging Media via MediaStore
        for (entry in entries) {
            if (entry.uri in dupUris) continue
            val lower = entry.displayPath.lowercase()
            val isMessaging = MESSAGING_PATH_MARKERS.any { lower.contains(it) }
            if (entry.sizeBytes >= LARGE_FILE_THRESHOLD_BYTES || (isMessaging && entry.sizeBytes >= MESSAGING_MEDIA_MIN_BYTES)) {
                items.add(
                    CleanableItem(
                        id = "mslarge:${entry.uri}",
                        name = entry.name,
                        path = entry.displayPath,
                        sizeBytes = entry.sizeBytes,
                        lastModifiedMillis = entry.dateModifiedMs,
                        category = CleanerCategory.LARGE_AND_MESSAGING,
                        contentUri = entry.uri,
                        detailBadge = if (isMessaging) "Messaging Media" else "Large File",
                        isSelected = false
                    )
                )
            }
        }

        return items to entries.size
    }

    private fun readStorageCapacity(): Pair<Long, Long> = runCatching {
        val stat = StatFs(Environment.getDataDirectory().path)
        val total = stat.blockCountLong * stat.blockSizeLong
        val avail = stat.availableBlocksLong * stat.blockSizeLong
        total to avail
    }.getOrDefault(0L to 0L)

    private fun shouldSkipDirectory(path: String, whitelist: Set<String>): Boolean {
        if (isWhitelisted(path, whitelist)) return true
        val lower = path.lowercase()
        return lower.contains("/android/data") ||
            lower.contains("/android/obb") ||
            lower.startsWith("/system") ||
            lower.startsWith("/proc")
    }

    private fun isWhitelisted(path: String, whitelist: Set<String>): Boolean =
        whitelist.any { entry -> path == entry || path.startsWith("$entry/") }

    companion object {
        const val WHITELIST_TYPE_PATH = "CLEANER_PATH"
        private const val MAX_FILES_WALKED = 12_000
        private const val LARGE_FILE_THRESHOLD_BYTES = 25L * 1024L * 1024L
        private const val MESSAGING_MEDIA_MIN_BYTES = 5L * 1024L * 1024L
        private val APK_EXTENSIONS = setOf("apk", "apks", "xapk")
        private val TEMP_LOG_EXTENSIONS = setOf("tmp", "temp", "log", "bak", "dmp", "chk")
        private val MESSAGING_PATH_MARKERS = listOf(
            "whatsapp",
            "telegram",
            "signal",
            "viber",
            "messenger",
            "screenshots"
        )
    }
}
