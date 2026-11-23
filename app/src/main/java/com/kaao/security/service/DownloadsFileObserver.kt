package com.kaao.security.service

import android.os.Build
import android.os.FileObserver
import java.io.File

/**
 * Watches the public Downloads directory via Linux inotify FileObserver (API 26–35 compat)
 * to automatically trigger antivirus scanning on newly downloaded APK/DEX/ZIP/test files.
 */
class DownloadsFileObserver private constructor(
    private val directory: File,
    private val onCandidateFileReady: (File) -> Unit
) {
    private var observer: FileObserver? = null

    fun start() {
        if (!directory.exists() || !directory.canRead()) return
        stop()

        val mask = FileObserver.CLOSE_WRITE or FileObserver.MOVED_TO
        observer = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            object : FileObserver(directory, mask) {
                override fun onEvent(event: Int, path: String?) {
                    handleEvent(path)
                }
            }
        } else {
            @Suppress("DEPRECATION")
            object : FileObserver(directory.absolutePath, mask) {
                override fun onEvent(event: Int, path: String?) {
                    handleEvent(path)
                }
            }
        }
        runCatching { observer?.startWatching() }
    }

    fun stop() {
        runCatching { observer?.stopWatching() }
        observer = null
    }

    private fun handleEvent(relativePath: String?) {
        if (relativePath.isNullOrBlank()) return
        val file = File(directory, relativePath)
        if (!file.exists() || !file.isFile) return
        val ext = file.extension.lowercase()
        if (ext in WATCHED_EXTENSIONS || file.name.contains("eicar", ignoreCase = true)) {
            onCandidateFileReady(file)
        }
    }

    companion object {
        private val WATCHED_EXTENSIONS = setOf("apk", "apks", "xapk", "dex", "jar", "zip", "bin")

        fun create(directory: File, onCandidateFileReady: (File) -> Unit): DownloadsFileObserver =
            DownloadsFileObserver(directory, onCandidateFileReady)
    }
}
