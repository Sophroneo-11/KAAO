package com.kaao.security.core.crypto

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import dagger.hilt.android.qualifiers.ApplicationContext
import java.io.File
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Hardware-backed Android Keystore AES-256-GCM wrapper.
 * Wraps the 32-byte random SQLCipher 4.6.1 vault key and sensitive user API keys (e.g. VirusTotal).
 */
@Singleton
class KeystorePassphraseManager @Inject constructor(
    @ApplicationContext private val context: Context
) {
    private val keyStore: KeyStore by lazy {
        KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
    }

    private val lock = Any()

    fun getOrCreateDatabasePassphrase(): ByteArray = synchronized(lock) {
        val wrappedFile = File(context.noBackupFilesDir, WRAPPED_DB_KEY_FILE)
        if (wrappedFile.exists()) {
            val decrypted = runCatching {
                decryptPayload(wrappedFile.readText(Charsets.UTF_8))
            }.getOrNull()
            if (decrypted != null && decrypted.size == DB_KEY_BYTES) {
                return decrypted
            }
        }
        val rawPassphrase = ByteArray(DB_KEY_BYTES).also { SecureRandom().nextBytes(it) }
        val wrapped = encryptPayload(rawPassphrase)
        wrappedFile.writeText(wrapped, Charsets.UTF_8)
        rawPassphrase
    }

    fun encryptSecret(plaintext: String): String = synchronized(lock) {
        encryptPayload(plaintext.toByteArray(Charsets.UTF_8))
    }

    fun decryptSecret(encodedCiphertext: String): String? = synchronized(lock) {
        if (encodedCiphertext.isBlank()) return null
        runCatching {
            decryptPayload(encodedCiphertext).toString(Charsets.UTF_8)
        }.getOrNull()
    }

    fun isHardwareKeyReady(): Boolean = runCatching {
        getOrCreateMasterKey()
        true
    }.getOrDefault(false)

    private fun encryptPayload(plaintext: ByteArray): String {
        val cipher = Cipher.getInstance(AES_GCM_TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateMasterKey())
        val iv = cipher.iv
        val ciphertext = cipher.doFinal(plaintext)
        val combined = ByteArray(1 + iv.size + ciphertext.size)
        combined[0] = iv.size.toByte()
        System.arraycopy(iv, 0, combined, 1, iv.size)
        System.arraycopy(ciphertext, 0, combined, 1 + iv.size, ciphertext.size)
        return Base64.encodeToString(combined, Base64.NO_WRAP)
    }

    private fun decryptPayload(encoded: String): ByteArray {
        val combined = Base64.decode(encoded, Base64.NO_WRAP)
        require(combined.size > 13) { "Corrupted wrapped key payload" }
        val ivLength = combined[0].toInt() and 0xFF
        require(ivLength in 12..16 && combined.size > 1 + ivLength) { "Invalid GCM IV length" }
        val iv = combined.copyOfRange(1, 1 + ivLength)
        val ciphertext = combined.copyOfRange(1 + ivLength, combined.size)
        val cipher = Cipher.getInstance(AES_GCM_TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, getOrCreateMasterKey(), GCMParameterSpec(GCM_TAG_BITS, iv))
        return cipher.doFinal(ciphertext)
    }

    private fun getOrCreateMasterKey(): SecretKey {
        val existing = keyStore.getEntry(KEY_ALIAS, null) as? KeyStore.SecretKeyEntry
        if (existing != null) return existing.secretKey

        val keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES,
            ANDROID_KEYSTORE
        )
        val spec = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setRandomizedEncryptionRequired(true)
            .build()
        keyGenerator.init(spec)
        return keyGenerator.generateKey()
    }

    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val KEY_ALIAS = "kaao_vault_master_aes256_gcm"
        private const val AES_GCM_TRANSFORMATION = "AES/GCM/NoPadding"
        private const val GCM_TAG_BITS = 128
        private const val DB_KEY_BYTES = 32
        private const val WRAPPED_DB_KEY_FILE = "kaao_sqlcipher_key.enc"
    }
}
