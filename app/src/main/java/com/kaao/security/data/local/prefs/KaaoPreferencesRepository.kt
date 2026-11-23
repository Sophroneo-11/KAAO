package com.kaao.security.data.local.prefs

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.longPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import com.kaao.security.core.crypto.KeystorePassphraseManager
import com.kaao.security.data.local.db.SeedThreatCatalog
import com.kaao.security.domain.model.DohProvider
import com.kaao.security.domain.model.GameBoostConfig
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import javax.inject.Inject
import javax.inject.Singleton

private val Context.kaaoDataStore: DataStore<Preferences> by preferencesDataStore(name = "kaao_security_prefs")

data class KaaoSettings(
    val realtimeShieldEnabled: Boolean = false,
    val downloadsObserverEnabled: Boolean = true,
    val deltaPackageAuditEnabled: Boolean = true,
    val cloudHashLookupEnabled: Boolean = false,
    val hasVirusTotalApiKey: Boolean = false,
    val dohProvider: DohProvider = DohProvider.CLOUDFLARE,
    val blockPhishing: Boolean = true,
    val blockMalware: Boolean = true,
    val blockAdware: Boolean = true,
    val definitionVersion: Long = SeedThreatCatalog.INITIAL_BUNDLE_VERSION,
    val lastDefinitionVerifiedMillis: Long = 0L,
    val lastPackageSequenceNumber: Int = 0,
    val gameBoostConfig: GameBoostConfig = GameBoostConfig()
)

data class SavedSystemSnapshot(
    val hasActiveSnapshot: Boolean = false,
    val activeGamePackage: String? = null,
    val activeGameName: String? = null,
    val previousDndFilter: Int = -1,
    val previousBrightness: Int = -1,
    val previousBrightnessMode: Int = -1,
    val previousMasterSync: Boolean = true,
    val previousDnsShieldWasOn: Boolean = false
)

@Singleton
class KaaoPreferencesRepository @Inject constructor(
    @ApplicationContext private val context: Context,
    private val keystorePassphraseManager: KeystorePassphraseManager
) {
    private val dataStore = context.kaaoDataStore

    val settingsFlow: Flow<KaaoSettings> = dataStore.data.map { prefs ->
        val dohId = prefs[KEY_DOH_PROVIDER] ?: DohProvider.CLOUDFLARE.id
        val provider = DohProvider.entries.firstOrNull { it.id == dohId } ?: DohProvider.CLOUDFLARE
        KaaoSettings(
            realtimeShieldEnabled = prefs[KEY_REALTIME_SHIELD] ?: false,
            downloadsObserverEnabled = prefs[KEY_DOWNLOADS_OBSERVER] ?: true,
            deltaPackageAuditEnabled = prefs[KEY_DELTA_AUDIT] ?: true,
            cloudHashLookupEnabled = prefs[KEY_CLOUD_HASH_LOOKUP] ?: false,
            hasVirusTotalApiKey = !prefs[KEY_VT_API_KEY_ENC].isNullOrBlank(),
            dohProvider = provider,
            blockPhishing = prefs[KEY_BLOCK_PHISHING] ?: true,
            blockMalware = prefs[KEY_BLOCK_MALWARE] ?: true,
            blockAdware = prefs[KEY_BLOCK_ADWARE] ?: true,
            definitionVersion = prefs[KEY_DEF_VERSION] ?: SeedThreatCatalog.INITIAL_BUNDLE_VERSION,
            lastDefinitionVerifiedMillis = prefs[KEY_DEF_VERIFIED_MS] ?: 0L,
            lastPackageSequenceNumber = prefs[KEY_PACKAGE_SEQ] ?: 0,
            gameBoostConfig = GameBoostConfig(
                enableBackgroundFirewall = prefs[KEY_GB_FIREWALL] ?: true,
                enableDndSilence = prefs[KEY_GB_DND] ?: true,
                lockBrightness = prefs[KEY_GB_BRIGHTNESS_LOCK] ?: false,
                targetBrightnessPercent = prefs[KEY_GB_BRIGHTNESS_PCT] ?: 75,
                pauseAutoSync = prefs[KEY_GB_PAUSE_SYNC] ?: true,
                showFloatingHud = prefs[KEY_GB_HUD] ?: true
            )
        )
    }

    suspend fun getSettings(): KaaoSettings = settingsFlow.first()

    suspend fun setRealtimeShieldEnabled(enabled: Boolean) {
        dataStore.edit { it[KEY_REALTIME_SHIELD] = enabled }
    }

    suspend fun setDownloadsObserverEnabled(enabled: Boolean) {
        dataStore.edit { it[KEY_DOWNLOADS_OBSERVER] = enabled }
    }

    suspend fun setDeltaPackageAuditEnabled(enabled: Boolean) {
        dataStore.edit { it[KEY_DELTA_AUDIT] = enabled }
    }

    suspend fun setCloudHashLookupEnabled(enabled: Boolean) {
        dataStore.edit { it[KEY_CLOUD_HASH_LOOKUP] = enabled }
    }

    suspend fun saveVirusTotalApiKey(rawApiKey: String) {
        val trimmed = rawApiKey.trim()
        dataStore.edit { prefs ->
            if (trimmed.isEmpty()) {
                prefs.remove(KEY_VT_API_KEY_ENC)
            } else {
                prefs[KEY_VT_API_KEY_ENC] = keystorePassphraseManager.encryptSecret(trimmed)
            }
        }
    }

    suspend fun getDecryptedVirusTotalApiKey(): String? {
        val encrypted = dataStore.data.first()[KEY_VT_API_KEY_ENC] ?: return null
        return keystorePassphraseManager.decryptSecret(encrypted)
    }

    suspend fun setDohProvider(provider: DohProvider) {
        dataStore.edit { it[KEY_DOH_PROVIDER] = provider.id }
    }

    suspend fun setDnsCategories(phishing: Boolean, malware: Boolean, adware: Boolean) {
        dataStore.edit { prefs ->
            prefs[KEY_BLOCK_PHISHING] = phishing
            prefs[KEY_BLOCK_MALWARE] = malware
            prefs[KEY_BLOCK_ADWARE] = adware
        }
    }

    suspend fun updateDefinitionMetadata(version: Long, verifiedMillis: Long) {
        dataStore.edit { prefs ->
            prefs[KEY_DEF_VERSION] = version
            prefs[KEY_DEF_VERIFIED_MS] = verifiedMillis
        }
    }

    suspend fun updatePackageSequenceNumber(seq: Int) {
        dataStore.edit { it[KEY_PACKAGE_SEQ] = seq }
    }

    suspend fun updateGameBoostConfig(config: GameBoostConfig) {
        dataStore.edit { prefs ->
            prefs[KEY_GB_FIREWALL] = config.enableBackgroundFirewall
            prefs[KEY_GB_DND] = config.enableDndSilence
            prefs[KEY_GB_BRIGHTNESS_LOCK] = config.lockBrightness
            prefs[KEY_GB_BRIGHTNESS_PCT] = config.targetBrightnessPercent
            prefs[KEY_GB_PAUSE_SYNC] = config.pauseAutoSync
            prefs[KEY_GB_HUD] = config.showFloatingHud
        }
    }

    suspend fun saveSystemSnapshot(snapshot: SavedSystemSnapshot) {
        dataStore.edit { prefs ->
            prefs[KEY_SNAP_ACTIVE] = snapshot.hasActiveSnapshot
            if (snapshot.activeGamePackage != null) {
                prefs[KEY_SNAP_PKG] = snapshot.activeGamePackage
            } else {
                prefs.remove(KEY_SNAP_PKG)
            }
            if (snapshot.activeGameName != null) {
                prefs[KEY_SNAP_NAME] = snapshot.activeGameName
            } else {
                prefs.remove(KEY_SNAP_NAME)
            }
            prefs[KEY_SNAP_DND] = snapshot.previousDndFilter
            prefs[KEY_SNAP_BRIGHT] = snapshot.previousBrightness
            prefs[KEY_SNAP_BRIGHT_MODE] = snapshot.previousBrightnessMode
            prefs[KEY_SNAP_SYNC] = snapshot.previousMasterSync
            prefs[KEY_SNAP_DNS_WAS_ON] = snapshot.previousDnsShieldWasOn
        }
    }

    suspend fun getSavedSystemSnapshot(): SavedSystemSnapshot {
        val prefs = dataStore.data.first()
        return SavedSystemSnapshot(
            hasActiveSnapshot = prefs[KEY_SNAP_ACTIVE] ?: false,
            activeGamePackage = prefs[KEY_SNAP_PKG],
            activeGameName = prefs[KEY_SNAP_NAME],
            previousDndFilter = prefs[KEY_SNAP_DND] ?: -1,
            previousBrightness = prefs[KEY_SNAP_BRIGHT] ?: -1,
            previousBrightnessMode = prefs[KEY_SNAP_BRIGHT_MODE] ?: -1,
            previousMasterSync = prefs[KEY_SNAP_SYNC] ?: true,
            previousDnsShieldWasOn = prefs[KEY_SNAP_DNS_WAS_ON] ?: false
        )
    }

    suspend fun clearSystemSnapshot() {
        saveSystemSnapshot(SavedSystemSnapshot(hasActiveSnapshot = false))
    }

    companion object {
        private val KEY_REALTIME_SHIELD = booleanPreferencesKey("realtime_shield_enabled")
        private val KEY_DOWNLOADS_OBSERVER = booleanPreferencesKey("downloads_observer_enabled")
        private val KEY_DELTA_AUDIT = booleanPreferencesKey("delta_package_audit_enabled")
        private val KEY_CLOUD_HASH_LOOKUP = booleanPreferencesKey("cloud_hash_lookup_enabled")
        private val KEY_VT_API_KEY_ENC = stringPreferencesKey("vt_api_key_encrypted")
        private val KEY_DOH_PROVIDER = stringPreferencesKey("doh_provider")
        private val KEY_BLOCK_PHISHING = booleanPreferencesKey("block_phishing")
        private val KEY_BLOCK_MALWARE = booleanPreferencesKey("block_malware")
        private val KEY_BLOCK_ADWARE = booleanPreferencesKey("block_adware")
        private val KEY_DEF_VERSION = longPreferencesKey("definition_version")
        private val KEY_DEF_VERIFIED_MS = longPreferencesKey("definition_verified_millis")
        private val KEY_PACKAGE_SEQ = intPreferencesKey("last_package_sequence")
        private val KEY_GB_FIREWALL = booleanPreferencesKey("gb_firewall")
        private val KEY_GB_DND = booleanPreferencesKey("gb_dnd")
        private val KEY_GB_BRIGHTNESS_LOCK = booleanPreferencesKey("gb_brightness_lock")
        private val KEY_GB_BRIGHTNESS_PCT = intPreferencesKey("gb_brightness_pct")
        private val KEY_GB_PAUSE_SYNC = booleanPreferencesKey("gb_pause_sync")
        private val KEY_GB_HUD = booleanPreferencesKey("gb_hud")

        private val KEY_SNAP_ACTIVE = booleanPreferencesKey("snap_active")
        private val KEY_SNAP_PKG = stringPreferencesKey("snap_pkg")
        private val KEY_SNAP_NAME = stringPreferencesKey("snap_name")
        private val KEY_SNAP_DND = intPreferencesKey("snap_dnd")
        private val KEY_SNAP_BRIGHT = intPreferencesKey("snap_bright")
        private val KEY_SNAP_BRIGHT_MODE = intPreferencesKey("snap_bright_mode")
        private val KEY_SNAP_SYNC = booleanPreferencesKey("snap_sync")
        private val KEY_SNAP_DNS_WAS_ON = booleanPreferencesKey("snap_dns_was_on")
    }
}
