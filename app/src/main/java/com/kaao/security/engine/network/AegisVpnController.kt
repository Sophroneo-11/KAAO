package com.kaao.security.engine.network

import android.content.Context
import android.content.Intent
import androidx.core.content.ContextCompat
import com.kaao.security.data.local.db.DnsBlockRuleDao
import com.kaao.security.data.local.db.DnsBlockRuleEntity
import com.kaao.security.data.local.db.DnsQueryLogDao
import com.kaao.security.data.local.db.DnsQueryLogEntity
import com.kaao.security.data.local.prefs.KaaoPreferencesRepository
import com.kaao.security.domain.model.AegisVpnMode
import com.kaao.security.domain.model.AegisVpnState
import com.kaao.security.domain.model.DnsQueryEvent
import com.kaao.security.domain.model.DohProvider
import com.kaao.security.service.AegisVpnService
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.withContext
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class AegisVpnController @Inject constructor(
    @ApplicationContext private val context: Context,
    private val blockRuleDao: DnsBlockRuleDao,
    private val queryLogDao: DnsQueryLogDao,
    private val prefs: KaaoPreferencesRepository,
    val matcher: DomainBlocklistMatcher
) {
    private val _vpnState = MutableStateFlow(AegisVpnState())
    val vpnState: StateFlow<AegisVpnState> = _vpnState.asStateFlow()

    val recentQueriesFlow: Flow<List<DnsQueryEvent>> = queryLogDao.observeRecent().map { list ->
        list.map {
            DnsQueryEvent(
                id = it.id,
                domain = it.domain,
                queryType = it.queryType,
                blocked = it.blocked,
                category = it.category,
                latencyMs = it.latencyMs,
                timestampMillis = it.timestampMillis
            )
        }
    }

    val totalBlockedFlow: Flow<Long> = queryLogDao.observeBlockedCount()
    val customRulesFlow: Flow<List<DnsBlockRuleEntity>> = blockRuleDao.observeAll()

    suspend fun reloadMatcherRules() = withContext(Dispatchers.IO) {
        val settings = prefs.getSettings()
        val rules = blockRuleDao.getAll()
        matcher.updateRules(
            rules = rules,
            blockPhishing = settings.blockPhishing,
            blockMalware = settings.blockMalware,
            blockAdware = settings.blockAdware
        )
        _vpnState.update { it.copy(dohProvider = settings.dohProvider) }
    }

    suspend fun addCustomRule(domain: String, allow: Boolean) = withContext(Dispatchers.IO) {
        val clean = domain.trim().lowercase().removePrefix("https://").removePrefix("http://")
            .substringBefore('/').trimEnd('.')
        if (clean.isBlank() || !clean.contains('.')) return@withContext
        blockRuleDao.upsert(
            DnsBlockRuleEntity(
                domain = clean,
                category = if (allow) "CUSTOM_ALLOW" else "CUSTOM_BLOCK",
                isUserCustom = true,
                addedAtMillis = System.currentTimeMillis()
            )
        )
        reloadMatcherRules()
    }

    suspend fun removeCustomRule(domain: String) = withContext(Dispatchers.IO) {
        blockRuleDao.deleteByDomain(domain.lowercase())
        reloadMatcherRules()
    }

    suspend fun clearQueryLogs() = withContext(Dispatchers.IO) {
        queryLogDao.clearAll()
    }

    fun startDnsShield(provider: DohProvider? = null) {
        val intent = Intent(context, AegisVpnService::class.java).apply {
            action = AegisVpnService.ACTION_START_DNS_SHIELD
            provider?.let { putExtra(AegisVpnService.EXTRA_DOH_PROVIDER_ID, it.id) }
        }
        ContextCompat.startForegroundService(context, intent)
    }

    fun startGameFirewall(gamePackage: String, gameName: String) {
        val intent = Intent(context, AegisVpnService::class.java).apply {
            action = AegisVpnService.ACTION_START_GAME_FIREWALL
            putExtra(AegisVpnService.EXTRA_GAME_PACKAGE, gamePackage)
            putExtra(AegisVpnService.EXTRA_GAME_NAME, gameName)
        }
        ContextCompat.startForegroundService(context, intent)
    }

    fun stopVpn() {
        val intent = Intent(context, AegisVpnService::class.java).apply {
            action = AegisVpnService.ACTION_STOP_VPN
        }
        context.startService(intent)
    }

    internal fun updateServiceState(
        mode: AegisVpnMode,
        dohProvider: DohProvider,
        activeGamePackage: String? = null,
        activeGameName: String? = null,
        lastError: String? = null
    ) {
        _vpnState.update {
            it.copy(
                mode = mode,
                dohProvider = dohProvider,
                activeGamePackage = activeGamePackage,
                activeGameName = activeGameName,
                lastError = lastError
            )
        }
    }

    internal suspend fun recordDnsQuery(
        domain: String,
        queryType: String,
        blocked: Boolean,
        category: String,
        latencyMs: Long
    ) {
        _vpnState.update {
            it.copy(
                queriesProcessed = it.queriesProcessed + 1,
                queriesBlocked = if (blocked) it.queriesBlocked + 1 else it.queriesBlocked
            )
        }
        runCatching {
            queryLogDao.insert(
                DnsQueryLogEntity(
                    domain = domain,
                    queryType = queryType,
                    blocked = blocked,
                    category = category,
                    latencyMs = latencyMs,
                    timestampMillis = System.currentTimeMillis()
                )
            )
            queryLogDao.pruneOld()
        }
    }
}
