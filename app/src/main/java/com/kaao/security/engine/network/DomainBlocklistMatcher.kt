package com.kaao.security.engine.network

import com.kaao.security.data.local.db.DnsBlockRuleEntity
import java.util.concurrent.atomic.AtomicReference
import javax.inject.Inject
import javax.inject.Singleton

data class DomainMatchDecision(
    val blocked: Boolean,
    val category: String,
    val matchedRule: String? = null
)

/**
 * Lock-free domain suffix/exact matcher for AegisVpnService DNS sinkhole.
 * Supports category toggles (PHISHING, MALWARE, ADWARE), custom blocks, and custom allowlist precedence.
 */
@Singleton
class DomainBlocklistMatcher @Inject constructor() {

    private data class Snapshot(
        val blockedByDomain: Map<String, String>,
        val allowedDomains: Set<String>,
        val enabledCategories: Set<String>
    )

    private val snapshotRef = AtomicReference(
        Snapshot(
            blockedByDomain = emptyMap(),
            allowedDomains = emptySet(),
            enabledCategories = setOf("PHISHING", "MALWARE", "ADWARE", "CUSTOM_BLOCK")
        )
    )

    fun updateRules(
        rules: List<DnsBlockRuleEntity>,
        blockPhishing: Boolean,
        blockMalware: Boolean,
        blockAdware: Boolean
    ) {
        val blocked = HashMap<String, String>(rules.size)
        val allowed = HashSet<String>()
        for (rule in rules) {
            val normalized = rule.domain.trim().lowercase().trimEnd('.')
            if (normalized.isEmpty()) continue
            if (rule.category.equals("CUSTOM_ALLOW", ignoreCase = true)) {
                allowed.add(normalized)
            } else {
                blocked[normalized] = rule.category.uppercase()
            }
        }
        val enabled = buildSet {
            add("CUSTOM_BLOCK")
            if (blockPhishing) add("PHISHING")
            if (blockMalware) add("MALWARE")
            if (blockAdware) add("ADWARE")
        }
        snapshotRef.set(Snapshot(blocked, allowed, enabled))
    }

    fun evaluate(rawDomain: String): DomainMatchDecision {
        val domain = rawDomain.trim().lowercase().trimEnd('.')
        if (domain.isEmpty()) return DomainMatchDecision(blocked = false, category = "ALLOWED")

        val snap = snapshotRef.get()

        // 1. Check explicit user allowlist first (exact + parent suffix)
        var candidate: String? = domain
        while (candidate != null) {
            if (candidate in snap.allowedDomains) {
                return DomainMatchDecision(blocked = false, category = "CUSTOM_ALLOW", matchedRule = candidate)
            }
            candidate = parentDomain(candidate)
        }

        // 2. Check blocklist (exact + parent suffix)
        candidate = domain
        while (candidate != null) {
            val category = snap.blockedByDomain[candidate]
            if (category != null && category in snap.enabledCategories) {
                return DomainMatchDecision(blocked = true, category = category, matchedRule = candidate)
            }
            candidate = parentDomain(candidate)
        }

        return DomainMatchDecision(blocked = false, category = "ALLOWED")
    }

    private fun parentDomain(domain: String): String? {
        val dot = domain.indexOf('.')
        if (dot <= 0 || dot >= domain.length - 1) return null
        return domain.substring(dot + 1)
    }
}
