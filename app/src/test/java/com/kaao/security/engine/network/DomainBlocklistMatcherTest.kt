package com.kaao.security.engine.network

import com.kaao.security.data.local.db.DnsBlockRuleEntity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class DomainBlocklistMatcherTest {

    @Test
    fun matchesExactAndSubdomainsWhileHonoringAllowlistAndCategoryToggles() {
        val matcher = DomainBlocklistMatcher()
        val rules = listOf(
            DnsBlockRuleEntity("evil-phish.com", "PHISHING", false, 1L),
            DnsBlockRuleEntity("ads.doubleclick.net", "ADWARE", false, 1L),
            DnsBlockRuleEntity("safe.evil-phish.com", "CUSTOM_ALLOW", true, 1L)
        )

        matcher.updateRules(rules, blockPhishing = true, blockMalware = true, blockAdware = false)

        val exactHit = matcher.evaluate("evil-phish.com")
        assertTrue(exactHit.blocked)
        assertEquals("PHISHING", exactHit.category)

        val subHit = matcher.evaluate("login.portal.evil-phish.com")
        assertTrue(subHit.blocked)
        assertEquals("evil-phish.com", subHit.matchedRule)

        // Allowlist overrides parent block rule
        val allowOverride = matcher.evaluate("api.safe.evil-phish.com")
        assertFalse(allowOverride.blocked)
        assertEquals("CUSTOM_ALLOW", allowOverride.category)

        // Disabled adware category is allowed
        assertFalse(matcher.evaluate("ads.doubleclick.net").blocked)

        // Re-enable adware
        matcher.updateRules(rules, blockPhishing = true, blockMalware = true, blockAdware = true)
        assertTrue(matcher.evaluate("metrics.ads.doubleclick.net").blocked)
    }
}
