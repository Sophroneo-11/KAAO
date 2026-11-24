package com.kaao.security.engine.gamebooster

import com.kaao.security.data.local.prefs.KaaoSettings
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class GameFirewallExceptionsTest {

    @Test
    fun detectsPopularVoiceChatPackagesAndIncludesSensibleDefaults() {
        assertTrue(GameDetector.isKnownVoiceChatPackage("com.discord"))
        assertTrue(GameDetector.isKnownVoiceChatPackage("com.whatsapp"))
        assertTrue(GameDetector.isKnownVoiceChatPackage("org.telegram.messenger"))
        assertTrue(GameDetector.isKnownVoiceChatPackage("org.thoughtcrime.securesms"))
        assertFalse(GameDetector.isKnownVoiceChatPackage("com.random.background.updater"))

        assertTrue("com.discord" in KaaoSettings.DEFAULT_VOICE_CHAT_PACKAGES)
        assertTrue("com.whatsapp" in KaaoSettings.DEFAULT_VOICE_CHAT_PACKAGES)
    }
}
