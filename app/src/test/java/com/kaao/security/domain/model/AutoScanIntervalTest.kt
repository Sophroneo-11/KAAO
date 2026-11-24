package com.kaao.security.domain.model

import org.junit.Assert.assertEquals
import org.junit.Test

class AutoScanIntervalTest {

    @Test
    fun mapsAllIntervalsAndDefaultsSafelyToDaily() {
        assertEquals(AutoScanInterval.OFF, AutoScanInterval.fromId("off"))
        assertEquals(0L, AutoScanInterval.OFF.intervalHours)
        assertEquals(AutoScanInterval.EVERY_6_HOURS, AutoScanInterval.fromId("6h"))
        assertEquals(6L, AutoScanInterval.EVERY_6_HOURS.intervalHours)
        assertEquals(AutoScanInterval.EVERY_12_HOURS, AutoScanInterval.fromId("12h"))
        assertEquals(12L, AutoScanInterval.EVERY_12_HOURS.intervalHours)
        assertEquals(AutoScanInterval.DAILY, AutoScanInterval.fromId("24h"))
        assertEquals(24L, AutoScanInterval.DAILY.intervalHours)
        assertEquals(AutoScanInterval.WEEKLY, AutoScanInterval.fromId("168h"))
        assertEquals(168L, AutoScanInterval.WEEKLY.intervalHours)
        assertEquals(AutoScanInterval.DAILY, AutoScanInterval.fromId(null))
        assertEquals(AutoScanInterval.DAILY, AutoScanInterval.fromId("unknown"))
    }
}
