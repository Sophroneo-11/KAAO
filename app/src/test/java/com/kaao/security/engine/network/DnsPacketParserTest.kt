package com.kaao.security.engine.network

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer

class DnsPacketParserTest {

    private fun buildTestIpv4UdpDnsQuery(domain: String, qType: Int, txId: Int = 0x1A2B): ByteArray {
        val dns = ByteArrayOutputStream().apply {
            write((txId ushr 8) and 0xFF)
            write(txId and 0xFF)
            write(0x01); write(0x00) // Standard recursive query
            write(0x00); write(0x01) // QDCOUNT = 1
            write(0x00); write(0x00) // ANCOUNT = 0
            write(0x00); write(0x00) // NSCOUNT = 0
            write(0x00); write(0x00) // ARCOUNT = 0
            for (label in domain.split('.')) {
                val bytes = label.toByteArray(Charsets.US_ASCII)
                write(bytes.size)
                write(bytes)
            }
            write(0)
            write((qType ushr 8) and 0xFF); write(qType and 0xFF)
            write(0x00); write(0x01) // IN class
        }.toByteArray()

        val udpLen = 8 + dns.size
        val totalLen = 20 + udpLen
        val packet = ByteArray(totalLen)
        val buf = ByteBuffer.wrap(packet)
        buf.put(0x45.toByte())
        buf.put(0x00.toByte())
        buf.putShort(totalLen.toShort())
        buf.putShort(0x1111.toShort())
        buf.putShort(0x4000.toShort())
        buf.put(64.toByte())
        buf.put(17.toByte()) // UDP
        buf.putShort(0)
        buf.put(byteArrayOf(10, 111, 222.toByte(), 1))
        buf.put(byteArrayOf(10, 111, 222.toByte(), 2))
        buf.putShort(51234.toShort())
        buf.putShort(53.toShort())
        buf.putShort(udpLen.toShort())
        buf.putShort(0)
        buf.put(dns)
        return packet
    }

    @Test
    fun parsesIpv4UdpDnsQueryAndBuildsValidZeroIpSinkholePacket() {
        val rawQuery = buildTestIpv4UdpDnsQuery("Phish.Evil-Domain.COM", ParsedIpv4UdpDnsPacket.TYPE_A, 0xBEEF)
        val parsed = DnsPacketParser.parseIpv4UdpDnsQuery(rawQuery)
        assertNotNull(parsed)
        parsed!!

        assertEquals("phish.evil-domain.com", parsed.queryDomain)
        assertEquals(ParsedIpv4UdpDnsPacket.TYPE_A, parsed.queryType)
        assertEquals("A", parsed.queryTypeLabel)
        assertEquals(0xBEEF, parsed.transactionId)

        val sinkholeDns = DnsPacketParser.buildSinkholeDnsPayload(parsed)
        // QR bit set & ANCOUNT == 1
        assertEquals(0x81, sinkholeDns[2].toInt() and 0xFF)
        assertEquals(1, ((sinkholeDns[6].toInt() and 0xFF) shl 8) or (sinkholeDns[7].toInt() and 0xFF))
        // Last 4 bytes must be 0.0.0.0
        for (i in sinkholeDns.size - 4 until sinkholeDns.size) {
            assertEquals(0, sinkholeDns[i].toInt())
        }

        val responseIp = DnsPacketParser.buildIpv4UdpResponsePacket(parsed, sinkholeDns)
        // Verify IPv4 header checksum validates to 0
        assertEquals(0, DnsPacketParser.computeChecksum(responseIp, 0, 20))
        // Src IP of response == original dst IP (10.111.222.2)
        assertEquals(2, responseIp[15].toInt() and 0xFF)
        // Dst IP of response == original src IP (10.111.222.1)
        assertEquals(1, responseIp[19].toInt() and 0xFF)
    }

    @Test
    fun buildsNxDomainForNonAddressQueryTypes() {
        val rawQuery = buildTestIpv4UdpDnsQuery("tracker.example.com", ParsedIpv4UdpDnsPacket.TYPE_HTTPS, 0x0042)
        val parsed = DnsPacketParser.parseIpv4UdpDnsQuery(rawQuery)!!
        val sinkholeDns = DnsPacketParser.buildSinkholeDnsPayload(parsed)
        // RCODE = 3 (NXDOMAIN)
        assertEquals(3, sinkholeDns[3].toInt() and 0x0F)
        assertEquals(0, ((sinkholeDns[6].toInt() and 0xFF) shl 8) or (sinkholeDns[7].toInt() and 0xFF))
    }
}
