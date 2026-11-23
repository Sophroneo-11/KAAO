package com.kaao.security.engine.network

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer

data class ParsedIpv4UdpDnsPacket(
    val sourceIp: ByteArray,
    val destIp: ByteArray,
    val sourcePort: Int,
    val destPort: Int,
    val dnsPayload: ByteArray,
    val transactionId: Int,
    val queryDomain: String,
    val queryType: Int,
    val queryClass: Int,
    val questionEndOffset: Int
) {
    val queryTypeLabel: String
        get() = when (queryType) {
            TYPE_A -> "A"
            TYPE_AAAA -> "AAAA"
            TYPE_CNAME -> "CNAME"
            TYPE_HTTPS -> "HTTPS"
            TYPE_TXT -> "TXT"
            TYPE_MX -> "MX"
            TYPE_SRV -> "SRV"
            else -> "TYPE$queryType"
        }

    companion object {
        const val TYPE_A = 1
        const val TYPE_CNAME = 5
        const val TYPE_MX = 15
        const val TYPE_TXT = 16
        const val TYPE_AAAA = 28
        const val TYPE_SRV = 33
        const val TYPE_HTTPS = 65
    }
}

/**
 * Pure RFC 1035 DNS + IPv4/UDP packet parser and checksummed response packet builder
 * for the zero-root local AegisVpnService TUN interface.
 */
object DnsPacketParser {

    private const val PROTO_UDP = 17
    private const val DNS_PORT = 53
    private const val DNS_HEADER_LEN = 12

    fun parseIpv4UdpDnsQuery(packet: ByteArray, length: Int = packet.size): ParsedIpv4UdpDnsPacket? {
        if (length < 28 + DNS_HEADER_LEN) return null
        val version = (packet[0].toInt() ushr 4) and 0x0F
        if (version != 4) return null

        val ihl = (packet[0].toInt() and 0x0F) * 4
        if (ihl < 20 || length < ihl + 8 + DNS_HEADER_LEN) return null

        val protocol = packet[9].toInt() and 0xFF
        if (protocol != PROTO_UDP) return null

        val udpOffset = ihl
        val sourcePort = readUInt16(packet, udpOffset)
        val destPort = readUInt16(packet, udpOffset + 2)
        if (destPort != DNS_PORT) return null

        val udpLength = readUInt16(packet, udpOffset + 4)
        val dnsOffset = udpOffset + 8
        val dnsLength = minOf(udpLength - 8, length - dnsOffset)
        if (dnsLength < DNS_HEADER_LEN) return null

        val dnsPayload = packet.copyOfRange(dnsOffset, dnsOffset + dnsLength)
        val parsedQuestion = parseDnsQuestion(dnsPayload) ?: return null

        return ParsedIpv4UdpDnsPacket(
            sourceIp = packet.copyOfRange(12, 16),
            destIp = packet.copyOfRange(16, 20),
            sourcePort = sourcePort,
            destPort = destPort,
            dnsPayload = dnsPayload,
            transactionId = parsedQuestion.transactionId,
            queryDomain = parsedQuestion.domain,
            queryType = parsedQuestion.qType,
            queryClass = parsedQuestion.qClass,
            questionEndOffset = parsedQuestion.questionEndOffset
        )
    }

    data class DnsQuestion(
        val transactionId: Int,
        val domain: String,
        val qType: Int,
        val qClass: Int,
        val questionEndOffset: Int
    )

    fun parseDnsQuestion(dnsPayload: ByteArray): DnsQuestion? {
        if (dnsPayload.size < DNS_HEADER_LEN + 5) return null
        val txId = readUInt16(dnsPayload, 0)
        val flags = readUInt16(dnsPayload, 2)
        val isResponse = (flags and 0x8000) != 0
        if (isResponse) return null

        val qdCount = readUInt16(dnsPayload, 4)
        if (qdCount < 1) return null

        val (domain, nextOffset) = readDomainName(dnsPayload, DNS_HEADER_LEN) ?: return null
        if (nextOffset + 4 > dnsPayload.size) return null

        val qType = readUInt16(dnsPayload, nextOffset)
        val qClass = readUInt16(dnsPayload, nextOffset + 2)
        return DnsQuestion(
            transactionId = txId,
            domain = domain.lowercase().trimEnd('.'),
            qType = qType,
            qClass = qClass,
            questionEndOffset = nextOffset + 4
        )
    }

    /**
     * Builds an RFC 1035 sinkhole DNS wire payload returning 0.0.0.0 (A), :: (AAAA),
     * or NXDOMAIN for other record types.
     */
    fun buildSinkholeDnsPayload(query: ParsedIpv4UdpDnsPacket, useNxDomain: Boolean = false): ByteArray {
        val out = ByteArrayOutputStream()
        val rdFlag = if (query.dnsPayload.size >= 4) (query.dnsPayload[2].toInt() and 0x01) else 0x01

        // Transaction ID
        writeUInt16(out, query.transactionId)

        val canAnswerZeroIp = !useNxDomain &&
            (query.queryType == ParsedIpv4UdpDnsPacket.TYPE_A ||
                query.queryType == ParsedIpv4UdpDnsPacket.TYPE_AAAA)

        if (canAnswerZeroIp) {
            // QR=1, Opcode=0, AA=0, TC=0, RD=rdFlag, RA=1, RCODE=0 (NOERROR)
            out.write(0x80 or rdFlag)
            out.write(0x80)
            writeUInt16(out, 1) // QDCOUNT
            writeUInt16(out, 1) // ANCOUNT
            writeUInt16(out, 0) // NSCOUNT
            writeUInt16(out, 0) // ARCOUNT
            // Echo original Question section
            out.write(query.dnsPayload, DNS_HEADER_LEN, query.questionEndOffset - DNS_HEADER_LEN)
            // Answer RR: pointer to offset 12 (0xC00C)
            writeUInt16(out, 0xC00C)
            writeUInt16(out, query.queryType)
            writeUInt16(out, query.queryClass)
            writeUInt32(out, 60) // TTL 60s
            if (query.queryType == ParsedIpv4UdpDnsPacket.TYPE_A) {
                writeUInt16(out, 4)
                out.write(ByteArray(4)) // 0.0.0.0
            } else {
                writeUInt16(out, 16)
                out.write(ByteArray(16)) // ::
            }
        } else {
            // RCODE = 3 (NXDOMAIN)
            out.write(0x80 or rdFlag)
            out.write(0x83)
            writeUInt16(out, 1) // QDCOUNT
            writeUInt16(out, 0) // ANCOUNT
            writeUInt16(out, 0) // NSCOUNT
            writeUInt16(out, 0) // ARCOUNT
            out.write(query.dnsPayload, DNS_HEADER_LEN, query.questionEndOffset - DNS_HEADER_LEN)
        }
        return out.toByteArray()
    }

    /**
     * Wraps a DNS response payload into a complete IPv4 + UDP packet with swapped src/dst addresses
     * and valid IPv4 header + UDP pseudo-header checksums.
     */
    fun buildIpv4UdpResponsePacket(
        originalQuery: ParsedIpv4UdpDnsPacket,
        dnsResponsePayload: ByteArray
    ): ByteArray {
        val ipHeaderLen = 20
        val udpLen = 8 + dnsResponsePayload.size
        val totalLen = ipHeaderLen + udpLen
        val packet = ByteArray(totalLen)
        val buf = ByteBuffer.wrap(packet)

        // IPv4 Header (src/dst swapped)
        buf.put(0x45.toByte()) // Version 4, IHL 5
        buf.put(0x00.toByte()) // DSCP/ECN
        buf.putShort(totalLen.toShort())
        buf.putShort((originalQuery.transactionId and 0xFFFF).toShort()) // Identification
        buf.putShort(0x4000.toShort()) // Don't Fragment
        buf.put(64.toByte()) // TTL
        buf.put(PROTO_UDP.toByte())
        buf.putShort(0) // Checksum placeholder
        buf.put(originalQuery.destIp)   // New src IP = original dst IP (virtual DNS 10.111.222.2)
        buf.put(originalQuery.sourceIp) // New dst IP = original src IP (TUN local 10.111.222.1)

        // Compute IPv4 Header Checksum
        val ipChecksum = computeChecksum(packet, 0, ipHeaderLen)
        packet[10] = (ipChecksum ushr 8).toByte()
        packet[11] = (ipChecksum and 0xFF).toByte()

        // UDP Header
        buf.putShort(originalQuery.destPort.toShort())   // 53
        buf.putShort(originalQuery.sourcePort.toShort()) // client ephemeral port
        buf.putShort(udpLen.toShort())
        buf.putShort(0) // UDP checksum placeholder
        buf.put(dnsResponsePayload)

        val udpChecksum = computeUdpIpv4Checksum(
            srcIp = originalQuery.destIp,
            dstIp = originalQuery.sourceIp,
            udpSegment = packet,
            udpOffset = ipHeaderLen,
            udpLength = udpLen
        )
        packet[ipHeaderLen + 6] = (udpChecksum ushr 8).toByte()
        packet[ipHeaderLen + 7] = (udpChecksum and 0xFF).toByte()

        return packet
    }

    internal fun computeChecksum(data: ByteArray, offset: Int, length: Int): Int {
        var sum = 0L
        var i = offset
        val end = offset + length
        while (i + 1 < end) {
            sum += ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
            i += 2
        }
        if (i < end) {
            sum += (data[i].toInt() and 0xFF) shl 8
        }
        while ((sum ushr 16) != 0L) {
            sum = (sum and 0xFFFFL) + (sum ushr 16)
        }
        return (sum.inv() and 0xFFFFL).toInt()
    }

    private fun computeUdpIpv4Checksum(
        srcIp: ByteArray,
        dstIp: ByteArray,
        udpSegment: ByteArray,
        udpOffset: Int,
        udpLength: Int
    ): Int {
        var sum = 0L
        sum += ((srcIp[0].toInt() and 0xFF) shl 8) or (srcIp[1].toInt() and 0xFF)
        sum += ((srcIp[2].toInt() and 0xFF) shl 8) or (srcIp[3].toInt() and 0xFF)
        sum += ((dstIp[0].toInt() and 0xFF) shl 8) or (dstIp[1].toInt() and 0xFF)
        sum += ((dstIp[2].toInt() and 0xFF) shl 8) or (dstIp[3].toInt() and 0xFF)
        sum += PROTO_UDP.toLong()
        sum += udpLength.toLong()

        var i = udpOffset
        val end = udpOffset + udpLength
        while (i + 1 < end) {
            sum += ((udpSegment[i].toInt() and 0xFF) shl 8) or (udpSegment[i + 1].toInt() and 0xFF)
            i += 2
        }
        if (i < end) {
            sum += (udpSegment[i].toInt() and 0xFF) shl 8
        }
        while ((sum ushr 16) != 0L) {
            sum = (sum and 0xFFFFL) + (sum ushr 16)
        }
        val result = (sum.inv() and 0xFFFFL).toInt()
        return if (result == 0) 0xFFFF else result
    }

    private fun readDomainName(data: ByteArray, startOffset: Int): Pair<String, Int>? {
        val labels = mutableListOf<String>()
        var offset = startOffset
        var endOffset = -1
        var jumps = 0

        while (offset < data.size && jumps < 16) {
            val len = data[offset].toInt() and 0xFF
            if (len == 0) {
                if (endOffset == -1) endOffset = offset + 1
                break
            }
            if ((len and 0xC0) == 0xC0) {
                if (offset + 1 >= data.size) return null
                if (endOffset == -1) endOffset = offset + 2
                val pointer = ((len and 0x3F) shl 8) or (data[offset + 1].toInt() and 0xFF)
                if (pointer >= data.size) return null
                offset = pointer
                jumps++
            } else {
                offset++
                if (offset + len > data.size) return null
                labels.add(String(data, offset, len, Charsets.US_ASCII))
                offset += len
            }
        }
        if (labels.isEmpty() || endOffset == -1) return null
        return labels.joinToString(".") to endOffset
    }

    private fun readUInt16(data: ByteArray, offset: Int): Int =
        ((data[offset].toInt() and 0xFF) shl 8) or (data[offset + 1].toInt() and 0xFF)

    private fun writeUInt16(out: ByteArrayOutputStream, value: Int) {
        out.write((value ushr 8) and 0xFF)
        out.write(value and 0xFF)
    }

    private fun writeUInt32(out: ByteArrayOutputStream, value: Int) {
        out.write((value ushr 24) and 0xFF)
        out.write((value ushr 16) and 0xFF)
        out.write((value ushr 8) and 0xFF)
        out.write(value and 0xFF)
    }
}
