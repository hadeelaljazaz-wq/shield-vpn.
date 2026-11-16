package com.smartadshield.vpn.core

import com.smartadshield.vpn.core.dns.BlockStyle
import com.smartadshield.vpn.core.dns.DnsCache
import com.smartadshield.vpn.core.dns.DnsMessage
import com.smartadshield.vpn.core.net.IpPacket
import com.smartadshield.vpn.core.proxy.DpiBypassEngine
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class PacketAndDnsTest {
    private val v4a = byteArrayOf(10, 1, 2, 3)
    private val v4b = byteArrayOf(10, 111, 222.toByte(), 53)
    private val v6a = ByteArray(16) { (it + 1).toByte() }
    private val v6b = ByteArray(16).also { it[0] = 0xfd.toByte(); it[15] = 0x53 }

    @Test
    fun udpIpv4RoundTripAndChecksums() {
        val q = DnsMessage.buildQuery(0x4242, "Ads.Example.COM", DnsMessage.TYPE_A)
        val pkt = IpPacket.buildUdp(v4a, v4b, 40000, 53, q)
        assertTrue(IpPacket.verifyChecksums(pkt))
        val p = IpPacket.parse(pkt, pkt.size)!!
        assertEquals(4, p.ipVersion); assertEquals(17, p.protocol)
        assertEquals(40000, p.srcPort); assertEquals(53, p.dstPort)
        assertArrayEquals(v4a, p.src); assertArrayEquals(v4b, p.dst)
        val dq = DnsMessage.parseQuery(pkt, p.payloadOffset, p.payloadLength)!!
        assertEquals("ads.example.com", dq.name)
        assertEquals(0x4242, dq.id)
        assertEquals(DnsMessage.TYPE_A, dq.qtype)
    }

    @Test
    fun udpIpv6RoundTripAndChecksums() {
        val q = DnsMessage.buildQuery(7, "example.org", DnsMessage.TYPE_AAAA)
        val pkt = IpPacket.buildUdp(v6a, v6b, 5353, 53, q)
        assertTrue(IpPacket.verifyChecksums(pkt))
        val p = IpPacket.parse(pkt, pkt.size)!!
        assertEquals(6, p.ipVersion)
        assertEquals("example.org", DnsMessage.parseQuery(pkt, p.payloadOffset, p.payloadLength)!!.name)
    }

    @Test
    fun rejectsFragmentsAndGarbage() {
        val pkt = IpPacket.buildUdp(v4a, v4b, 1, 53, DnsMessage.buildQuery(1, "a.com", 1))
        pkt[6] = 0x20 // MF flag
        assertNull(IpPacket.parse(pkt, pkt.size))
        assertNull(IpPacket.parse(ByteArray(10), 10))
        assertNull(IpPacket.parse(ByteArray(40).also { it[0] = 0x70 }, 40))
    }

    @Test
    fun tcpResetForSyn() {
        // Hand-built SYN 10.1.2.3:51000 -> 10.111.222.53:853, seq=1000
        val l4 = ByteArray(20)
        l4[0] = (51000 shr 8).toByte(); l4[1] = 51000.toByte(); l4[2] = (853 shr 8).toByte(); l4[3] = 853.toByte()
        l4[4] = 0; l4[5] = 0; l4[6] = 0x03; l4[7] = 0xE8.toByte(); l4[12] = 0x50; l4[13] = IpPacket.TCP_SYN.toByte()
        val ip = ByteArray(40)
        ip[0] = 0x45; ip[3] = 40; ip[8] = 64; ip[9] = 6
        System.arraycopy(v4a, 0, ip, 12, 4); System.arraycopy(v4b, 0, ip, 16, 4)
        System.arraycopy(l4, 0, ip, 20, 20)
        val syn = IpPacket.parse(ip, ip.size)!!
        val rst = IpPacket.buildTcpRst(syn)!!
        assertTrue(IpPacket.verifyChecksums(rst))
        val r = IpPacket.parse(rst, rst.size)!!
        assertEquals(853, r.srcPort); assertEquals(51000, r.dstPort)
        assertEquals(1001L, r.tcpAck)
        assertEquals(IpPacket.TCP_RST or IpPacket.TCP_ACK, r.tcpFlags)
        assertNull(IpPacket.buildTcpRst(r)) // never answer a RST
    }

    @Test
    fun blockedResponses() {
        val qa = DnsMessage.buildQuery(99, "doubleclick.net", DnsMessage.TYPE_A)
        val pa = DnsMessage.parseQuery(qa, 0, qa.size)!!
        val ra = DnsMessage.buildBlockedResponse(qa, 0, pa, BlockStyle.NULL_IP, 10)
        assertEquals(99, DnsMessage.id(ra)); assertTrue(DnsMessage.isResponse(ra))
        assertEquals(0, DnsMessage.rcode(ra)); assertEquals(10L, DnsMessage.minTtl(ra))
        assertEquals(qa.size + 16, ra.size) // 12-byte RR header + 4-byte 0.0.0.0
        assertTrue(ra.copyOfRange(ra.size - 4, ra.size).all { it == 0.toByte() })

        val q6 = DnsMessage.buildQuery(5, "doubleclick.net", DnsMessage.TYPE_AAAA)
        val r6 = DnsMessage.buildBlockedResponse(q6, 0, DnsMessage.parseQuery(q6, 0, q6.size)!!, BlockStyle.NULL_IP, 10)
        assertEquals(q6.size + 28, r6.size)

        val qh = DnsMessage.buildQuery(6, "doubleclick.net", 65)
        val rh = DnsMessage.buildBlockedResponse(qh, 0, DnsMessage.parseQuery(qh, 0, qh.size)!!, BlockStyle.NULL_IP, 10)
        assertEquals(qh.size, rh.size) // NODATA: no HTTPS record with address hints
        assertEquals(0, DnsMessage.rcode(rh))

        val rn = DnsMessage.buildBlockedResponse(qa, 0, pa, BlockStyle.NXDOMAIN, 10)
        assertEquals(3, DnsMessage.rcode(rn))
    }

    @Test
    fun cacheAgesTtlAndRewritesId() {
        var now = 1_000_000L
        val cache = DnsCache(clock = { now })
        val q = DnsMessage.buildQuery(1, "x.com", 1)
        val pq = DnsMessage.parseQuery(q, 0, q.size)!!
        // Use a "blocked" style response as a well-formed answer with TTL 100.
        val resp = DnsMessage.buildBlockedResponse(q, 0, pq, BlockStyle.NULL_IP, 100)
        cache.put(pq.cacheKey, resp)
        now += 30_000
        val hit = cache.get(pq.cacheKey, 777)!!
        assertEquals(777, DnsMessage.id(hit))
        assertEquals(70L, DnsMessage.minTtl(hit))
        now += 71_000
        assertNull(cache.get(pq.cacheKey, 1))
    }

    @Test
    fun cacheSkipsServfailAndTruncated() {
        val cache = DnsCache()
        val q = DnsMessage.buildQuery(1, "y.com", 1)
        val pq = DnsMessage.parseQuery(q, 0, q.size)!!
        cache.put("a", DnsMessage.buildErrorResponse(q, 0, pq, 2))
        assertNull(cache.get("a", 1))
        val tc = DnsMessage.buildBlockedResponse(q, 0, pq, BlockStyle.NULL_IP, 100)
        tc[2] = (tc[2].toInt() or 0x02).toByte()
        cache.put("b", tc)
        assertNull(cache.get("b", 1))
        assertFalse(DnsMessage.isTruncated(DnsMessage.buildErrorResponse(q, 0, pq, 2)))
        assertNotNull(DnsMessage.parseQuery(q, 0, q.size))
    }

    @Test
    fun icmpPortUnreachableForNonDnsUdp() {
        val dummyPayload = ByteArray(20) { it.toByte() }
        val udpPkt = IpPacket.buildUdp(v4a, v4b, 52000, 443, dummyPayload)
        val p = IpPacket.parse(udpPkt, udpPkt.size)!!
        assertEquals(443, p.dstPort)
        val icmp = IpPacket.buildIcmpPortUnreachable(p, udpPkt, udpPkt.size)!!
        assertNotNull(icmp)
        assertEquals(4, (icmp[0].toInt() ushr 4) and 0xF)
        assertEquals(IpPacket.PROTO_ICMP, icmp[9].toInt() and 0xFF)
        assertEquals(3, icmp[20].toInt() and 0xFF) // Type 3 Destination Unreachable
        assertEquals(3, icmp[21].toInt() and 0xFF) // Code 3 Port Unreachable

        val udpPkt6 = IpPacket.buildUdp(v6a, v6b, 52000, 443, dummyPayload)
        val p6 = IpPacket.parse(udpPkt6, udpPkt6.size)!!
        val icmp6 = IpPacket.buildIcmpPortUnreachable(p6, udpPkt6, udpPkt6.size)!!
        assertNotNull(icmp6)
        assertEquals(6, (icmp6[0].toInt() ushr 4) and 0xF)
        assertEquals(IpPacket.PROTO_ICMPV6, icmp6[6].toInt() and 0xFF)
        assertEquals(1, icmp6[40].toInt() and 0xFF) // Type 1 Destination Unreachable
        assertEquals(4, icmp6[41].toInt() and 0xFF) // Code 4 Port Unreachable
    }

    @Test
    fun buildTcpAndVerifyChecksums() {
        val payload = "Hello TikTok Handshake".toByteArray()
        val tcpPkt4 = IpPacket.buildTcp(
            src = v4a,
            dst = v4b,
            srcPort = 45000,
            dstPort = 443,
            seq = 1000L,
            ack = 2000L,
            flags = IpPacket.TCP_SYN or IpPacket.TCP_ACK,
            payload = payload,
            windowSize = 65535,
            mss = 1400,
        )
        assertTrue(IpPacket.verifyChecksums(tcpPkt4))
        val p4 = IpPacket.parse(tcpPkt4, tcpPkt4.size)!!
        assertEquals(4, p4.ipVersion)
        assertEquals(IpPacket.PROTO_TCP, p4.protocol)
        assertEquals(45000, p4.srcPort)
        assertEquals(443, p4.dstPort)
        assertEquals(1000L, p4.tcpSeq)
        assertEquals(2000L, p4.tcpAck)
        assertEquals(IpPacket.TCP_SYN or IpPacket.TCP_ACK, p4.tcpFlags)
        assertEquals(payload.size, p4.payloadLength)

        val tcpPkt6 = IpPacket.buildTcp(
            src = v6a,
            dst = v6b,
            srcPort = 45001,
            dstPort = 443,
            seq = 5000L,
            ack = 6000L,
            flags = IpPacket.TCP_ACK,
            payload = payload,
            windowSize = 32768,
        )
        assertTrue(IpPacket.verifyChecksums(tcpPkt6))
        val p6 = IpPacket.parse(tcpPkt6, tcpPkt6.size)!!
        assertEquals(6, p6.ipVersion)
        assertEquals(45001, p6.srcPort)
        assertEquals(443, p6.dstPort)
        assertEquals(5000L, p6.tcpSeq)
        assertEquals(6000L, p6.tcpAck)
        assertEquals(IpPacket.TCP_ACK, p6.tcpFlags)
    }

    @Test
    fun tlsClientHelloDetection() {
        // Valid TLS 1.2 ClientHello header
        val tlsClientHello = byteArrayOf(0x16, 0x03, 0x03, 0x00, 0x50, 0x01, 0x00)
        assertTrue(DpiBypassEngine.isTlsClientHello(tlsClientHello))

        // Valid TLS 1.3 ClientHello header (legacy_version is 0x0303 or 0x0301)
        val tls13 = byteArrayOf(0x16, 0x03, 0x01, 0x01, 0x00, 0x01)
        assertTrue(DpiBypassEngine.isTlsClientHello(tls13))

        // TLS Application Data (0x17)
        val tlsAppData = byteArrayOf(0x17, 0x03, 0x03, 0x00, 0x20, 0x00)
        assertFalse(DpiBypassEngine.isTlsClientHello(tlsAppData))

        // HTTP GET request
        val httpGet = "GET / HTTP/1.1\r\n".toByteArray()
        assertFalse(DpiBypassEngine.isTlsClientHello(httpGet))

        // Truncated / empty
        assertFalse(DpiBypassEngine.isTlsClientHello(ByteArray(4)))
        assertFalse(DpiBypassEngine.isTlsClientHello(ByteArray(0)))

        // Session key hashing
        val key1 = DpiBypassEngine.sessionKey(v4a, 1234, v4b, 443)
        val key2 = DpiBypassEngine.sessionKey(v4a, 1234, v4b, 443)
        val key3 = DpiBypassEngine.sessionKey(v4a, 1235, v4b, 443)
        assertEquals(key1, key2)
        assertTrue(key1 != key3)
    }
}
