package com.smartadshield.vpn.core

import com.smartadshield.vpn.core.dns.DnsCache
import com.smartadshield.vpn.core.dns.DnsMessage
import com.smartadshield.vpn.core.dns.SocketProtector
import com.smartadshield.vpn.core.dns.UpstreamResolver
import com.smartadshield.vpn.core.filter.DomainHashSet
import com.smartadshield.vpn.core.filter.EngineOptions
import com.smartadshield.vpn.core.filter.FilterEngine
import com.smartadshield.vpn.core.net.IpPacket
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import java.net.InetAddress

/**
 * End-to-end test of the DNS data path with a REAL upstream resolver (network required):
 * raw IP/UDP packet → DnsPacketProcessor → upstream 8.8.8.8 / 1.1.1.1 → raw IP/UDP reply.
 * This is exactly what the VpnService feeds from / writes to the TUN file descriptor.
 */
class PipelineIntegrationTest {
    private val client4 = byteArrayOf(10, 111, 222.toByte(), 1)
    private val vdns4 = byteArrayOf(10, 111, 222.toByte(), 53)
    private val client6 = InetAddress.getByName("fd66:6164:7368::1").address
    private val vdns6 = InetAddress.getByName("fd66:6164:7368::53").address
    private val out = java.util.Collections.synchronizedList(ArrayList<ByteArray>())
    private val events = java.util.Collections.synchronizedList(ArrayList<QueryEvent>())
    private lateinit var proc: DnsPacketProcessor

    private fun reachable(): Boolean = runCatching {
        val r = UpstreamResolver(SocketProtector.None, 2000).apply { servers = listOf(InetAddress.getByName("8.8.8.8")) }
        r.resolve(DnsMessage.buildQuery(1, "example.com", 1), DnsMessage.buildQuery(1, "example.com", 1).size).response != null
    }.getOrDefault(false)

    @Before
    fun setup() {
        val engine = FilterEngine(
            DomainHashSet.Builder().apply { add("doubleclick.net") }.build(),
            DomainHashSet.EMPTY, DomainHashSet.EMPTY, emptyList(), emptySet(), emptySet(), EngineOptions(),
        )
        val upstream = UpstreamResolver(SocketProtector.None).apply {
            servers = listOf(InetAddress.getByName("8.8.8.8"), InetAddress.getByName("1.1.1.1"))
        }
        proc = DnsPacketProcessor(
            engine, DnsCache(), upstream,
            setOf(InetAddress.getByAddress(vdns4), InetAddress.getByAddress(vdns6)),
            writer = { out.add(it) }, listener = { events.add(it) },
        )
    }

    private fun send(src: ByteArray, dst: ByteArray, name: String, type: Int, id: Int): ByteArray {
        out.clear()
        val pkt = IpPacket.buildUdp(src, dst, 40000 + id, 53, DnsMessage.buildQuery(id, name, type))
        proc.handlePacketSync(pkt, pkt.size)
        assertEquals(1, out.size)
        val reply = out[0]
        assertTrue("checksums", IpPacket.verifyChecksums(reply))
        val p = IpPacket.parse(reply, reply.size)!!
        assertEquals(53, p.srcPort); assertEquals(40000 + id, p.dstPort)
        assertTrue(p.src.contentEquals(dst)); assertTrue(p.dst.contentEquals(src))
        val dns = reply.copyOfRange(p.payloadOffset, p.payloadOffset + p.payloadLength)
        assertEquals(id, DnsMessage.id(dns))
        return dns
    }

    @Test
    fun blockedQueryAnsweredLocallyWithoutNetwork() {
        val dns = send(client4, vdns4, "securepubads.g.doubleclick.net", 1, 11)
        assertEquals(0, DnsMessage.rcode(dns))
        assertTrue(dns.copyOfRange(dns.size - 4, dns.size).all { it == 0.toByte() })
        assertTrue(events.last().decision.blocked)
    }

    @Test
    fun realUpstreamIpv4AndIpv6TransportsAndCache() {
        assumeTrue("no network for upstream DNS", reachable())
        val a = send(client4, vdns4, "example.com", DnsMessage.TYPE_A, 21)
        assertEquals(0, DnsMessage.rcode(a))
        assertTrue("has answers", DnsMessage.minTtl(a) > 0)
        val first = events.last()
        println("[e2e] example.com A via IPv4 tunnel: ${a.size} bytes, upstream ${first.latencyMs} ms, cached=${first.cached}")

        val a2 = send(client4, vdns4, "example.com", DnsMessage.TYPE_A, 22)
        assertEquals(0, DnsMessage.rcode(a2))
        assertTrue("second identical query served from cache", events.last().cached)
        println("[e2e] repeat served from cache in ${events.last().latencyMs} ms")

        val aaaa = send(client6, vdns6, "www.google.com", DnsMessage.TYPE_AAAA, 23)
        assertEquals(0, DnsMessage.rcode(aaaa))
        println("[e2e] www.google.com AAAA via IPv6 tunnel transport: ${aaaa.size} bytes")

        val nx = send(client4, vdns4, "this-domain-does-not-exist-smartadshield.example", 1, 24)
        assertEquals(DnsMessage.RCODE_NXDOMAIN, DnsMessage.rcode(nx))
    }

    @Test
    fun truncatedUdpFallsBackToTcp() {
        assumeTrue("no network for upstream DNS", reachable())
        // google.com TXT is normally > 512 bytes → truncated over plain UDP (no EDNS) → TCP retry.
        val dns = send(client4, vdns4, "google.com", 16, 31)
        assertEquals(0, DnsMessage.rcode(dns))
        println("[e2e] google.com TXT size=${dns.size} truncated=${DnsMessage.isTruncated(dns)}")
        if (dns.size > 512) assertTrue(!DnsMessage.isTruncated(dns))
    }

    @Test
    fun interceptedHardcodedResolverIsFilteredAndForwardedToOriginalServer() {
        assumeTrue("no network for upstream DNS", reachable())
        val google = InetAddress.getByName("8.8.8.8").address
        val blocked = send(client4, google, "doubleclick.net", 1, 41)
        assertTrue(events.last().decision.blocked && events.last().intercepted)
        assertTrue(blocked.copyOfRange(blocked.size - 4, blocked.size).all { it == 0.toByte() })
        val ok = send(client4, google, "wikipedia.org", 1, 42)
        assertEquals(0, DnsMessage.rcode(ok))
        assertNotEquals(null, events.last().decision)
    }

    @Test
    fun tcpToVirtualDnsGetsReset() {
        val l4 = ByteArray(20)
        l4[0] = 0x9C.toByte(); l4[1] = 0x40; l4[2] = 0x03; l4[3] = 0x55 /* 853 */
        l4[7] = 5; l4[12] = 0x50; l4[13] = IpPacket.TCP_SYN.toByte()
        val ip = ByteArray(40)
        ip[0] = 0x45; ip[3] = 40; ip[8] = 64; ip[9] = 6
        System.arraycopy(client4, 0, ip, 12, 4); System.arraycopy(vdns4, 0, ip, 16, 4); System.arraycopy(l4, 0, ip, 20, 20)
        out.clear()
        proc.handlePacketSync(ip, ip.size)
        assertEquals(1, out.size)
        val r = IpPacket.parse(out[0], out[0].size)!!
        assertTrue((r.tcpFlags and IpPacket.TCP_RST) != 0)
    }
}
