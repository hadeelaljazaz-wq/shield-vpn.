package com.smartadshield.vpn.core

import com.smartadshield.vpn.core.dns.BlockStyle
import com.smartadshield.vpn.core.dns.DnsCache
import com.smartadshield.vpn.core.dns.DnsMessage
import com.smartadshield.vpn.core.dns.UpstreamResolver
import com.smartadshield.vpn.core.filter.AppMode
import com.smartadshield.vpn.core.filter.Decision
import com.smartadshield.vpn.core.filter.FilterEngine
import com.smartadshield.vpn.core.filter.Reason
import com.smartadshield.vpn.core.net.IpPacket
import com.smartadshield.vpn.core.net.ParsedPacket
import com.smartadshield.vpn.core.proxy.DpiBypassEngine
import java.net.InetAddress
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.ThreadFactory
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

class AppInfo(val uid: Int, val packageName: String?, val label: String, val mode: AppMode)

class QueryEvent(
    val time: Long,
    val domain: String,
    val qtype: Int,
    val decision: Decision,
    val app: AppInfo?,
    val cached: Boolean,
    val latencyMs: Long,
    val upstreamError: String?,
    val intercepted: Boolean,
)

class ProcessorConfig(
    val blockStyle: BlockStyle = BlockStyle.NULL_IP,
    /** Short TTL so that "allow this domain" takes effect within seconds even with OS caching. */
    val blockedTtl: Int = 10,
    val identifyApps: Boolean = true,
)

/**
 * The DNS data path: TUN packet in → policy → local answer / cache / upstream → TUN packet out.
 * Pure JVM code (no Android APIs) so it is covered by unit and integration tests.
 */
class DnsPacketProcessor(
    @Volatile var engine: FilterEngine,
    private val cache: DnsCache,
    private val upstream: UpstreamResolver,
    private val virtualDnsAddresses: Set<InetAddress>,
    private val writer: (ByteArray) -> Unit,
    private val listener: (QueryEvent) -> Unit = {},
    private val appResolver: (ParsedPacket) -> AppInfo? = { null },
    @Volatile var config: ProcessorConfig = ProcessorConfig(),
    val dpiBypass: DpiBypassEngine? = null,
    maxThreads: Int = 16,
) {
    private val threadIndex = AtomicInteger()
    private val executor = ThreadPoolExecutor(
        maxThreads, maxThreads, 20, TimeUnit.SECONDS, LinkedBlockingQueue(1024),
        ThreadFactory { r -> Thread(r, "dns-worker-${threadIndex.incrementAndGet()}").apply { isDaemon = true } },
        ThreadPoolExecutor.DiscardOldestPolicy(),
    ).apply { allowCoreThreadTimeOut(true) } // idle workers exit → no idle CPU/battery cost

    val droppedPackets = AtomicInteger()
    val tcpResets = AtomicInteger()
    val icmpUnreachables = AtomicInteger()

    /** Called from the TUN reader thread; [buf] is reused by the caller, so copy what we keep. */
    fun handlePacket(buf: ByteArray, len: Int) {
        val p = IpPacket.parse(buf, len)
        if (p == null) { droppedPackets.incrementAndGet(); return }
        when (p.protocol) {
            IpPacket.PROTO_TCP -> {
                val isDnsTcp = p.dstPort == 53 || runCatching {
                    InetAddress.getByAddress(p.dst) in virtualDnsAddresses
                }.getOrDefault(false)
                if (isDnsTcp || dpiBypass == null) {
                    // DoT (853), DoH to hijacked resolvers, or DNS-over-TCP to the virtual server:
                    // reset immediately so the client falls back to plain UDP DNS instead of hanging.
                    IpPacket.buildTcpRst(p)?.let { tcpResets.incrementAndGet(); writer(it) }
                } else {
                    dpiBypass.handleTcpPacket(p, buf, len)
                }
            }
            IpPacket.PROTO_UDP -> {
                if (p.dstPort == 53) {
                    val payload = buf.copyOfRange(p.payloadOffset, p.payloadOffset + p.payloadLength)
                    executor.execute { handleDns(p, payload) }
                } else if (dpiBypass != null && p.dstPort != 443) {
                    // Forward non-DNS UDP (except UDP 443 QUIC which is rejected with ICMP so clients fall back to TCP TLS for DPI bypass)
                    dpiBypass.handleUdpPacket(p, buf, len)
                } else {
                    // Non-DNS UDP (e.g. QUIC/443 to intercepted resolvers):
                    // reject immediately with ICMP Port Unreachable so browser falls back instantly.
                    IpPacket.buildIcmpPortUnreachable(p, buf, len)?.let {
                        icmpUnreachables.incrementAndGet()
                        writer(it)
                    } ?: droppedPackets.incrementAndGet()
                }
            }
            else -> droppedPackets.incrementAndGet()
        }
    }

    /** Synchronous variant used by tests. */
    fun handlePacketSync(buf: ByteArray, len: Int) {
        val p = IpPacket.parse(buf, len) ?: return
        if (p.protocol == IpPacket.PROTO_UDP && p.dstPort == 53) {
            handleDns(p, buf.copyOfRange(p.payloadOffset, p.payloadOffset + p.payloadLength))
        } else if (p.protocol == IpPacket.PROTO_TCP) {
            IpPacket.buildTcpRst(p)?.let(writer)
        } else if (p.protocol == IpPacket.PROTO_UDP) {
            IpPacket.buildIcmpPortUnreachable(p, buf, len)?.let(writer)
        }
    }

    private fun handleDns(p: ParsedPacket, payload: ByteArray) {
        val started = System.nanoTime()
        val q = DnsMessage.parseQuery(payload, 0, payload.size)
        if (q == null) { droppedPackets.incrementAndGet(); return }
        val cfg = config
        val app = if (cfg.identifyApps) runCatching { appResolver(p) }.getOrNull() else null
        val dst = InetAddress.getByAddress(p.dst)
        val intercepted = dst !in virtualDnsAddresses
        val decision = engine.evaluate(q.name, app?.mode ?: AppMode.FILTER)

        if (decision.blocked) {
            val style = if (decision.reason == Reason.DNS_BYPASS) BlockStyle.NXDOMAIN else cfg.blockStyle
            val resp = DnsMessage.buildBlockedResponse(payload, 0, q, style, cfg.blockedTtl)
            writer(IpPacket.buildUdpReply(p, resp))
            listener(QueryEvent(System.currentTimeMillis(), q.name, q.qtype, decision, app, false, elapsed(started), null, intercepted))
            return
        }

        val key = if (intercepted) "${dst.hostAddress}|${q.cacheKey}" else q.cacheKey
        cache.get(key, q.id)?.let { cached ->
            writer(IpPacket.buildUdpReply(p, cached))
            listener(QueryEvent(System.currentTimeMillis(), q.name, q.qtype, decision, app, true, elapsed(started), null, intercepted))
            return
        }

        val result = upstream.resolve(payload, payload.size, if (intercepted) dst else null)
        val resp = result.response
        if (resp != null) {
            cache.put(key, resp)
            writer(IpPacket.buildUdpReply(p, resp))
        } else {
            // Fail fast so the OS resolver can retry/fall back rather than wait for a timeout.
            writer(IpPacket.buildUdpReply(p, DnsMessage.buildErrorResponse(payload, 0, q, DnsMessage.RCODE_SERVFAIL)))
        }
        listener(QueryEvent(System.currentTimeMillis(), q.name, q.qtype, decision, app, false, result.latencyMs, result.error, intercepted))
    }

    private fun elapsed(startNs: Long) = (System.nanoTime() - startNs) / 1_000_000

    fun shutdown() {
        executor.shutdownNow()
    }
}
