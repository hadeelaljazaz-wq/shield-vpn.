package com.smartadshield.vpn.core.routing

import com.smartadshield.vpn.core.AppInfo
import com.smartadshield.vpn.core.DnsPacketProcessor
import com.smartadshield.vpn.core.net.IpPacket
import com.smartadshield.vpn.core.net.ParsedPacket
import com.smartadshield.vpn.core.relay.DirectRoutingRelay
import com.smartadshield.vpn.core.wireguard.WireGuardTunnelEngine
import java.net.InetAddress
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

enum class RouteMode {
    DNS_LOCAL,
    WIREGUARD_TUNNEL,
    DIRECT_PHYSICAL,
}

data class HybridRouterStats(
    val dnsQueriesProcessed: Long,
    val tunneledPackets: Long,
    val directPackets: Long,
    val killSwitchBlockedPackets: Long,
)

/**
 * Master Hybrid VPN Router coordinating:
 * 1. Unified Local DNS Filtering (190,000+ rules + Video Compatibility) for all apps.
 * 2. Real WireGuard Encrypted Tunnel for TikTok and designated apps.
 * 3. Transparent Direct Routing for all other apps (preserving local IP and maximum speed).
 * 4. Selective Kill Switch for tunneled apps without breaking regular internet.
 */
class HybridRouter(
    val dnsProcessor: DnsPacketProcessor,
    val wireGuardEngine: WireGuardTunnelEngine?,
    val directRelay: DirectRoutingRelay,
    private val tunneledPackageNames: Set<String>,
    private val appResolver: (ParsedPacket) -> AppInfo?,
    private val tunWriter: (ByteArray) -> Unit,
    val killSwitchEnabled: Boolean = true,
) {
    private val dnsCount = AtomicLong(0)
    private val tunneledCount = AtomicLong(0)
    private val directCount = AtomicLong(0)
    private val killSwitchCount = AtomicLong(0)

    // Fast session cache: sessionKey -> RouteMode
    private val sessionRouteCache = ConcurrentHashMap<Long, RouteMode>(1024)

    fun handlePacket(buf: ByteArray, len: Int) {
        val p = IpPacket.parse(buf, len) ?: return

        // 1. Port 53 DNS Queries (UDP or TCP) are intercepted locally for ALL apps
        if (p.dstPort == 53) {
            dnsCount.incrementAndGet()
            dnsProcessor.handlePacket(buf, len)
            return
        }

        // 2. Classify traffic by connection 4-tuple
        val key = DirectRoutingRelay.sessionKey(p.src, p.srcPort, p.dst, p.dstPort)
        var routeMode = sessionRouteCache[key]

        if (routeMode == null) {
            val app = runCatching { appResolver(p) }.getOrNull()
            val isTunneledApp = app?.packageName != null && app.packageName in tunneledPackageNames

            routeMode = if (isTunneledApp) RouteMode.WIREGUARD_TUNNEL else RouteMode.DIRECT_PHYSICAL
            if (sessionRouteCache.size < 4096) {
                sessionRouteCache[key] = routeMode
            }
        }

        // 3. Dispatch based on route mode
        when (routeMode) {
            RouteMode.WIREGUARD_TUNNEL -> {
                val wg = wireGuardEngine
                if (wg != null && wg.isConnected()) {
                    tunneledCount.incrementAndGet()
                    wg.encapsulateAndSend(buf, len)
                } else {
                    // Selective Kill Switch for tunneled apps:
                    // Drop or RST packets when WireGuard is down so TikTok never leaks to the ISP.
                    killSwitchCount.incrementAndGet()
                    if (killSwitchEnabled && p.protocol == IpPacket.PROTO_TCP) {
                        IpPacket.buildTcpRst(p)?.let(tunWriter)
                    }
                }
            }

            RouteMode.DIRECT_PHYSICAL -> {
                directCount.incrementAndGet()
                when (p.protocol) {
                    IpPacket.PROTO_TCP -> directRelay.handleTcpPacket(p, buf, len)
                    IpPacket.PROTO_UDP -> directRelay.handleUdpPacket(p, buf, len)
                    else -> directRelay.handleUdpPacket(p, buf, len)
                }
            }

            RouteMode.DNS_LOCAL -> {
                dnsProcessor.handlePacket(buf, len)
            }
        }
    }

    fun stats(): HybridRouterStats = HybridRouterStats(
        dnsQueriesProcessed = dnsCount.get(),
        tunneledPackets = tunneledCount.get(),
        directPackets = directCount.get(),
        killSwitchBlockedPackets = killSwitchCount.get(),
    )

    fun shutdown() {
        sessionRouteCache.clear()
        directRelay.shutdown()
        wireGuardEngine?.stop()
        dnsProcessor.shutdown()
    }
}
