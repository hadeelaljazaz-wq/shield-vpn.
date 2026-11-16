package com.smartadshield.vpn.tunnel

import android.content.Context
import com.wireguard.android.backend.GoBackend
import com.wireguard.android.backend.Tunnel
import com.wireguard.config.Config
import com.wireguard.config.Interface
import com.wireguard.config.Peer
import com.wireguard.crypto.Key
import com.wireguard.crypto.KeyPair
import java.io.BufferedReader
import java.io.StringReader

/**
 * Official WireGuard userspace implementation (wireguard-go via GoBackend).
 * Replaces the previous hand-written Kotlin Noise implementation, which
 * omitted mandatory KDF steps and therefore could never complete a handshake.
 */
class WireGuardEngine(context: Context) {
    private val backend = GoBackend(context.applicationContext)

    private val tunnel = object : Tunnel {
        override fun getName() = "shield"
        override fun onStateChange(newState: Tunnel.State) {
            stateListener?.invoke(newState)
        }
    }

    @Volatile var stateListener: ((Tunnel.State) -> Unit)? = null
    @Volatile private var peerKey: Key? = null

    data class Split(val include: Set<String>, val exclude: Set<String>)

    fun buildFromProvisioned(
        p: ProvisionedServer,
        keyPair: KeyPair,
        dns: List<String>,
        split: Split,
    ): Config {
        val iface = Interface.Builder()
            .setKeyPair(keyPair)
            .parseAddresses(listOfNotNull(p.wgAddress4, p.wgAddress6).joinToString(", "))
            .parseDnsServers(dns.joinToString(", "))
            .setMtu(p.wgMtu)
        applySplit(iface, split)
        val peer = Peer.Builder()
            .parsePublicKey(p.wgServerPublicKey)
            .parseEndpoint(formatEndpoint(p.wgEndpointHost, p.wgEndpointPort))
            .parseAllowedIPs("0.0.0.0/0, ::/0")
            .setPersistentKeepalive(p.wgKeepalive)
            .build()
        return Config.Builder().setInterface(iface.build()).addPeer(peer).build()
    }

    /** Manual import: keeps the user's [Interface]/[Peer] but applies app split-tunnel and DNS choice. */
    fun buildFromWgQuick(text: String, overrideDns: List<String>?, split: Split): Config {
        val parsed = Config.parse(BufferedReader(StringReader(text)))
        val src = parsed.`interface`
        val iface = Interface.Builder()
            .setKeyPair(src.keyPair)
            .addAddresses(src.addresses)
        if (overrideDns != null) iface.parseDnsServers(overrideDns.joinToString(", ")) else iface.addDnsServers(src.dnsServers)
        src.mtu.ifPresent { iface.setMtu(it) }
        applySplit(iface, split)
        return Config.Builder().setInterface(iface.build()).addPeers(parsed.peers).build()
    }

    private fun applySplit(b: Interface.Builder, split: Split) {
        if (split.include.isNotEmpty()) b.includeApplications(split.include)
        else if (split.exclude.isNotEmpty()) b.excludeApplications(split.exclude)
    }

    fun up(config: Config) {
        peerKey = config.peers.firstOrNull()?.publicKey
        backend.setState(tunnel, Tunnel.State.UP, config)
    }

    fun down() {
        runCatching { backend.setState(tunnel, Tunnel.State.DOWN, null) }
    }

    fun isUp(): Boolean = runCatching { backend.getState(tunnel) == Tunnel.State.UP }.getOrDefault(false)

    data class Stats(val rx: Long, val tx: Long, val lastHandshakeMs: Long)

    fun stats(): Stats? = runCatching {
        val s = backend.getStatistics(tunnel)
        val key = peerKey ?: return null
        val ps = s.peer(key) ?: return Stats(s.totalRx(), s.totalTx(), 0L)
        Stats(ps.rxBytes(), ps.txBytes(), ps.latestHandshakeEpochMillis())
    }.getOrNull()

    fun version(): String = runCatching { backend.version }.getOrDefault("?")

    companion object {
        fun formatEndpoint(host: String, port: Int) = if (host.contains(':') && !host.startsWith("[")) "[$host]:$port" else "$host:$port"
    }
}
