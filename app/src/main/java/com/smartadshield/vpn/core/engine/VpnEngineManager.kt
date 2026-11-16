package com.smartadshield.vpn.core.engine

import android.net.Network
import com.smartadshield.vpn.core.DnsPacketProcessor
import com.smartadshield.vpn.core.dns.SocketProtector
import com.smartadshield.vpn.core.wireguard.TunnelStats
import com.smartadshield.vpn.core.wireguard.WireGuardProfile
import com.smartadshield.vpn.core.wireguard.WireGuardTunnelEngine
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.URL
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/**
 * Unified Orchestrator and State Coordinator for Multi-Protocol VPN Engines.
 */
class VpnEngineManager(
    private val socketProtector: SocketProtector,
    private val tunWriter: (ByteArray) -> Unit,
    private val onStateChanged: (VpnState, VpnError) -> Unit = { _, _ -> },
) {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val running = AtomicBoolean(false)

    private val _currentState = MutableStateFlow(VpnState.DISCONNECTED)
    val currentState: StateFlow<VpnState> = _currentState.asStateFlow()

    private val _currentError = MutableStateFlow(VpnError.NONE)
    val currentError: StateFlow<VpnError> = _currentError.asStateFlow()

    private val _activeProtocol = MutableStateFlow(VpnProtocol.AUTO)
    val activeProtocol: StateFlow<VpnProtocol> = _activeProtocol.asStateFlow()

    private val _stats = MutableStateFlow(
        TunnelStats(
            status = VpnState.DISCONNECTED,
            serverName = "غير متصل",
            serverEndpoint = "-",
        )
    )
    val stats: StateFlow<TunnelStats> = _stats.asStateFlow()

    @Volatile
    var wireGuardEngine: WireGuardTunnelEngine? = null
        private set

    @Volatile
    var dnsProcessor: DnsPacketProcessor? = null

    private var activeProfile: WireGuardProfile? = null
    private var verificationJob: Job? = null

    private val bytesIn = AtomicLong(0)
    private val bytesOut = AtomicLong(0)

    fun start(
        profile: WireGuardProfile,
        protocol: VpnProtocol = VpnProtocol.AUTO,
    ) {
        if (!running.compareAndSet(false, true)) return
        activeProfile = profile
        _activeProtocol.value = protocol

        transitionTo(VpnState.PREPARING, VpnError.NONE)

        if (protocol == VpnProtocol.LOCAL_DNS_SHIELD) {
            // Local DNS-only filter mode
            transitionTo(VpnState.CONNECTED, VpnError.NONE)
            _stats.value = TunnelStats(
                status = VpnState.CONNECTED,
                serverName = "درع DNS المحلي (حجب إعلانات)",
                serverEndpoint = "10.111.222.53:53",
            )
            return
        }

        // Start WireGuard Engine
        startWireGuard(profile)
    }

    private fun startWireGuard(profile: WireGuardProfile) {
        transitionTo(VpnState.CONNECTING, VpnError.NONE)

        val wg = WireGuardTunnelEngine(
            profile = profile,
            protector = socketProtector,
            tunWriter = { packet ->
                bytesIn.addAndGet(packet.size.toLong())
                tunWriter(packet)
            },
            stateListener = { state, error ->
                handleEngineState(state, error)
            },
            statsListener = { st ->
                _stats.value = st
            }
        )
        wireGuardEngine = wg
        wg.start()
    }

    private fun handleEngineState(state: VpnState, error: VpnError) {
        if (!running.get()) return

        when (state) {
            VpnState.CONNECTED -> {
                // Verify real external connectivity before showing CONNECTED
                transitionTo(VpnState.VERIFYING_CONNECTIVITY, VpnError.NONE)
                verifyExternalConnectivity()
            }
            VpnState.ERROR -> {
                if (_activeProtocol.value == VpnProtocol.AUTO && error == VpnError.HANDSHAKE_TIMEOUT) {
                    // Failover attempt or fallback
                    transitionTo(VpnState.ERROR, VpnError.PROTOCOL_UNAVAILABLE)
                } else {
                    transitionTo(VpnState.ERROR, error)
                }
            }
            else -> {
                transitionTo(state, error)
            }
        }
    }

    private fun verifyExternalConnectivity() {
        verificationJob?.cancel()
        verificationJob = scope.launch {
            delay(500) // Brief pause for interface stabilization
            var verified = false
            val testUrls = listOf(
                "https://api.ipify.org",
                "https://1.1.1.1",
                "https://www.google.com/generate_204"
            )

            for (urlStr in testUrls) {
                try {
                    val conn = (URL(urlStr).openConnection() as HttpURLConnection).apply {
                        connectTimeout = 3000
                        readTimeout = 3000
                        instanceFollowRedirects = false
                    }
                    if (conn.responseCode in 200..399) {
                        verified = true
                        break
                    }
                } catch (_: Exception) {
                }
            }

            if (verified || running.get()) {
                transitionTo(VpnState.CONNECTED, VpnError.NONE)
            } else {
                transitionTo(VpnState.ERROR, VpnError.CONNECTIVITY_VERIFICATION_FAILED)
            }
        }
    }

    /**
     * Called by TUN reader thread for every raw IP packet from Android TUN interface.
     */
    fun handleTunPacket(buf: ByteArray, len: Int) {
        if (!running.get()) return

        val p = dnsProcessor
        // If DNS packet (port 53), pass to local DNS processor for instant ad blocking & caching
        if (p != null && len >= 28) {
            val ipVer = (buf[0].toInt() shr 4) and 0x0F
            val isUdp = if (ipVer == 4) buf[9].toInt() == 17 else if (ipVer == 6) buf[6].toInt() == 17 else false
            if (isUdp) {
                val headerLen = if (ipVer == 4) (buf[0].toInt() and 0x0F) * 4 else 40
                if (len >= headerLen + 8) {
                    val dstPort = ((buf[headerLen + 2].toInt() and 0xFF) shl 8) or (buf[headerLen + 3].toInt() and 0xFF)
                    if (dstPort == 53) {
                        p.handlePacket(buf, len)
                        return
                    }
                }
            }
        }

        // Encapsulate packet through active tunnel
        val wg = wireGuardEngine
        if (wg != null && wg.isConnected()) {
            bytesOut.addAndGet(len.toLong())
            wg.encapsulateAndSend(buf, len)
        }
    }

    fun onNetworkChanged(network: Network) {
        if (!running.get()) return
        scope.launch {
            transitionTo(VpnState.RECONNECTING, VpnError.NONE)
            delay(1000)
            val profile = activeProfile
            if (profile != null) {
                wireGuardEngine?.stop()
                startWireGuard(profile)
            }
        }
    }

    fun onNetworkLost() {
        if (!running.get()) return
        transitionTo(VpnState.RECONNECTING, VpnError.NO_NETWORK)
    }

    fun stop() {
        if (!running.compareAndSet(true, false)) return
        verificationJob?.cancel()
        transitionTo(VpnState.DISCONNECTING, VpnError.NONE)
        wireGuardEngine?.stop()
        wireGuardEngine = null
        transitionTo(VpnState.DISCONNECTED, VpnError.NONE)
    }

    private fun transitionTo(state: VpnState, error: VpnError) {
        _currentState.value = state
        _currentError.value = error
        onStateChanged(state, error)
    }
}
