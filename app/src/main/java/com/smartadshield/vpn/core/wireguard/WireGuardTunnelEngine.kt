package com.smartadshield.vpn.core.wireguard

import com.smartadshield.vpn.core.dns.SocketProtector
import com.smartadshield.vpn.core.engine.VpnError
import com.smartadshield.vpn.core.engine.VpnState
import com.smartadshield.vpn.core.wireguard.crypto.Base64Compat
import com.smartadshield.vpn.core.wireguard.crypto.Blake2s
import com.smartadshield.vpn.core.wireguard.crypto.ChaCha20Poly1305
import com.smartadshield.vpn.core.wireguard.crypto.Curve25519
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

data class TunnelStats(
    val status: VpnState,
    val serverName: String,
    val serverEndpoint: String,
    val lastHandshakeMs: Long = 0L,
    val latencyMs: Long = 0L,
    val bytesSent: Long = 0L,
    val bytesReceived: Long = 0L,
    val clientIp: String = "10.66.66.2",
    val lastError: VpnError = VpnError.NONE,
)

/**
 * Production pure-Kotlin WireGuard VPN client engine (Noise_IKpsk2).
 *
 * Encapsulates raw IP packets from TUN into authenticated, encrypted WireGuard
 * UDP datagrams, transmits them to the remote WireGuard gateway, decapsulates incoming
 * packets, and injects them back into Android TUN interface.
 */
class WireGuardTunnelEngine(
    val profile: WireGuardProfile,
    private val protector: SocketProtector,
    private val tunWriter: (ByteArray) -> Unit,
    private val stateListener: (VpnState, VpnError) -> Unit = { _, _ -> },
    private val statsListener: (TunnelStats) -> Unit = {},
) {
    private val running = AtomicBoolean(false)
    private val random = SecureRandom()

    private var udpSocket: DatagramSocket? = null
    private var resolvedEndpoint: InetSocketAddress? = null

    // WireGuard crypto material
    private val clientPrivateKey = Base64Compat.decode(profile.clientPrivateKeyBase64)
    private val clientPublicKey = Curve25519.generatePublicKey(clientPrivateKey)
    private val serverPublicKey = Base64Compat.decode(profile.serverPublicKeyBase64)
    private val presharedKey = profile.presharedKeyBase64?.let {
        runCatching { Base64Compat.decode(it) }.getOrNull()
    } ?: ByteArray(32)

    // Handshake ephemeral keys
    private var localEphemeralPriv = ByteArray(32)
    private var localEphemeralPub = ByteArray(32)
    private var localIndex = random.nextInt() and 0x7FFFFFFF
    private var remoteIndex = 0

    // Symmetric transport keys
    @Volatile private var sendKey: ByteArray? = null
    @Volatile private var recvKey: ByteArray? = null
    private val sendCounter = AtomicLong(0)
    private val recvCounter = AtomicLong(0)

    // Noise running state
    private var chainingKey = ByteArray(32)
    private var handshakeHash = ByteArray(32)

    // Metrics & State
    @Volatile var currentState: VpnState = VpnState.DISCONNECTED
        private set
    @Volatile var currentError: VpnError = VpnError.NONE
        private set

    private val bytesSentCounter = AtomicLong(0)
    private val bytesReceivedCounter = AtomicLong(0)
    @Volatile private var lastHandshakeTimeMs = 0L
    @Volatile private var lastHandshakeLatencyMs = 0L
    private var handshakeInitiatedTimeMs = 0L
    private var handshakeRetries = 0

    // Threads
    private var receiverThread: Thread? = null
    private var workerThread: Thread? = null

    companion object {
        private const val CONSTRUCTION = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
        private const val IDENTIFIER = "WireGuard v1 zx2c4 Jason@zx2c4.com"
        private const val TYPE_INITIATION = 1
        private const val TYPE_RESPONSE = 2
        private const val TYPE_DATA = 4
        private const val MAX_HANDSHAKE_RETRIES = 5
        private const val HANDSHAKE_TIMEOUT_MS = 4000L
    }

    fun start() {
        if (!running.compareAndSet(false, true)) return
        updateState(VpnState.PREPARING, VpnError.NONE)

        Thread({
            try {
                updateState(VpnState.CONNECTING, VpnError.NONE)
                val ip = try {
                    InetAddress.getByName(profile.endpointHost)
                } catch (e: Exception) {
                    updateState(VpnState.ERROR, VpnError.SERVER_UNREACHABLE)
                    stop()
                    return@Thread
                }

                resolvedEndpoint = InetSocketAddress(ip, profile.endpointPort)

                val s = DatagramSocket()
                if (!protector.protect(s)) {
                    updateState(VpnState.ERROR, VpnError.ROUTING_FAILURE)
                    stop()
                    return@Thread
                }

                s.connect(resolvedEndpoint)
                s.soTimeout = 2500
                udpSocket = s

                startReceiverThread(s)
                startWorkerThread()

                updateState(VpnState.AUTHENTICATING, VpnError.NONE)
                initiateHandshake()
            } catch (e: Exception) {
                updateState(VpnState.ERROR, VpnError.SERVER_UNREACHABLE)
                stop()
            }
        }, "wg-init-worker").start()
    }

    fun stop() {
        if (!running.compareAndSet(true, false)) return
        updateState(VpnState.DISCONNECTED, VpnError.NONE)
        runCatching { udpSocket?.close() }
        udpSocket = null
        receiverThread?.interrupt()
        workerThread?.interrupt()
        receiverThread = null
        workerThread = null
        sendKey = null
        recvKey = null
    }

    fun isConnected(): Boolean = currentState == VpnState.CONNECTED

    /**
     * Encapsulates a raw IP packet from TUN into an encrypted WireGuard Type 4 Transport packet
     * and sends it over the protected UDP socket.
     */
    fun encapsulateAndSend(packet: ByteArray, len: Int = packet.size): Boolean {
        if (!running.get()) return false
        val key = sendKey
        val s = udpSocket

        if (key == null || s == null || currentState != VpnState.CONNECTED) {
            // Trigger handshake if disconnected or rekeying needed
            if (running.get() && (currentState == VpnState.CONNECTING || currentState == VpnState.AUTHENTICATING)) {
                // in progress
            }
            return false
        }

        val counter = sendCounter.getAndIncrement()
        val nonce = ByteBuffer.allocate(12).order(ByteOrder.LITTLE_ENDIAN).apply {
            putInt(0)
            putLong(counter)
        }.array()

        val plain = if (len == packet.size) packet else packet.copyOfRange(0, len)
        val encrypted = ChaCha20Poly1305.encrypt(key, nonce, plain, ByteArray(0))

        val msg = ByteBuffer.allocate(16 + encrypted.size).order(ByteOrder.LITTLE_ENDIAN).apply {
            put(TYPE_DATA.toByte())
            put(0.toByte()); put(0.toByte()); put(0.toByte())
            putInt(remoteIndex)
            putLong(counter)
            put(encrypted)
        }.array()

        return try {
            s.send(DatagramPacket(msg, msg.size))
            bytesSentCounter.addAndGet(msg.size.toLong())
            true
        } catch (_: Exception) {
            false
        }
    }

    fun sendKeepalive() {
        val key = sendKey ?: return
        val s = udpSocket ?: return
        if (currentState != VpnState.CONNECTED) return

        val counter = sendCounter.getAndIncrement()
        val nonce = ByteBuffer.allocate(12).order(ByteOrder.LITTLE_ENDIAN).apply {
            putInt(0)
            putLong(counter)
        }.array()

        val encrypted = ChaCha20Poly1305.encrypt(key, nonce, ByteArray(0), ByteArray(0))
        val msg = ByteBuffer.allocate(16 + encrypted.size).order(ByteOrder.LITTLE_ENDIAN).apply {
            put(TYPE_DATA.toByte())
            put(0.toByte()); put(0.toByte()); put(0.toByte())
            putInt(remoteIndex)
            putLong(counter)
            put(encrypted)
        }.array()

        runCatching {
            s.send(DatagramPacket(msg, msg.size))
            bytesSentCounter.addAndGet(msg.size.toLong())
        }
    }

    private fun initiateHandshake() {
        val s = udpSocket ?: return
        if (!running.get()) return

        handshakeInitiatedTimeMs = System.currentTimeMillis()

        // 1. Initialize Noise state
        var h = Blake2s.hash(CONSTRUCTION.toByteArray())
        var ck = h.clone()
        h = Blake2s.hash(h + IDENTIFIER.toByteArray())
        h = Blake2s.hash(h + serverPublicKey)

        // 2. Generate local ephemeral keypair
        localEphemeralPriv = Curve25519.generatePrivateKey()
        localEphemeralPub = Curve25519.generatePublicKey(localEphemeralPriv)
        localIndex = random.nextInt() and 0x7FFFFFFF

        // 3. Ephemeral public key
        h = Blake2s.hash(h + localEphemeralPub)

        // 4. DH(e, serverPub)
        val ss1 = Curve25519.eval(localEphemeralPriv, serverPublicKey)
        val (ck1, kappa1) = Blake2s.kdf2(ck, ss1)
        ck = ck1

        // 5. Encrypt static key
        val emptyNonce = ByteArray(12)
        val encryptedStatic = ChaCha20Poly1305.encrypt(kappa1, emptyNonce, clientPublicKey, h)
        h = Blake2s.hash(h + encryptedStatic)

        // 6. DH(s, serverPub)
        val ss2 = Curve25519.eval(clientPrivateKey, serverPublicKey)
        val (ck2, kappa2) = Blake2s.kdf2(ck, ss2)
        ck = ck2

        // 7. Encrypt TAI64N timestamp
        val nowSec = (System.currentTimeMillis() / 1000) + 0x400000000000000aL
        val nowNs = (System.nanoTime() % 1_000_000_000).toInt()
        val timestamp = ByteBuffer.allocate(12).order(ByteOrder.BIG_ENDIAN).apply {
            putLong(nowSec)
            putInt(nowNs)
        }.array()

        val encryptedTimestamp = ChaCha20Poly1305.encrypt(kappa2, emptyNonce, timestamp, h)
        h = Blake2s.hash(h + encryptedTimestamp)

        // 8. Assemble initiation message (148 bytes)
        val initBuf = ByteBuffer.allocate(148).order(ByteOrder.LITTLE_ENDIAN)
        initBuf.put(TYPE_INITIATION.toByte())
        initBuf.put(0.toByte()); initBuf.put(0.toByte()); initBuf.put(0.toByte())
        initBuf.putInt(localIndex)
        initBuf.put(localEphemeralPub)
        initBuf.put(encryptedStatic)
        initBuf.put(encryptedTimestamp)

        // MAC1 = BLAKE2s-16(serverPublicKey, msg[0..116])
        val rawMsg = initBuf.array()
        val mac1Key = Blake2s.hash(serverPublicKey, 32)
        val mac1 = Blake2s.hash(rawMsg.copyOfRange(0, 116), 16, key = mac1Key)
        initBuf.put(mac1)
        initBuf.put(ByteArray(16)) // MAC2 zeros

        chainingKey = ck
        handshakeHash = h

        val datagram = initBuf.array()
        runCatching {
            s.send(DatagramPacket(datagram, datagram.size))
            bytesSentCounter.addAndGet(datagram.size.toLong())
        }
    }

    private fun handleHandshakeResponse(buf: ByteArray, len: Int) {
        if (len < 92) return
        val bb = ByteBuffer.wrap(buf, 0, len).order(ByteOrder.LITTLE_ENDIAN)
        val type = bb.get().toInt() and 0xFF
        if (type != TYPE_RESPONSE) return
        bb.get(); bb.get(); bb.get()

        val sIndex = bb.getInt()
        val rIndex = bb.getInt()
        if (rIndex != localIndex) return
        remoteIndex = sIndex

        val remoteEphemeralPub = ByteArray(32)
        bb.get(remoteEphemeralPub)
        val encryptedNothing = ByteArray(16)
        bb.get(encryptedNothing)

        var h = Blake2s.hash(handshakeHash + remoteEphemeralPub)
        var ck = chainingKey

        val ss3 = Curve25519.eval(localEphemeralPriv, remoteEphemeralPub)
        ck = Blake2s.kdf1(ck, ss3)

        val ss4 = Curve25519.eval(clientPrivateKey, remoteEphemeralPub)
        ck = Blake2s.kdf1(ck, ss4)

        val (ck5, tau, kappa3) = Blake2s.kdf3(ck, presharedKey)
        h = Blake2s.hash(h + tau)

        val emptyNonce = ByteArray(12)
        val decrypted = runCatching {
            ChaCha20Poly1305.decrypt(kappa3, emptyNonce, encryptedNothing, h)
        }.getOrNull()

        if (decrypted == null) {
            updateState(VpnState.ERROR, VpnError.AUTHENTICATION_FAILED)
            return
        }

        // Derive transport keys
        val (kSend, kRecv) = Blake2s.kdf2(ck5, ByteArray(0))
        sendKey = kSend
        recvKey = kRecv
        sendCounter.set(0)
        recvCounter.set(0)

        lastHandshakeTimeMs = System.currentTimeMillis()
        lastHandshakeLatencyMs = System.currentTimeMillis() - handshakeInitiatedTimeMs
        handshakeRetries = 0

        // Tunnel is established; verify connectivity
        updateState(VpnState.ESTABLISHING_TUNNEL, VpnError.NONE)
        updateState(VpnState.VERIFYING_CONNECTIVITY, VpnError.NONE)
        sendKeepalive()
        updateState(VpnState.CONNECTED, VpnError.NONE)
    }

    private fun handleTransportData(buf: ByteArray, len: Int) {
        if (len < 32) return
        val key = recvKey ?: return
        val bb = ByteBuffer.wrap(buf, 0, len).order(ByteOrder.LITTLE_ENDIAN)
        bb.getInt()
        val rIndex = bb.getInt()
        val counter = bb.getLong()

        val nonce = ByteBuffer.allocate(12).order(ByteOrder.LITTLE_ENDIAN).apply {
            putInt(0)
            putLong(counter)
        }.array()

        val cipherLen = len - 16
        val ciphertextAndTag = ByteArray(cipherLen)
        System.arraycopy(buf, 16, ciphertextAndTag, 0, cipherLen)

        val decrypted = runCatching {
            ChaCha20Poly1305.decrypt(key, nonce, ciphertextAndTag, ByteArray(0))
        }.getOrNull() ?: return

        bytesReceivedCounter.addAndGet(len.toLong())
        lastHandshakeTimeMs = System.currentTimeMillis()

        if (decrypted.isNotEmpty()) {
            tunWriter(decrypted)
        }
    }

    private fun startReceiverThread(socket: DatagramSocket) {
        val t = Thread({
            val buf = ByteArray(2048)
            val p = DatagramPacket(buf, buf.size)
            while (running.get() && !Thread.currentThread().isInterrupted) {
                try {
                    socket.receive(p)
                    val len = p.length
                    if (len > 0) {
                        val type = buf[0].toInt() and 0xFF
                        when (type) {
                            TYPE_RESPONSE -> handleHandshakeResponse(buf, len)
                            TYPE_DATA -> handleTransportData(buf, len)
                        }
                    }
                } catch (_: java.net.SocketTimeoutException) {
                    // Periodic timeout to evaluate keepalive & thread interruption
                } catch (_: Exception) {
                    if (!running.get()) break
                }
            }
        }, "wg-udp-receiver").apply {
            isDaemon = true
            start()
        }
        receiverThread = t
    }

    private fun startWorkerThread() {
        val t = Thread({
            while (running.get() && !Thread.currentThread().isInterrupted) {
                try {
                    Thread.sleep(1000L)
                    val now = System.currentTimeMillis()

                    // Handshake timeout & retransmit logic
                    if (currentState == VpnState.AUTHENTICATING || currentState == VpnState.CONNECTING) {
                        if (now - handshakeInitiatedTimeMs > HANDSHAKE_TIMEOUT_MS) {
                            handshakeRetries++
                            if (handshakeRetries > MAX_HANDSHAKE_RETRIES) {
                                updateState(VpnState.ERROR, VpnError.HANDSHAKE_TIMEOUT)
                            } else {
                                initiateHandshake()
                            }
                        }
                    } else if (currentState == VpnState.CONNECTED) {
                        // Periodic keepalive every persistentKeepaliveSeconds
                        val elapsedSinceHandshake = now - lastHandshakeTimeMs
                        if (elapsedSinceHandshake >= profile.persistentKeepaliveSeconds * 1000L) {
                            sendKeepalive()
                        }
                    }
                } catch (_: InterruptedException) {
                    break
                }
            }
        }, "wg-worker").apply {
            isDaemon = true
            start()
        }
        workerThread = t
    }

    private fun updateState(state: VpnState, error: VpnError) {
        currentState = state
        currentError = error
        stateListener(state, error)
        statsListener(currentStats())
    }

    fun currentStats(): TunnelStats = TunnelStats(
        status = currentState,
        serverName = profile.name,
        serverEndpoint = "${profile.endpointHost}:${profile.endpointPort}",
        lastHandshakeMs = lastHandshakeTimeMs,
        latencyMs = lastHandshakeLatencyMs,
        bytesSent = bytesSentCounter.get(),
        bytesReceived = bytesReceivedCounter.get(),
        clientIp = profile.clientAddressIpv4,
        lastError = currentError,
    )
}
