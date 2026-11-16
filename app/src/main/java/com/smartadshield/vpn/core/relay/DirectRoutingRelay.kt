package com.smartadshield.vpn.core.relay

import com.smartadshield.vpn.core.dns.SocketProtector
import com.smartadshield.vpn.core.net.IpPacket
import com.smartadshield.vpn.core.net.ParsedPacket
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.ThreadFactory
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

/**
 * Transparent direct routing relay for non-tunneled applications.
 *
 * Ensures all regular apps (YouTube, Chrome, Banking, WhatsApp) maintain their original
 * public IP address and 100% full hardware network speed without routing through any
 * external VPN server.
 *
 * QUIC (UDP 443) and HTTPS are forwarded intact without TLS interception or certificate modification.
 */
class DirectRoutingRelay(
    private val tunWriter: (ByteArray) -> Unit,
    private val protector: SocketProtector,
    private val maxTcpSessions: Int = 512,
    private val maxUdpSessions: Int = 256,
) {
    private val running = AtomicBoolean(true)
    private val threadIndex = AtomicInteger()

    private val executor = ThreadPoolExecutor(
        8, 32, 30L, TimeUnit.SECONDS, LinkedBlockingQueue(1024),
        ThreadFactory { r -> Thread(r, "direct-relay-${threadIndex.incrementAndGet()}").apply { isDaemon = true } },
        ThreadPoolExecutor.DiscardOldestPolicy(),
    ).apply { allowCoreThreadTimeOut(true) }

    private val tcpSessions = ConcurrentHashMap<Long, DirectTcpSession>()
    private val udpSessions = ConcurrentHashMap<Long, DirectUdpSession>()

    fun handleTcpPacket(p: ParsedPacket, buf: ByteArray, len: Int) {
        if (!running.get()) return
        val key = sessionKey(p.src, p.srcPort, p.dst, p.dstPort)
        val flags = p.tcpFlags

        if ((flags and IpPacket.TCP_SYN) != 0 && (flags and IpPacket.TCP_ACK) == 0) {
            if (tcpSessions.size >= maxTcpSessions) {
                IpPacket.buildTcpRst(p)?.let(tunWriter)
                return
            }
            val session = DirectTcpSession(
                key = key,
                clientIp = p.src,
                clientPort = p.srcPort,
                serverIp = p.dst,
                serverPort = p.dstPort,
                clientInitSeq = p.tcpSeq,
                ipVersion = p.ipVersion,
                tunWriter = tunWriter,
                protector = protector,
                onClosed = { tcpSessions.remove(key) },
            )
            tcpSessions[key] = session
            executor.execute { session.start() }
        } else {
            val session = tcpSessions[key]
            if (session != null) {
                session.handlePacket(p, buf, len)
            } else if ((flags and IpPacket.TCP_RST) == 0) {
                IpPacket.buildTcpRst(p)?.let(tunWriter)
            }
        }
    }

    fun handleUdpPacket(p: ParsedPacket, buf: ByteArray, len: Int) {
        if (!running.get()) return
        val key = sessionKey(p.src, p.srcPort, p.dst, p.dstPort)
        var session = udpSessions[key]
        if (session == null) {
            if (udpSessions.size >= maxUdpSessions) return
            val created = DirectUdpSession(
                key = key,
                clientIp = p.src,
                clientPort = p.srcPort,
                serverIp = p.dst,
                serverPort = p.dstPort,
                tunWriter = tunWriter,
                protector = protector,
                onClosed = { udpSessions.remove(key) },
            )
            udpSessions[key] = created
            session = created
            executor.execute { created.start() }
        }
        val payload = buf.copyOfRange(p.payloadOffset, p.payloadOffset + p.payloadLength)
        session.send(payload)
    }

    fun shutdown() {
        if (!running.compareAndSet(true, false)) return
        executor.shutdownNow()
        tcpSessions.values.forEach { runCatching { it.close() } }
        tcpSessions.clear()
        udpSessions.values.forEach { runCatching { it.close() } }
        udpSessions.clear()
    }

    companion object {
        fun sessionKey(src: ByteArray, srcPort: Int, dst: ByteArray, dstPort: Int): Long {
            var hash = 17L
            for (b in src) hash = 31L * hash + (b.toInt() and 0xFF)
            for (b in dst) hash = 31L * hash + (b.toInt() and 0xFF)
            return (hash shl 32) or ((srcPort.toLong() and 0xFFFF) shl 16) or (dstPort.toLong() and 0xFFFF)
        }
    }
}

/** Direct transparent TCP session between client app and real physical server. */
private class DirectTcpSession(
    val key: Long,
    val clientIp: ByteArray,
    val clientPort: Int,
    val serverIp: ByteArray,
    val serverPort: Int,
    val clientInitSeq: Long,
    val ipVersion: Int,
    val tunWriter: (ByteArray) -> Unit,
    val protector: SocketProtector,
    val onClosed: () -> Unit,
) {
    private val socket = Socket()
    private val closed = AtomicBoolean(false)
    private var mySeq = 1000L
    private var expectedClientSeq = (clientInitSeq + 1) and 0xFFFFFFFFL

    fun start() {
        try {
            if (!protector.protect(socket)) {
                close()
                return
            }
            socket.tcpNoDelay = true
            socket.soTimeout = 30_000
            val targetAddr = InetSocketAddress(InetAddress.getByAddress(serverIp), serverPort)
            socket.connect(targetAddr, 8000)

            // Reply SYN-ACK to client
            val synAck = IpPacket.buildTcp(
                src = serverIp, dst = clientIp, srcPort = serverPort, dstPort = clientPort,
                seq = mySeq, ack = expectedClientSeq,
                flags = IpPacket.TCP_SYN or IpPacket.TCP_ACK,
                mss = 1400,
            )
            mySeq = (mySeq + 1) and 0xFFFFFFFFL
            tunWriter(synAck)

            // Read loop from server to TUN
            val inStream = socket.getInputStream()
            val buf = ByteArray(16384)
            while (!closed.get()) {
                val n = inStream.read(buf)
                if (n < 0) break
                if (n > 0) {
                    val dataPkt = IpPacket.buildTcp(
                        src = serverIp, dst = clientIp, srcPort = serverPort, dstPort = clientPort,
                        seq = mySeq, ack = expectedClientSeq,
                        flags = IpPacket.TCP_ACK,
                        payload = buf, payloadOff = 0, payloadLen = n,
                    )
                    mySeq = (mySeq + n) and 0xFFFFFFFFL
                    tunWriter(dataPkt)
                }
            }
        } catch (_: Exception) {
        } finally {
            close()
        }
    }

    fun handlePacket(p: ParsedPacket, buf: ByteArray, len: Int) {
        if (closed.get()) return
        val flags = p.tcpFlags

        if ((flags and IpPacket.TCP_RST) != 0) {
            close()
            return
        }

        if ((flags and IpPacket.TCP_FIN) != 0) {
            expectedClientSeq = (p.tcpSeq + 1) and 0xFFFFFFFFL
            val finAck = IpPacket.buildTcp(
                src = serverIp, dst = clientIp, srcPort = serverPort, dstPort = clientPort,
                seq = mySeq, ack = expectedClientSeq,
                flags = IpPacket.TCP_ACK or IpPacket.TCP_FIN,
            )
            tunWriter(finAck)
            close()
            return
        }

        if (p.payloadLength > 0) {
            expectedClientSeq = (p.tcpSeq + p.payloadLength) and 0xFFFFFFFFL
            try {
                val out = socket.getOutputStream()
                out.write(buf, p.payloadOffset, p.payloadLength)
                out.flush()

                // Send ACK back
                val ack = IpPacket.buildTcp(
                    src = serverIp, dst = clientIp, srcPort = serverPort, dstPort = clientPort,
                    seq = mySeq, ack = expectedClientSeq,
                    flags = IpPacket.TCP_ACK,
                )
                tunWriter(ack)
            } catch (_: Exception) {
                close()
            }
        }
    }

    fun close() {
        if (closed.compareAndSet(false, true)) {
            runCatching { socket.close() }
            onClosed()
        }
    }
}

/** Direct UDP session (supporting QUIC without modification). */
private class DirectUdpSession(
    val key: Long,
    val clientIp: ByteArray,
    val clientPort: Int,
    val serverIp: ByteArray,
    val serverPort: Int,
    val tunWriter: (ByteArray) -> Unit,
    val protector: SocketProtector,
    val onClosed: () -> Unit,
) {
    private val socket = DatagramSocket()
    private val closed = AtomicBoolean(false)
    private val target = InetSocketAddress(InetAddress.getByAddress(serverIp), serverPort)

    fun start() {
        try {
            if (!protector.protect(socket)) {
                close()
                return
            }
            socket.connect(target)
            socket.soTimeout = 45_000
            val buf = ByteArray(2048)
            val p = DatagramPacket(buf, buf.size)
            while (!closed.get()) {
                socket.receive(p)
                val reply = IpPacket.buildUdp(
                    src = serverIp, dst = clientIp, srcPort = serverPort, dstPort = clientPort,
                    payload = buf, payloadOff = 0, payloadLen = p.length,
                )
                tunWriter(reply)
            }
        } catch (_: Exception) {
        } finally {
            close()
        }
    }

    fun send(payload: ByteArray) {
        if (closed.get()) return
        runCatching {
            socket.send(DatagramPacket(payload, payload.size))
        }
    }

    fun close() {
        if (closed.compareAndSet(false, true)) {
            runCatching { socket.close() }
            onClosed()
        }
    }
}
