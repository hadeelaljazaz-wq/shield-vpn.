package com.smartadshield.vpn.core.proxy

import com.smartadshield.vpn.core.dns.SocketProtector
import com.smartadshield.vpn.core.net.IpPacket
import com.smartadshield.vpn.core.net.ParsedPacket
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.StandardSocketOptions
import java.nio.ByteBuffer
import java.nio.channels.SocketChannel
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.ThreadFactory
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

/**
 * Transparent local TCP/UDP engine with Deep Packet Inspection (DPI) circumvention.
 *
 * When enabled, routes all device traffic locally. For TLS connections, the initial
 * ClientHello record is fragmented across TCP boundaries so ISP DPI hardware cannot inspect
 * the SNI extension and block restricted platforms (like TikTok).
 */
class DpiBypassEngine(
    private val writer: (ByteArray) -> Unit,
    private val protector: SocketProtector,
    private val fragmentSize: Int = 3,
    private val maxTcpSessions: Int = 256,
    private val maxUdpSessions: Int = 128,
) {
    private val threadIndex = AtomicInteger()
    private val executor = ThreadPoolExecutor(
        8, 32, 30L, TimeUnit.SECONDS, LinkedBlockingQueue(1024),
        ThreadFactory { r -> Thread(r, "dpi-worker-${threadIndex.incrementAndGet()}").apply { isDaemon = true } },
        ThreadPoolExecutor.DiscardOldestPolicy(),
    ).apply { allowCoreThreadTimeOut(true) }

    private val tcpSessions = ConcurrentHashMap<Long, TcpSession>()
    private val udpSessions = ConcurrentHashMap<Long, UdpSession>()
    private val running = AtomicBoolean(true)

    companion object {
        /**
         * Checks whether [data] begins with a standard TLS ClientHello handshake record:
         * Byte 0: 0x16 (Handshake)
         * Byte 1: 0x03 (TLS major version 3)
         * Byte 2: 0x00..0x04 (SSLv3, TLS 1.0, 1.1, 1.2, 1.3)
         * Byte 5: 0x01 (ClientHello)
         */
        fun isTlsClientHello(data: ByteArray, offset: Int = 0, length: Int = data.size): Boolean {
            if (length < 6 || offset + 6 > data.size) return false
            val b0 = data[offset].toInt() and 0xFF
            val b1 = data[offset + 1].toInt() and 0xFF
            val b2 = data[offset + 2].toInt() and 0xFF
            val b5 = data[offset + 5].toInt() and 0xFF
            return b0 == 0x16 && b1 == 0x03 && (b2 in 0x00..0x04) && b5 == 0x01
        }

        fun sessionKey(src: ByteArray, srcPort: Int, dst: ByteArray, dstPort: Int): Long {
            var hash = 17L
            for (b in src) hash = 31L * hash + (b.toInt() and 0xFF)
            for (b in dst) hash = 31L * hash + (b.toInt() and 0xFF)
            return (hash shl 32) or ((srcPort.toLong() and 0xFFFF) shl 16) or (dstPort.toLong() and 0xFFFF)
        }
    }

    @Suppress("UNUSED_PARAMETER")
    fun handleTcpPacket(p: ParsedPacket, buf: ByteArray, len: Int) {
        if (!running.get()) return
        val key = sessionKey(p.src, p.srcPort, p.dst, p.dstPort)
        val flags = p.tcpFlags

        if ((flags and IpPacket.TCP_SYN) != 0 && (flags and IpPacket.TCP_ACK) == 0) {
            // New TCP connection request
            if (tcpSessions.size >= maxTcpSessions) {
                // Drop or reset when overloaded
                IpPacket.buildTcpRst(p)?.let(writer)
                return
            }
            val session = TcpSession(
                key = key,
                clientIp = p.src,
                clientPort = p.srcPort,
                serverIp = p.dst,
                serverPort = p.dstPort,
                clientInitSeq = p.tcpSeq,
                ipVersion = p.ipVersion,
                fragmentSize = fragmentSize,
                writer = writer,
                protector = protector,
                onClosed = { tcpSessions.remove(key) }
            )
            tcpSessions[key] = session
            executor.execute { session.start() }
            return
        }

        val session = tcpSessions[key]
        if (session == null) {
            if ((flags and IpPacket.TCP_RST) == 0) {
                IpPacket.buildTcpRst(p)?.let(writer)
            }
            return
        }

        if ((flags and IpPacket.TCP_RST) != 0) {
            session.close()
            return
        }

        if ((flags and IpPacket.TCP_FIN) != 0) {
            session.onClientFin(p.tcpSeq)
            return
        }

        if (p.payloadLength > 0) {
            val payload = buf.copyOfRange(p.payloadOffset, p.payloadOffset + p.payloadLength)
            session.onClientData(p.tcpSeq, payload)
        } else if ((flags and IpPacket.TCP_ACK) != 0) {
            session.onClientAck(p.tcpAck)
        }
    }

    @Suppress("UNUSED_PARAMETER")
    fun handleUdpPacket(p: ParsedPacket, buf: ByteArray, len: Int) {
        if (!running.get()) return
        val key = sessionKey(p.src, p.srcPort, p.dst, p.dstPort)
        var session = udpSessions[key]
        if (session == null) {
            if (udpSessions.size >= maxUdpSessions) return
            session = UdpSession(
                key = key,
                clientIp = p.src,
                clientPort = p.srcPort,
                serverIp = p.dst,
                serverPort = p.dstPort,
                writer = writer,
                protector = protector,
                onClosed = { udpSessions.remove(key) }
            )
            udpSessions[key] = session
            executor.execute { session.start() }
        }

        if (p.payloadLength > 0) {
            val payload = buf.copyOfRange(p.payloadOffset, p.payloadOffset + p.payloadLength)
            session.send(payload)
        }
    }

    fun shutdown() {
        running.set(false)
        for ((_, session) in tcpSessions) {
            session.close()
        }
        tcpSessions.clear()
        for ((_, session) in udpSessions) {
            session.close()
        }
        udpSessions.clear()
        executor.shutdownNow()
    }

    // ---------------------------------------------------------------- TcpSession
    private class TcpSession(
        val key: Long,
        val clientIp: ByteArray,
        val clientPort: Int,
        val serverIp: ByteArray,
        val serverPort: Int,
        val clientInitSeq: Long,
        val ipVersion: Int,
        val fragmentSize: Int,
        val writer: (ByteArray) -> Unit,
        val protector: SocketProtector,
        val onClosed: () -> Unit,
    ) {
        private val closed = AtomicBoolean(false)
        private var channel: SocketChannel? = null
        private val ourSeq = AtomicLong((System.nanoTime() and 0x7FFFFFFFL) + 1000L)
        private val expectedClientSeq = AtomicLong((clientInitSeq + 1L) and 0xFFFFFFFFL)
        private val isTlsFragmented = AtomicBoolean(false)
        @Volatile var lastActivity = System.currentTimeMillis()

        fun start() {
            try {
                val sc = SocketChannel.open()
                channel = sc
                sc.configureBlocking(true)
                sc.socket().soTimeout = 30000
                runCatching { sc.setOption(StandardSocketOptions.TCP_NODELAY, true) }
                protector.protect(sc.socket())

                val serverAddr = InetAddress.getByAddress(serverIp)
                sc.connect(InetSocketAddress(serverAddr, serverPort))

                // Connection successful: send SYN-ACK back to client
                val synAck = IpPacket.buildTcp(
                    src = serverIp,
                    dst = clientIp,
                    srcPort = serverPort,
                    dstPort = clientPort,
                    seq = ourSeq.get(),
                    ack = expectedClientSeq.get(),
                    flags = IpPacket.TCP_SYN or IpPacket.TCP_ACK,
                    windowSize = 65535,
                    mss = 1400,
                )
                ourSeq.incrementAndGet() // SYN consumes 1 sequence number
                writer(synAck)

                // Loop reading from server channel
                val buf = ByteBuffer.allocate(16384)
                while (!closed.get()) {
                    buf.clear()
                    val read = sc.read(buf)
                    if (read < 0) break // Server closed connection
                    if (read > 0) {
                        lastActivity = System.currentTimeMillis()
                        val data = ByteArray(read)
                        buf.flip()
                        buf.get(data)
                        val pkt = IpPacket.buildTcp(
                            src = serverIp,
                            dst = clientIp,
                            srcPort = serverPort,
                            dstPort = clientPort,
                            seq = ourSeq.get(),
                            ack = expectedClientSeq.get(),
                            flags = IpPacket.TCP_ACK or 0x08, // PSH | ACK
                            payload = data,
                            windowSize = 65535,
                        )
                        ourSeq.addAndGet(read.toLong())
                        writer(pkt)
                    }
                }
                // Send FIN-ACK to client
                sendFin()
            } catch (_: Exception) {
                // Connection or read error: send RST to client
                sendRst()
            } finally {
                close()
            }
        }

        fun onClientData(seq: Long, payload: ByteArray) {
            if (closed.get()) return
            lastActivity = System.currentTimeMillis()
            expectedClientSeq.set((seq + payload.size) and 0xFFFFFFFFL)

            // Immediately ACK the client data
            val ackPkt = IpPacket.buildTcp(
                src = serverIp,
                dst = clientIp,
                srcPort = serverPort,
                dstPort = clientPort,
                seq = ourSeq.get(),
                ack = expectedClientSeq.get(),
                flags = IpPacket.TCP_ACK,
                windowSize = 65535,
            )
            writer(ackPkt)

            // Forward to real server (with DPI fragmentation if TLS ClientHello)
            val sc = channel ?: return
            try {
                if (!isTlsFragmented.get() && isTlsClientHello(payload)) {
                    isTlsFragmented.set(true)
                    // Fragment TLS ClientHello across 2 writes
                    val split = fragmentSize.coerceIn(1, minOf(5, payload.size - 1))
                    val part1 = ByteBuffer.wrap(payload, 0, split)
                    val part2 = ByteBuffer.wrap(payload, split, payload.size - split)
                    sc.write(part1)
                    Thread.sleep(1) // Minor pause forces distinct TCP segment at the IP level
                    sc.write(part2)
                } else {
                    val bb = ByteBuffer.wrap(payload)
                    while (bb.hasRemaining()) {
                        sc.write(bb)
                    }
                }
            } catch (_: Exception) {
                close()
            }
        }

        @Suppress("UNUSED_PARAMETER")
        fun onClientAck(ack: Long) {
            lastActivity = System.currentTimeMillis()
        }

        fun onClientFin(seq: Long) {
            expectedClientSeq.set((seq + 1L) and 0xFFFFFFFFL)
            sendFin()
            close()
        }

        private fun sendFin() {
            if (closed.get()) return
            val finPkt = IpPacket.buildTcp(
                src = serverIp,
                dst = clientIp,
                srcPort = serverPort,
                dstPort = clientPort,
                seq = ourSeq.get(),
                ack = expectedClientSeq.get(),
                flags = IpPacket.TCP_FIN or IpPacket.TCP_ACK,
                windowSize = 65535,
            )
            ourSeq.incrementAndGet()
            writer(finPkt)
        }

        private fun sendRst() {
            if (closed.get()) return
            val rstPkt = IpPacket.buildTcp(
                src = serverIp,
                dst = clientIp,
                srcPort = serverPort,
                dstPort = clientPort,
                seq = ourSeq.get(),
                ack = expectedClientSeq.get(),
                flags = IpPacket.TCP_RST or IpPacket.TCP_ACK,
                windowSize = 0,
            )
            writer(rstPkt)
        }

        fun close() {
            if (closed.compareAndSet(false, true)) {
                runCatching { channel?.close() }
                onClosed()
            }
        }
    }

    // ---------------------------------------------------------------- UdpSession
    private class UdpSession(
        val key: Long,
        val clientIp: ByteArray,
        val clientPort: Int,
        val serverIp: ByteArray,
        val serverPort: Int,
        val writer: (ByteArray) -> Unit,
        val protector: SocketProtector,
        val onClosed: () -> Unit,
    ) {
        private val closed = AtomicBoolean(false)
        private var socket: DatagramSocket? = null
        @Volatile var lastActivity = System.currentTimeMillis()

        fun start() {
            try {
                val ds = DatagramSocket()
                socket = ds
                ds.soTimeout = 30000
                protector.protect(ds)
                val serverAddr = InetAddress.getByAddress(serverIp)
                ds.connect(serverAddr, serverPort)

                val buf = ByteArray(2048)
                val packet = DatagramPacket(buf, buf.size)
                while (!closed.get()) {
                    try {
                        ds.receive(packet)
                        lastActivity = System.currentTimeMillis()
                        val reply = IpPacket.buildUdp(
                            src = serverIp,
                            dst = clientIp,
                            srcPort = serverPort,
                            dstPort = clientPort,
                            payload = packet.data,
                            payloadOff = packet.offset,
                            payloadLen = packet.length,
                        )
                        writer(reply)
                    } catch (_: Exception) {
                        break
                    }
                }
            } catch (_: Exception) {
            } finally {
                close()
            }
        }

        fun send(payload: ByteArray) {
            val ds = socket ?: return
            if (closed.get()) return
            lastActivity = System.currentTimeMillis()
            try {
                val dp = DatagramPacket(payload, payload.size)
                ds.send(dp)
            } catch (_: Exception) {
                close()
            }
        }

        fun close() {
            if (closed.compareAndSet(false, true)) {
                runCatching { socket?.close() }
                onClosed()
            }
        }
    }
}
