package com.smartadshield.vpn.core.dns

import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException

/**
 * Prepares every outgoing socket so that it can never loop back into the tunnel:
 * on Android this calls VpnService.protect() and binds the socket to the physical network.
 */
interface SocketProtector {
    fun protect(socket: DatagramSocket): Boolean
    fun protect(socket: Socket): Boolean

    object None : SocketProtector {
        override fun protect(socket: DatagramSocket) = true
        override fun protect(socket: Socket) = true
    }
}

class UpstreamResult(val response: ByteArray?, val server: InetAddress?, val latencyMs: Long, val error: String?, val viaTcp: Boolean)

/**
 * Forwards raw DNS queries to the *network's own* resolvers (the same ones Android would use
 * without this app), so CDN geo-steering and regional results stay exactly the same.
 * Falls back to TCP when an answer is truncated.
 */
class UpstreamResolver(
    private val protector: SocketProtector,
    private val timeoutMs: Int = 2500,
) {
    @Volatile
    var servers: List<InetAddress> = emptyList()

    fun resolve(query: ByteArray, len: Int, explicitServer: InetAddress? = null): UpstreamResult {
        val targets = if (explicitServer != null) listOf(explicitServer) else servers.take(3)
        if (targets.isEmpty()) return UpstreamResult(null, null, 0, "لا توجد خوادم DNS للشبكة الحالية", false)
        val queryId = DnsMessage.id(query)
        var lastError: String? = null
        val started = System.nanoTime()
        for (server in targets) {
            try {
                val udp = queryUdp(server, query, len, queryId)
                if (udp != null) {
                    if (DnsMessage.isTruncated(udp)) {
                        val tcp = runCatching { queryTcp(server, query, len, queryId) }.getOrNull()
                        if (tcp != null) return UpstreamResult(tcp, server, ms(started), null, true)
                    }
                    return UpstreamResult(udp, server, ms(started), null, false)
                }
                lastError = "انتهت المهلة: ${server.hostAddress}"
            } catch (e: Exception) {
                lastError = "${server.hostAddress}: ${e.javaClass.simpleName} ${e.message ?: ""}".trim()
            }
        }
        return UpstreamResult(null, null, ms(started), lastError, false)
    }

    private fun ms(startNs: Long) = (System.nanoTime() - startNs) / 1_000_000

    private fun queryUdp(server: InetAddress, query: ByteArray, len: Int, id: Int): ByteArray? {
        DatagramSocket(null as java.net.SocketAddress?).use { s ->
            if (!protector.protect(s)) throw IllegalStateException("protect() failed")
            s.bind(null)
            s.soTimeout = timeoutMs
            s.connect(InetSocketAddress(server, 53))
            s.send(DatagramPacket(query, 0, len))
            val buf = ByteArray(16384)
            val deadline = System.currentTimeMillis() + timeoutMs
            while (true) {
                val p = DatagramPacket(buf, buf.size)
                try {
                    s.receive(p)
                } catch (_: SocketTimeoutException) {
                    return null
                }
                // Ignore spoofed/stale datagrams whose ID does not match.
                if (p.length >= 12 && DnsMessage.id(buf) == id && DnsMessage.isResponse(buf)) {
                    return buf.copyOf(p.length)
                }
                val left = deadline - System.currentTimeMillis()
                if (left <= 0) return null
                s.soTimeout = left.toInt()
            }
        }
    }

    private fun queryTcp(server: InetAddress, query: ByteArray, len: Int, id: Int): ByteArray? {
        Socket().use { s ->
            if (!protector.protect(s)) throw IllegalStateException("protect() failed")
            s.soTimeout = timeoutMs
            s.connect(InetSocketAddress(server, 53), timeoutMs)
            val out = DataOutputStream(s.getOutputStream())
            out.writeShort(len)
            out.write(query, 0, len)
            out.flush()
            val input = DataInputStream(s.getInputStream())
            val rlen = input.readUnsignedShort()
            val resp = ByteArray(rlen)
            input.readFully(resp)
            return if (rlen >= 12 && DnsMessage.id(resp) == id) resp else null
        }
    }
}
