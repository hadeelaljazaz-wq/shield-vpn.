package com.smartadshield.vpn.tunnel

import java.net.InetSocketAddress
import java.net.Proxy
import java.net.Socket
import java.net.URL
import javax.net.ssl.HttpsURLConnection

/**
 * Real measurements only: exit IP / country (Cloudflare trace, addressed by IP
 * so no DNS is needed), TCP round-trip time and download throughput.
 * When [proxy] is set (Xray mode) requests go through Xray's loopback SOCKS
 * inbound, i.e. through the tunnel.
 */
class NetProbe(private val proxy: Proxy? = null) {

    data class Exit(val ip: String, val country: String?, val colo: String?, val ms: Long)

    private val traceUrls = listOf(
        "https://1.1.1.1/cdn-cgi/trace",
        "https://1.0.0.1/cdn-cgi/trace",
    )

    fun exitInfo(timeoutMs: Int = 8000): Result<Exit> {
        var last: Throwable? = null
        for (u in traceUrls) {
            try {
                val t0 = System.nanoTime()
                val c = (if (proxy != null) URL(u).openConnection(proxy) else URL(u).openConnection()) as HttpsURLConnection
                c.connectTimeout = timeoutMs
                c.readTimeout = timeoutMs
                c.useCaches = false
                val body = c.inputStream.bufferedReader().use { it.readText() }
                c.disconnect()
                val kv = body.lines().mapNotNull { l -> l.split('=', limit = 2).takeIf { it.size == 2 }?.let { it[0] to it[1] } }.toMap()
                val ip = kv["ip"] ?: error("no ip in trace")
                return Result.success(Exit(ip, kv["loc"], kv["colo"], (System.nanoTime() - t0) / 1_000_000))
            } catch (t: Throwable) {
                last = t
            }
        }
        return Result.failure(last ?: IllegalStateException("trace failed"))
    }

    /** TCP connect time = one round trip on the measured path. */
    fun tcpRttMs(host: String = "1.1.1.1", port: Int = 443, timeoutMs: Int = 4000): Long? = runCatching {
        val s = if (proxy != null) Socket(proxy) else Socket()
        s.use {
            val t0 = System.nanoTime()
            it.connect(InetSocketAddress(host, port), timeoutMs)
            (System.nanoTime() - t0) / 1_000_000
        }
    }.getOrNull()

    /** Downloads [bytes] from Cloudflare's speed endpoint; returns Mbit/s. */
    fun downloadMbps(bytes: Int = 10_000_000, timeoutMs: Int = 30000): Result<Double> = runCatching {
        val url = URL("https://speed.cloudflare.com/__down?bytes=$bytes")
        val c = (if (proxy != null) url.openConnection(proxy) else url.openConnection()) as HttpsURLConnection
        c.connectTimeout = 8000
        c.readTimeout = timeoutMs
        c.useCaches = false
        val buf = ByteArray(64 * 1024)
        var total = 0L
        val input = c.inputStream
        val t0 = System.nanoTime()
        input.use {
            while (true) {
                val n = it.read(buf)
                if (n < 0) break
                total += n
            }
        }
        val sec = (System.nanoTime() - t0) / 1e9
        c.disconnect()
        require(total > 0) { "no data" }
        total * 8 / 1e6 / sec
    }

    companion object {
        fun socks(port: Int) = NetProbe(Proxy(Proxy.Type.SOCKS, InetSocketAddress("127.0.0.1", port)))
    }
}
