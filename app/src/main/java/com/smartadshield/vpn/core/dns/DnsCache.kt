package com.smartadshield.vpn.core.dns

/**
 * Small LRU cache of upstream DNS responses that honours record TTLs.
 *
 * - Only NOERROR / NXDOMAIN, non-truncated responses are stored.
 * - TTLs are aged on read so clients never see stale lifetimes.
 * - The cache is flushed whenever the underlying network changes, because CDN answers
 *   depend on the network (keeps geo-routing identical to not using the app).
 */
class DnsCache(
    private val maxEntries: Int = 2048,
    private val maxPositiveTtl: Long = 3600,
    private val maxNegativeTtl: Long = 300,
    private val clock: () -> Long = System::currentTimeMillis,
) {
    private class Entry(val data: ByteArray, val storedAt: Long, val ttlSec: Long)

    private val map = object : LinkedHashMap<String, Entry>(256, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, Entry>?) = size > maxEntries
    }

    @Synchronized
    fun get(key: String, requestId: Int): ByteArray? {
        val e = map[key] ?: return null
        val elapsedMs = clock() - e.storedAt
        if (elapsedMs >= e.ttlSec * 1000) {
            map.remove(key)
            return null
        }
        val aged = DnsMessage.withAgedTtls(e.data, elapsedMs / 1000) ?: return null
        DnsMessage.setId(aged, requestId)
        return aged
    }

    @Synchronized
    fun put(key: String, response: ByteArray) {
        if (DnsMessage.isTruncated(response)) return
        val rcode = DnsMessage.rcode(response)
        if (rcode != DnsMessage.RCODE_NOERROR && rcode != DnsMessage.RCODE_NXDOMAIN) return
        val ttl = DnsMessage.minTtl(response)
        if (ttl <= 0) return
        val capped = if (rcode == DnsMessage.RCODE_NOERROR) ttl.coerceAtMost(maxPositiveTtl) else ttl.coerceAtMost(maxNegativeTtl)
        map[key] = Entry(response.copyOf(), clock(), capped)
    }

    @Synchronized
    fun clear() = map.clear()

    @Synchronized
    fun size() = map.size
}
