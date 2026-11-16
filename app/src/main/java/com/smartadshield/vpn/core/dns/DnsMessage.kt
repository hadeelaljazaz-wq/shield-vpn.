package com.smartadshield.vpn.core.dns

/** A single-question DNS query as received from the system resolver. */
class DnsQuery(
    val id: Int,
    val flags: Int,
    val name: String,
    val qtype: Int,
    val qclass: Int,
    /** Offset (relative to message start) where the question section ends. */
    val questionEnd: Int,
) {
    val cacheKey: String get() = "$name|$qtype|$qclass"
}

enum class BlockStyle { NULL_IP, NXDOMAIN }

object DnsMessage {
    const val TYPE_A = 1
    const val TYPE_AAAA = 28
    const val TYPE_OPT = 41
    const val TYPE_SOA = 6
    const val RCODE_NOERROR = 0
    const val RCODE_SERVFAIL = 2
    const val RCODE_NXDOMAIN = 3

    private fun u8(b: ByteArray, o: Int) = b[o].toInt() and 0xFF
    private fun u16(b: ByteArray, o: Int) = (u8(b, o) shl 8) or u8(b, o + 1)
    private fun put16(b: ByteArray, o: Int, v: Int) {
        b[o] = (v ushr 8).toByte(); b[o + 1] = v.toByte()
    }

    fun typeName(t: Int): String = when (t) {
        1 -> "A"; 2 -> "NS"; 5 -> "CNAME"; 6 -> "SOA"; 12 -> "PTR"; 15 -> "MX"; 16 -> "TXT"
        28 -> "AAAA"; 33 -> "SRV"; 64 -> "SVCB"; 65 -> "HTTPS"; else -> "TYPE$t"
    }

    /** Parses a standard query with exactly one question; returns null otherwise. */
    fun parseQuery(buf: ByteArray, off: Int, len: Int): DnsQuery? {
        if (len < 12) return null
        val flags = u16(buf, off + 2)
        if ((flags and 0x8000) != 0) return null // QR=1 → not a query
        if (((flags ushr 11) and 0xF) != 0) return null // only OPCODE QUERY
        if (u16(buf, off + 4) != 1) return null
        val sb = StringBuilder(64)
        var pos = off + 12
        val end = off + len
        while (true) {
            if (pos >= end) return null
            val l = u8(buf, pos)
            if (l == 0) { pos++; break }
            if (l and 0xC0 != 0) return null // no compression expected inside a question
            if (pos + 1 + l > end) return null
            if (sb.isNotEmpty()) sb.append('.')
            for (i in pos + 1..pos + l) {
                var c = (buf[i].toInt() and 0xFF).toChar()
                if (c in 'A'..'Z') c += 32
                sb.append(c)
            }
            if (sb.length > 253) return null
            pos += 1 + l
        }
        if (pos + 4 > end) return null
        return DnsQuery(u16(buf, off), flags, sb.toString(), u16(buf, pos), u16(buf, pos + 2), pos + 4 - off)
    }

    /** Builds a local answer for a blocked domain. */
    fun buildBlockedResponse(query: ByteArray, off: Int, q: DnsQuery, style: BlockStyle, ttl: Int): ByteArray {
        val rdLen = when {
            style == BlockStyle.NXDOMAIN -> -1
            q.qtype == TYPE_A -> 4
            q.qtype == TYPE_AAAA -> 16
            else -> -1 // NODATA for HTTPS/SVCB/etc. so no address hints leak through
        }
        val rcode = if (style == BlockStyle.NXDOMAIN) RCODE_NXDOMAIN else RCODE_NOERROR
        val answerLen = if (rdLen >= 0) 12 + rdLen else 0
        val out = ByteArray(q.questionEnd + answerLen)
        System.arraycopy(query, off, out, 0, q.questionEnd)
        writeResponseHeader(out, q, rcode, if (rdLen >= 0) 1 else 0)
        if (rdLen >= 0) {
            var p = q.questionEnd
            put16(out, p, 0xC00C); p += 2
            put16(out, p, q.qtype); p += 2
            put16(out, p, q.qclass); p += 2
            out[p] = (ttl ushr 24).toByte(); out[p + 1] = (ttl ushr 16).toByte()
            out[p + 2] = (ttl ushr 8).toByte(); out[p + 3] = ttl.toByte(); p += 4
            put16(out, p, rdLen) // rdata stays all-zero: 0.0.0.0 / ::
        }
        return out
    }

    fun buildErrorResponse(query: ByteArray, off: Int, q: DnsQuery, rcode: Int): ByteArray {
        val out = ByteArray(q.questionEnd)
        System.arraycopy(query, off, out, 0, q.questionEnd)
        writeResponseHeader(out, q, rcode, 0)
        return out
    }

    private fun writeResponseHeader(out: ByteArray, q: DnsQuery, rcode: Int, ancount: Int) {
        put16(out, 0, q.id)
        // QR=1, keep RD (and CD), set RA.
        val flags = 0x8000 or (q.flags and 0x0110) or 0x0080 or (rcode and 0xF)
        put16(out, 2, flags)
        put16(out, 4, 1)
        put16(out, 6, ancount)
        put16(out, 8, 0)
        put16(out, 10, 0)
    }

    fun id(msg: ByteArray): Int = u16(msg, 0)
    fun setId(msg: ByteArray, id: Int) = put16(msg, 0, id)
    fun rcode(msg: ByteArray): Int = u8(msg, 3) and 0xF
    fun isTruncated(msg: ByteArray): Boolean = (u8(msg, 2) and 0x02) != 0
    fun isResponse(msg: ByteArray): Boolean = (u8(msg, 2) and 0x80) != 0

    private fun skipName(b: ByteArray, len: Int, start: Int): Int {
        var pos = start
        while (true) {
            if (pos >= len) return -1
            val l = u8(b, pos)
            when {
                l == 0 -> return pos + 1
                l and 0xC0 == 0xC0 -> return if (pos + 2 <= len) pos + 2 else -1
                l and 0xC0 != 0 -> return -1
                else -> pos += 1 + l
            }
        }
    }

    /**
     * Walks all resource records and calls [visit] with (section, ttlOffset, type).
     * Section: 0 answer, 1 authority, 2 additional. Returns false if malformed.
     */
    private inline fun walkRecords(b: ByteArray, len: Int, visit: (Int, Int, Int) -> Unit): Boolean {
        if (len < 12) return false
        val qd = u16(b, 4)
        val counts = intArrayOf(u16(b, 6), u16(b, 8), u16(b, 10))
        var pos = 12
        repeat(qd) {
            pos = skipName(b, len, pos)
            if (pos < 0 || pos + 4 > len) return false
            pos += 4
        }
        for (section in 0..2) {
            repeat(counts[section]) {
                pos = skipName(b, len, pos)
                if (pos < 0 || pos + 10 > len) return false
                val type = u16(b, pos)
                val rdLen = u16(b, pos + 8)
                visit(section, pos + 4, type)
                pos += 10 + rdLen
                if (pos > len) return false
            }
        }
        return true
    }

    private fun readTtl(b: ByteArray, o: Int): Long =
        (u8(b, o).toLong() shl 24) or (u8(b, o + 1).toLong() shl 16) or
            (u8(b, o + 2).toLong() shl 8) or u8(b, o + 3).toLong()

    /**
     * Minimum TTL over answer + authority records (OPT excluded).
     * Returns -1 when the message is malformed or has nothing cacheable.
     */
    fun minTtl(msg: ByteArray, len: Int = msg.size): Long {
        var min = Long.MAX_VALUE
        val ok = walkRecords(msg, len) { section, ttlOff, type ->
            if (section < 2 && type != TYPE_OPT) {
                val t = readTtl(msg, ttlOff)
                if (t < min) min = t
            }
        }
        return if (!ok || min == Long.MAX_VALUE) -1 else min
    }

    /** Returns a copy whose TTLs are reduced by [elapsedSec] (never below 1). */
    fun withAgedTtls(msg: ByteArray, elapsedSec: Long): ByteArray? {
        val out = msg.copyOf()
        val ok = walkRecords(out, out.size) { _, ttlOff, type ->
            if (type != TYPE_OPT) {
                val t = (readTtl(out, ttlOff) - elapsedSec).coerceAtLeast(1)
                out[ttlOff] = (t ushr 24).toByte(); out[ttlOff + 1] = (t ushr 16).toByte()
                out[ttlOff + 2] = (t ushr 8).toByte(); out[ttlOff + 3] = t.toByte()
            }
        }
        return if (ok) out else null
    }

    /** Builds a minimal query packet (used by tests and diagnostics). */
    fun buildQuery(id: Int, name: String, qtype: Int): ByteArray {
        val labels = name.trimEnd('.').split('.')
        val qLen = labels.sumOf { it.length + 1 } + 1
        val out = ByteArray(12 + qLen + 4)
        put16(out, 0, id)
        put16(out, 2, 0x0100)
        put16(out, 4, 1)
        var p = 12
        for (l in labels) {
            out[p++] = l.length.toByte()
            for (c in l) out[p++] = c.code.toByte()
        }
        out[p++] = 0
        put16(out, p, qtype)
        put16(out, p + 2, 1)
        return out
    }
}
