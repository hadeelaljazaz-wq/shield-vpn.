package com.smartadshield.vpn.core.net

/**
 * Minimal, allocation-conscious IPv4/IPv6 + UDP/TCP parser and builder.
 *
 * The tunnel only ever receives packets addressed to the virtual DNS server (and, optionally,
 * to well-known public DNS resolvers), so we only need: UDP datagrams (DNS) and TCP segments
 * (which we answer with RST so clients fall back quickly instead of hanging).
 */
class ParsedPacket(
    val ipVersion: Int,
    val protocol: Int,
    val src: ByteArray,
    val dst: ByteArray,
    val srcPort: Int,
    val dstPort: Int,
    val payloadOffset: Int,
    val payloadLength: Int,
    val tcpSeq: Long = 0,
    val tcpAck: Long = 0,
    val tcpFlags: Int = 0,
)

object IpPacket {
    const val PROTO_ICMP = 1
    const val PROTO_TCP = 6
    const val PROTO_UDP = 17
    const val PROTO_ICMPV6 = 58

    const val TCP_FIN = 0x01
    const val TCP_SYN = 0x02
    const val TCP_RST = 0x04
    const val TCP_ACK = 0x10

    private fun u8(b: ByteArray, o: Int) = b[o].toInt() and 0xFF
    private fun u16(b: ByteArray, o: Int) = (u8(b, o) shl 8) or u8(b, o + 1)
    private fun u32(b: ByteArray, o: Int): Long =
        (u8(b, o).toLong() shl 24) or (u8(b, o + 1).toLong() shl 16) or
            (u8(b, o + 2).toLong() shl 8) or u8(b, o + 3).toLong()

    private fun put16(b: ByteArray, o: Int, v: Int) {
        b[o] = (v ushr 8).toByte(); b[o + 1] = v.toByte()
    }

    private fun put32(b: ByteArray, o: Int, v: Long) {
        b[o] = (v ushr 24).toByte(); b[o + 1] = (v ushr 16).toByte()
        b[o + 2] = (v ushr 8).toByte(); b[o + 3] = v.toByte()
    }

    /** Returns null for anything malformed, fragmented or using IPv6 extension headers. */
    fun parse(buf: ByteArray, len: Int): ParsedPacket? {
        if (len < 20) return null
        val version = (buf[0].toInt() ushr 4) and 0xF
        val src: ByteArray
        val dst: ByteArray
        val proto: Int
        val l4Off: Int
        val l4End: Int
        when (version) {
            4 -> {
                val ihl = (buf[0].toInt() and 0xF) * 4
                if (ihl < 20 || ihl > len) return null
                val total = u16(buf, 2)
                if (total < ihl || total > len) return null
                // Drop fragments (MF flag or non-zero offset); DNS queries are never fragmented.
                if ((u16(buf, 6) and 0x3FFF) != 0) return null
                proto = u8(buf, 9)
                src = buf.copyOfRange(12, 16)
                dst = buf.copyOfRange(16, 20)
                l4Off = ihl
                l4End = total
            }
            6 -> {
                if (len < 40) return null
                val payloadLen = u16(buf, 4)
                proto = u8(buf, 6)
                src = buf.copyOfRange(8, 24)
                dst = buf.copyOfRange(24, 40)
                l4Off = 40
                l4End = 40 + payloadLen
                if (l4End > len) return null
            }
            else -> return null
        }
        return when (proto) {
            PROTO_UDP -> {
                if (l4End - l4Off < 8) return null
                val udpLen = u16(buf, l4Off + 4)
                if (udpLen < 8 || l4Off + udpLen > l4End) return null
                ParsedPacket(
                    version, proto, src, dst, u16(buf, l4Off), u16(buf, l4Off + 2),
                    l4Off + 8, udpLen - 8,
                )
            }
            PROTO_TCP -> {
                if (l4End - l4Off < 20) return null
                val dataOff = (u8(buf, l4Off + 12) ushr 4) * 4
                if (dataOff < 20 || l4Off + dataOff > l4End) return null
                ParsedPacket(
                    version, proto, src, dst, u16(buf, l4Off), u16(buf, l4Off + 2),
                    l4Off + dataOff, l4End - l4Off - dataOff,
                    tcpSeq = u32(buf, l4Off + 4), tcpAck = u32(buf, l4Off + 8),
                    tcpFlags = u8(buf, l4Off + 13),
                )
            }
            else -> ParsedPacket(version, proto, src, dst, 0, 0, l4Off, l4End - l4Off)
        }
    }

    // ---------------------------------------------------------------- checksums

    private fun sum(buf: ByteArray, off: Int, len: Int, initial: Long): Long {
        var s = initial
        var i = off
        val end = off + len
        while (i + 1 < end) {
            s += ((buf[i].toInt() and 0xFF) shl 8) or (buf[i + 1].toInt() and 0xFF)
            i += 2
        }
        if (i < end) s += (buf[i].toInt() and 0xFF) shl 8
        return s
    }

    private fun fold(s0: Long): Int {
        var s = s0
        while ((s ushr 16) != 0L) s = (s and 0xFFFF) + (s ushr 16)
        return (s.inv() and 0xFFFF).toInt()
    }

    /** Public for tests: verifies a full IP packet's IP (v4) and L4 checksums. */
    fun verifyChecksums(pkt: ByteArray): Boolean {
        val version = (pkt[0].toInt() ushr 4) and 0xF
        return if (version == 4) {
            val ihl = (pkt[0].toInt() and 0xF) * 4
            if (fold(sum(pkt, 0, ihl, 0)) != 0) return false
            val proto = u8(pkt, 9)
            val l4Len = u16(pkt, 2) - ihl
            val pseudo = sum(pkt, 12, 8, 0) + proto + l4Len
            fold(sum(pkt, ihl, l4Len, pseudo)) == 0
        } else {
            val proto = u8(pkt, 6)
            val l4Len = u16(pkt, 4)
            val pseudo = sum(pkt, 8, 32, 0) + proto + l4Len
            fold(sum(pkt, 40, l4Len, pseudo)) == 0
        }
    }

    // ---------------------------------------------------------------- builders

    private fun wrap(src: ByteArray, dst: ByteArray, proto: Int, l4: ByteArray, csumOffset: Int): ByteArray {
        val v6 = src.size == 16
        val hdr = if (v6) 40 else 20
        val out = ByteArray(hdr + l4.size)
        if (v6) {
            out[0] = 0x60
            put16(out, 4, l4.size)
            out[6] = proto.toByte()
            out[7] = 64
            System.arraycopy(src, 0, out, 8, 16)
            System.arraycopy(dst, 0, out, 24, 16)
        } else {
            out[0] = 0x45
            put16(out, 2, out.size)
            put16(out, 6, 0x4000) // DF
            out[8] = 64
            out[9] = proto.toByte()
            System.arraycopy(src, 0, out, 12, 4)
            System.arraycopy(dst, 0, out, 16, 4)
            put16(out, 10, fold(sum(out, 0, 20, 0)))
        }
        System.arraycopy(l4, 0, out, hdr, l4.size)
        val pseudo = if (v6) sum(out, 8, 32, 0) + proto + l4.size else sum(out, 12, 8, 0) + proto + l4.size
        var c = fold(sum(out, hdr, l4.size, pseudo))
        if (c == 0 && proto == PROTO_UDP) c = 0xFFFF
        put16(out, hdr + csumOffset, c)
        return out
    }

    fun buildUdp(
        src: ByteArray, dst: ByteArray, srcPort: Int, dstPort: Int,
        payload: ByteArray, payloadOff: Int = 0, payloadLen: Int = payload.size,
    ): ByteArray {
        val l4 = ByteArray(8 + payloadLen)
        put16(l4, 0, srcPort)
        put16(l4, 2, dstPort)
        put16(l4, 4, l4.size)
        System.arraycopy(payload, payloadOff, l4, 8, payloadLen)
        return wrap(src, dst, PROTO_UDP, l4, 6)
    }

    /** Builds a reply UDP packet for [req] (addresses/ports swapped). */
    fun buildUdpReply(req: ParsedPacket, payload: ByteArray, len: Int = payload.size): ByteArray =
        buildUdp(req.dst, req.src, req.dstPort, req.srcPort, payload, 0, len)

    /**
     * Builds a TCP packet with the given addresses, ports, sequence/acknowledgement numbers,
     * flags, optional payload, and optional MSS option (useful for SYN-ACK replies).
     */
    fun buildTcp(
        src: ByteArray, dst: ByteArray, srcPort: Int, dstPort: Int,
        seq: Long, ack: Long, flags: Int,
        payload: ByteArray = ByteArray(0), payloadOff: Int = 0, payloadLen: Int = payload.size,
        windowSize: Int = 65535,
        mss: Int? = null,
    ): ByteArray {
        val optLen = if (mss != null) 4 else 0
        val l4Len = 20 + optLen + payloadLen
        val l4 = ByteArray(l4Len)
        put16(l4, 0, srcPort)
        put16(l4, 2, dstPort)
        put32(l4, 4, seq and 0xFFFFFFFFL)
        put32(l4, 8, ack and 0xFFFFFFFFL)
        val dataOffsetWords = (20 + optLen) / 4
        l4[12] = (dataOffsetWords shl 4).toByte()
        l4[13] = (flags and 0xFF).toByte()
        put16(l4, 14, windowSize and 0xFFFF)
        // Checksum at offset 16, urgent pointer at offset 18 (0)
        if (mss != null) {
            l4[20] = 0x02 // MSS option kind
            l4[21] = 0x04 // MSS option length
            put16(l4, 22, mss and 0xFFFF)
        }
        if (payloadLen > 0) {
            System.arraycopy(payload, payloadOff, l4, 20 + optLen, payloadLen)
        }
        return wrap(src, dst, PROTO_TCP, l4, 16)
    }

    /**
     * RFC 793 reset generation for a segment that reached a closed port. Returns null when the
     * incoming segment is itself a RST (never answer a RST).
     */
    fun buildTcpRst(req: ParsedPacket): ByteArray? {
        if (req.protocol != PROTO_TCP || (req.tcpFlags and TCP_RST) != 0) return null
        val l4 = ByteArray(20)
        put16(l4, 0, req.dstPort)
        put16(l4, 2, req.srcPort)
        if ((req.tcpFlags and TCP_ACK) != 0) {
            put32(l4, 4, req.tcpAck)
            l4[13] = TCP_RST.toByte()
        } else {
            var segLen = req.payloadLength.toLong()
            if ((req.tcpFlags and TCP_SYN) != 0) segLen++
            if ((req.tcpFlags and TCP_FIN) != 0) segLen++
            put32(l4, 4, 0)
            put32(l4, 8, (req.tcpSeq + segLen) and 0xFFFFFFFFL)
            l4[13] = (TCP_RST or TCP_ACK).toByte()
        }
        l4[12] = (5 shl 4).toByte()
        return wrap(req.dst, req.src, PROTO_TCP, l4, 16)
    }

    /**
     * Builds an ICMP (RFC 792 Type 3 Code 3) or ICMPv6 (RFC 4443 Type 1 Code 4) Port Unreachable
     * message in response to non-DNS datagrams (e.g. QUIC/443) addressed to virtual or intercepted
     * DNS resolvers. This informs clients immediately that the port is closed, preventing hanging.
     */
    fun buildIcmpPortUnreachable(req: ParsedPacket, origBuf: ByteArray, origLen: Int): ByteArray? {
        if (req.ipVersion == 4) {
            val origIhl = (origBuf[0].toInt() and 0xF) * 4
            val icmpPayloadLen = origIhl + 8
            if (origLen < icmpPayloadLen) return null
            val l4 = ByteArray(8 + icmpPayloadLen)
            l4[0] = 3 // Destination Unreachable
            l4[1] = 3 // Port Unreachable
            System.arraycopy(origBuf, 0, l4, 8, icmpPayloadLen)
            val c = fold(sum(l4, 0, l4.size, 0))
            put16(l4, 2, c)

            val out = ByteArray(20 + l4.size)
            out[0] = 0x45
            put16(out, 2, out.size)
            put16(out, 6, 0x4000)
            out[8] = 64
            out[9] = PROTO_ICMP.toByte()
            System.arraycopy(req.dst, 0, out, 12, 4)
            System.arraycopy(req.src, 0, out, 16, 4)
            put16(out, 10, fold(sum(out, 0, 20, 0)))
            System.arraycopy(l4, 0, out, 20, l4.size)
            return out
        } else if (req.ipVersion == 6) {
            val icmpPayloadLen = minOf(origLen, 1232)
            val l4 = ByteArray(8 + icmpPayloadLen)
            l4[0] = 1 // Destination Unreachable
            l4[1] = 4 // Port Unreachable
            System.arraycopy(origBuf, 0, l4, 8, icmpPayloadLen)
            val pseudo = sum(req.dst, 0, 16, 0) + sum(req.src, 0, 16, 0) + PROTO_ICMPV6 + l4.size
            val c = fold(sum(l4, 0, l4.size, pseudo))
            put16(l4, 2, c)

            val out = ByteArray(40 + l4.size)
            out[0] = 0x60
            put16(out, 4, l4.size)
            out[6] = PROTO_ICMPV6.toByte()
            out[7] = 64
            System.arraycopy(req.dst, 0, out, 8, 16)
            System.arraycopy(req.src, 0, out, 24, 16)
            System.arraycopy(l4, 0, out, 40, l4.size)
            return out
        }
        return null
    }
}
