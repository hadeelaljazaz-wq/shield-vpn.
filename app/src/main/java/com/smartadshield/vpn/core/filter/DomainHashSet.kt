package com.smartadshield.vpn.core.filter

import java.io.DataInputStream
import java.io.DataOutputStream

/**
 * Memory-compact domain set: a sorted array of 64-bit hashes (8 bytes per rule instead of
 * ~80+ bytes for a HashSet<String>). 200k rules ≈ 1.6 MB. Lookups are binary searches and
 * hashing a suffix needs no substring allocation.
 *
 * Collision probability with 200k entries is ~1e-9 per lookup, which is acceptable for an
 * ad blocker (and the user allowlist always has the last word).
 */
class DomainHashSet private constructor(private val hashes: LongArray) {

    val size: Int get() = hashes.size

    fun containsHash(h: Long): Boolean = java.util.Arrays.binarySearch(hashes, h) >= 0

    fun contains(domain: String): Boolean = containsHash(hash(domain, 0))

    /**
     * Returns the start index (into [domain]) of the most specific suffix contained in this set,
     * e.g. for "a.ads.example.com" with "ads.example.com" in the set returns 2. -1 if none.
     */
    fun matchSuffix(domain: String): Int {
        if (hashes.isEmpty()) return -1
        var start = 0
        while (start < domain.length) {
            if (containsHash(hash(domain, start))) return start
            val dot = domain.indexOf('.', start)
            if (dot < 0) return -1
            start = dot + 1
        }
        return -1
    }

    fun write(out: DataOutputStream) {
        out.writeInt(hashes.size)
        for (h in hashes) out.writeLong(h)
    }

    class Builder(expected: Int = 1024) {
        private var arr = LongArray(expected.coerceAtLeast(16))
        private var n = 0
        fun add(domain: String) = addHash(hash(domain, 0))
        fun addHash(h: Long) {
            if (n == arr.size) arr = arr.copyOf(arr.size * 2)
            arr[n++] = h
        }
        val count: Int get() = n
        fun build(): DomainHashSet {
            val a = arr.copyOf(n)
            a.sort()
            // de-duplicate in place
            var w = 0
            for (i in a.indices) if (w == 0 || a[w - 1] != a[i]) a[w++] = a[i]
            return DomainHashSet(if (w == a.size) a else a.copyOf(w))
        }
    }

    companion object {
        val EMPTY = DomainHashSet(LongArray(0))

        /** FNV-1a 64 over chars [start, end) followed by the murmur3 fmix64 finalizer. */
        fun hash(s: String, start: Int): Long {
            var h = -0x340d631b7bdddcdbL // 0xcbf29ce484222325
            for (i in start until s.length) {
                h = h xor s[i].code.toLong()
                h *= 0x100000001b3L
            }
            h = h xor (h ushr 33)
            h *= -0xae502812aa7333L
            h = h xor (h ushr 33)
            h *= -0x3b314601e57a13adL
            h = h xor (h ushr 33)
            return h
        }

        fun read(input: DataInputStream): DomainHashSet {
            val n = input.readInt()
            require(n in 0..5_000_000) { "corrupt set size $n" }
            val a = LongArray(n) { input.readLong() }
            for (i in 1 until n) require(a[i - 1] < a[i]) { "set not sorted" }
            return DomainHashSet(a)
        }
    }
}
