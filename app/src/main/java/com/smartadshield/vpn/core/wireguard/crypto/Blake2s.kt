package com.smartadshield.vpn.core.wireguard.crypto

/**
 * Pure Kotlin RFC 7693 compliant BLAKE2s implementation with MAC and KDF functions
 * specified in the WireGuard protocol (Noise_IKpsk2).
 */
object Blake2s {

    private val IV = intArrayOf(
        0x6A09E667, -0x4498517B, 0x3C6EF372, -0x5AB00AC6,
        0x510E527F, -0x64FA9774, 0x1F83D9AB, 0x5BE0CD19
    )

    private val SIGMA = arrayOf(
        intArrayOf(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15),
        intArrayOf(14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3),
        intArrayOf(11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4),
        intArrayOf(7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8),
        intArrayOf(9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13),
        intArrayOf(2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9),
        intArrayOf(12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11),
        intArrayOf(13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10),
        intArrayOf(6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5),
        intArrayOf(10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0),
    )

    private fun rotr(x: Int, n: Int): Int = (x ushr n) or (x shl (32 - n))

    private fun g(v: IntArray, a: Int, b: Int, c: Int, d: Int, x: Int, y: Int) {
        v[a] = v[a] + v[b] + x
        v[d] = rotr(v[d] xor v[a], 16)
        v[c] = v[c] + v[d]
        v[b] = rotr(v[b] xor v[c], 12)
        v[a] = v[a] + v[b] + y
        v[d] = rotr(v[d] xor v[a], 8)
        v[c] = v[c] + v[d]
        v[b] = rotr(v[b] xor v[c], 7)
    }

    fun hash(data: ByteArray, outLen: Int = 32, key: ByteArray? = null): ByteArray {
        require(outLen in 1..32)
        val keyLen = key?.size ?: 0
        require(keyLen <= 64)

        val h = IV.clone()
        h[0] = h[0] xor 0x01010000 xor (keyLen shl 8) xor outLen

        var totalBytes = 0
        var block = ByteArray(64)
        var blockLen = 0

        fun compress(last: Boolean) {
            val v = IntArray(16)
            System.arraycopy(h, 0, v, 0, 8)
            System.arraycopy(IV, 0, v, 8, 8)
            v[12] = v[12] xor (totalBytes and -1)
            v[13] = v[13] xor (totalBytes ushr 32)
            if (last) {
                v[14] = v[14] xor -1
            }

            val m = IntArray(16)
            for (i in 0 until 16) {
                val o = i * 4
                m[i] = (block[o].toInt() and 0xFF) or
                        ((block[o + 1].toInt() and 0xFF) shl 8) or
                        ((block[o + 2].toInt() and 0xFF) shl 16) or
                        ((block[o + 3].toInt() and 0xFF) shl 24)
            }

            for (i in 0 until 10) {
                val s = SIGMA[i]
                g(v, 0, 4, 8, 12, m[s[0]], m[s[1]])
                g(v, 1, 5, 9, 13, m[s[2]], m[s[3]])
                g(v, 2, 6, 10, 14, m[s[4]], m[s[5]])
                g(v, 3, 7, 11, 15, m[s[6]], m[s[7]])
                g(v, 0, 5, 10, 15, m[s[8]], m[s[9]])
                g(v, 1, 6, 11, 12, m[s[10]], m[s[11]])
                g(v, 2, 7, 8, 13, m[s[12]], m[s[13]])
                g(v, 3, 4, 9, 14, m[s[14]], m[s[15]])
            }

            for (i in 0 until 8) {
                h[i] = h[i] xor v[i] xor v[i + 8]
            }
        }

        if (key != null && key.isNotEmpty()) {
            block = ByteArray(64)
            System.arraycopy(key, 0, block, 0, key.size)
            blockLen = 64
        }

        var offset = 0
        while (offset < data.size) {
            if (blockLen == 64) {
                totalBytes += 64
                compress(false)
                block = ByteArray(64)
                blockLen = 0
            }
            val toCopy = minOf(64 - blockLen, data.size - offset)
            System.arraycopy(data, offset, block, blockLen, toCopy)
            blockLen += toCopy
            offset += toCopy
        }

        totalBytes += blockLen
        while (blockLen < 64) {
            block[blockLen++] = 0
        }
        compress(true)

        val out = ByteArray(outLen)
        for (i in 0 until outLen) {
            out[i] = ((h[i / 4] ushr ((i % 4) * 8)) and 0xFF).toByte()
        }
        return out
    }

    fun hmac(key: ByteArray, data: ByteArray): ByteArray {
        val k = if (key.size > 64) hash(key, 32) else key
        val kPad = ByteArray(64)
        System.arraycopy(k, 0, kPad, 0, k.size)

        val oPad = ByteArray(64) { (kPad[it].toInt() xor 0x5C).toByte() }
        val iPad = ByteArray(64) { (kPad[it].toInt() xor 0x36).toByte() }

        val inner = hash(iPad + data, 32)
        return hash(oPad + inner, 32)
    }

    /** WireGuard KDF1: outputs 1 32-byte key */
    fun kdf1(key: ByteArray, input: ByteArray): ByteArray {
        val prk = hmac(key, input)
        return hmac(prk, byteArrayOf(0x01))
    }

    /** WireGuard KDF2: outputs 2 32-byte keys */
    fun kdf2(key: ByteArray, input: ByteArray): Pair<ByteArray, ByteArray> {
        val prk = hmac(key, input)
        val t0 = hmac(prk, byteArrayOf(0x01))
        val t1 = hmac(prk, t0 + byteArrayOf(0x02))
        return Pair(t0, t1)
    }

    /** WireGuard KDF3: outputs 3 32-byte keys */
    fun kdf3(key: ByteArray, input: ByteArray): Triple<ByteArray, ByteArray, ByteArray> {
        val prk = hmac(key, input)
        val t0 = hmac(prk, byteArrayOf(0x01))
        val t1 = hmac(prk, t0 + byteArrayOf(0x02))
        val t2 = hmac(prk, t1 + byteArrayOf(0x03))
        return Triple(t0, t1, t2)
    }
}
