package com.smartadshield.vpn.core.wireguard.crypto

import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * ChaCha20-Poly1305 Authenticated Encryption with Associated Data (AEAD).
 * RFC 8439 / WireGuard protocol standard.
 *
 * Uses hardware-accelerated JVM/Android standard crypto provider when available,
 * with pure Kotlin fallback to ensure compatibility across all Android versions.
 */
object ChaCha20Poly1305 {

    private val jvmCipherAvailable: Boolean by lazy {
        runCatching {
            val c = Cipher.getInstance("ChaCha20-Poly1305/None/NoPadding")
            val key = SecretKeySpec(ByteArray(32), "ChaCha20")
            val iv = IvParameterSpec(ByteArray(12))
            c.init(Cipher.ENCRYPT_MODE, key, iv)
            c.doFinal(ByteArray(0))
            true
        }.getOrDefault(false)
    }

    /**
     * Encrypts [plaintext] with [key] and [nonce] (12 bytes), authenticating [aad].
     * Returns ciphertext concatenated with the 16-byte Poly1305 tag.
     */
    fun encrypt(key: ByteArray, nonce: ByteArray, plaintext: ByteArray, aad: ByteArray = ByteArray(0)): ByteArray {
        require(key.size == 32) { "Key must be 32 bytes" }
        require(nonce.size == 12) { "Nonce must be 12 bytes" }

        if (jvmCipherAvailable) {
            try {
                val c = Cipher.getInstance("ChaCha20-Poly1305/None/NoPadding")
                c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "ChaCha20"), IvParameterSpec(nonce))
                if (aad.isNotEmpty()) c.updateAAD(aad)
                return c.doFinal(plaintext)
            } catch (_: Exception) {
                // fallback to pure kotlin
            }
        }
        return pureEncrypt(key, nonce, plaintext, aad)
    }

    /**
     * Decrypts [ciphertextAndTag] (length >= 16) with [key] and [nonce], verifying [aad].
     * Returns the decrypted plaintext, or throws GeneralSecurityException on tag mismatch.
     */
    fun decrypt(key: ByteArray, nonce: ByteArray, ciphertextAndTag: ByteArray, aad: ByteArray = ByteArray(0)): ByteArray {
        require(key.size == 32) { "Key must be 32 bytes" }
        require(nonce.size == 12) { "Nonce must be 12 bytes" }
        require(ciphertextAndTag.size >= 16) { "Ciphertext must include 16-byte authentication tag" }

        if (jvmCipherAvailable) {
            try {
                val c = Cipher.getInstance("ChaCha20-Poly1305/None/NoPadding")
                c.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "ChaCha20"), IvParameterSpec(nonce))
                if (aad.isNotEmpty()) c.updateAAD(aad)
                return c.doFinal(ciphertextAndTag)
            } catch (e: Exception) {
                if (e is javax.crypto.AEADBadTagException) throw e
                // fallback to pure kotlin
            }
        }
        return pureDecrypt(key, nonce, ciphertextAndTag, aad)
    }

    // ------------------------------------------------------------- Pure Kotlin Fallback

    private fun pureEncrypt(key: ByteArray, nonce: ByteArray, plaintext: ByteArray, aad: ByteArray): ByteArray {
        val polyKey = ByteArray(32)
        chacha20Block(key, 0, nonce, polyKey)

        val ciphertext = ByteArray(plaintext.size)
        chacha20Crypt(key, 1, nonce, plaintext, ciphertext)

        val tag = poly1305Mac(polyKey, aad, ciphertext)
        val out = ByteArray(ciphertext.size + 16)
        System.arraycopy(ciphertext, 0, out, 0, ciphertext.size)
        System.arraycopy(tag, 0, out, ciphertext.size, 16)
        return out
    }

    private fun pureDecrypt(key: ByteArray, nonce: ByteArray, ciphertextAndTag: ByteArray, aad: ByteArray): ByteArray {
        val polyKey = ByteArray(32)
        chacha20Block(key, 0, nonce, polyKey)

        val cipherLen = ciphertextAndTag.size - 16
        val ciphertext = ByteArray(cipherLen)
        val receivedTag = ByteArray(16)
        System.arraycopy(ciphertextAndTag, 0, ciphertext, 0, cipherLen)
        System.arraycopy(ciphertextAndTag, cipherLen, receivedTag, 0, 16)

        val computedTag = poly1305Mac(polyKey, aad, ciphertext)
        if (!constantTimeEquals(receivedTag, computedTag)) {
            throw javax.crypto.AEADBadTagException("Poly1305 MAC verification failed")
        }

        val plaintext = ByteArray(cipherLen)
        chacha20Crypt(key, 1, nonce, ciphertext, plaintext)
        return plaintext
    }

    private fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean {
        if (a.size != b.size) return false
        var diff = 0
        for (i in a.indices) diff = diff or (a[i].toInt() xor b[i].toInt())
        return diff == 0
    }

    private fun chacha20Block(key: ByteArray, counter: Int, nonce: ByteArray, out: ByteArray) {
        val state = IntArray(16)
        state[0] = 0x61707865; state[1] = 0x3320646e; state[2] = 0x79622d32; state[3] = 0x6b206574
        for (i in 0 until 8) state[4 + i] = u32Le(key, i * 4)
        state[12] = counter
        for (i in 0 until 3) state[13 + i] = u32Le(nonce, i * 4)

        val working = state.clone()
        for (i in 0 until 10) {
            quarterRound(working, 0, 4, 8, 12)
            quarterRound(working, 1, 5, 9, 13)
            quarterRound(working, 2, 6, 10, 14)
            quarterRound(working, 3, 7, 11, 15)
            quarterRound(working, 0, 5, 10, 15)
            quarterRound(working, 1, 6, 11, 12)
            quarterRound(working, 2, 7, 8, 13)
            quarterRound(working, 3, 4, 9, 14)
        }
        for (i in 0 until 16) {
            val sum = working[i] + state[i]
            val o = i * 4
            if (o + 4 <= out.size) {
                out[o] = sum.toByte()
                out[o + 1] = (sum ushr 8).toByte()
                out[o + 2] = (sum ushr 16).toByte()
                out[o + 3] = (sum ushr 24).toByte()
            }
        }
    }

    private fun chacha20Crypt(key: ByteArray, initialCounter: Int, nonce: ByteArray, src: ByteArray, dst: ByteArray) {
        var counter = initialCounter
        val block = ByteArray(64)
        var offset = 0
        while (offset < src.size) {
            chacha20Block(key, counter++, nonce, block)
            val len = minOf(64, src.size - offset)
            for (i in 0 until len) {
                dst[offset + i] = (src[offset + i].toInt() xor block[i].toInt()).toByte()
            }
            offset += len
        }
    }

    private fun quarterRound(x: IntArray, a: Int, b: Int, c: Int, d: Int) {
        x[a] = x[a] + x[b]; x[d] = rotl(x[d] xor x[a], 16)
        x[c] = x[c] + x[d]; x[b] = rotl(x[b] xor x[c], 12)
        x[a] = x[a] + x[b]; x[d] = rotl(x[d] xor x[a], 8)
        x[c] = x[c] + x[d]; x[b] = rotl(x[b] xor x[c], 7)
    }

    private fun rotl(v: Int, n: Int): Int = (v shl n) or (v ushr (32 - n))
    private fun u32Le(b: ByteArray, o: Int): Int =
        (b[o].toInt() and 0xFF) or ((b[o + 1].toInt() and 0xFF) shl 8) or
                ((b[o + 2].toInt() and 0xFF) shl 16) or ((b[o + 3].toInt() and 0xFF) shl 24)

    private fun poly1305Mac(key: ByteArray, aad: ByteArray, ciphertext: ByteArray): ByteArray {
        val r0 = (u32Le(key, 0).toLong() and 0x0FFFFFFFL)
        val r1 = (u32Le(key, 4).toLong() and 0x0FFFFFFCL)
        val r2 = (u32Le(key, 8).toLong() and 0x0FFFFFFCL)
        val r3 = (u32Le(key, 12).toLong() and 0x0FFFFFFCL)
        val s = key.copyOfRange(16, 32)

        // RFC 8439 MAC construction: aad || pad(aad) || ciphertext || pad(ciphertext) || len(aad) || len(ciphertext)
        val stream = java.io.ByteArrayOutputStream()
        stream.write(aad)
        val padAad = (16 - (aad.size % 16)) % 16
        for (i in 0 until padAad) stream.write(0)

        stream.write(ciphertext)
        val padCipher = (16 - (ciphertext.size % 16)) % 16
        for (i in 0 until padCipher) stream.write(0)

        // 8 bytes little-endian length of aad, 8 bytes little-endian length of ciphertext
        write64Le(stream, aad.size.toLong())
        write64Le(stream, ciphertext.size.toLong())

        val data = stream.toByteArray()
        val p = java.math.BigInteger.valueOf(2).pow(130).subtract(java.math.BigInteger.valueOf(5))
        var h = java.math.BigInteger.ZERO
        val r = (java.math.BigInteger.valueOf(r3).shiftLeft(96))
            .or(java.math.BigInteger.valueOf(r2).shiftLeft(64))
            .or(java.math.BigInteger.valueOf(r1).shiftLeft(32))
            .or(java.math.BigInteger.valueOf(r0))

        var i = 0
        while (i < data.size) {
            val chunkLen = minOf(16, data.size - i)
            val chunk = ByteArray(chunkLen + 1)
            System.arraycopy(data, i, chunk, 0, chunkLen)
            chunk[chunkLen] = 1 // 2^chunkLen term
            // reverse for BigInteger
            val rev = ByteArray(chunk.size)
            for (j in chunk.indices) rev[j] = chunk[chunk.size - 1 - j]
            val n = java.math.BigInteger(1, rev)
            h = h.add(n).multiply(r).mod(p)
            i += 16
        }

        // Add s
        val revS = ByteArray(16)
        for (j in 0 until 16) revS[j] = s[15 - j]
        val sInt = java.math.BigInteger(1, revS)
        val tagInt = h.add(sInt).mod(java.math.BigInteger.valueOf(2).pow(128))

        val tagRaw = tagInt.toByteArray()
        val outTag = ByteArray(16)
        for (j in tagRaw.indices) {
            if (j < 16) outTag[j] = tagRaw[tagRaw.size - 1 - j]
        }
        return outTag
    }

    private fun write64Le(stream: java.io.ByteArrayOutputStream, v: Long) {
        for (i in 0 until 8) stream.write(((v ushr (i * 8)) and 0xFF).toInt())
    }
}
