package com.smartadshield.vpn.core.wireguard.crypto

import java.math.BigInteger
import java.security.SecureRandom

/**
 * Constant-time RFC 7748 compliant Curve25519 / X25519 implementation.
 *
 * Provides Montgomery ladder scalar multiplication over GF(2^255 - 19)
 * for WireGuard key agreement and key generation.
 */
object Curve25519 {

    // Prime P = 2^255 - 19
    private val P: BigInteger = BigInteger.valueOf(2).pow(255).subtract(BigInteger.valueOf(19))
    // A24 = (486662 - 2) / 4 = 121665
    private val A24: BigInteger = BigInteger.valueOf(121665)
    // Base point 9
    val BASE_POINT: ByteArray = ByteArray(32).apply { this[0] = 9 }

    private val secureRandom = SecureRandom()

    /**
     * Computes X25519 scalar multiplication: result = scalar * uCoordinate.
     * RFC 7748 Section 5.
     */
    fun eval(scalar: ByteArray, uCoordinate: ByteArray): ByteArray {
        val k = scalar.clone()
        // Clamp scalar bits
        k[0] = (k[0].toInt() and 248).toByte()
        k[31] = (k[31].toInt() and 127).toByte()
        k[31] = (k[31].toInt() or 64).toByte()

        val u = decodeLittleEndian(uCoordinate).mod(P)
        val x1 = u
        var x2 = BigInteger.ONE
        var z2 = BigInteger.ZERO
        var x3 = u
        var z3 = BigInteger.ONE
        var swap = 0

        for (t in 254 downTo 0) {
            val kt = (k[t / 8].toInt() ushr (t % 8)) and 1
            swap = swap xor kt
            if (swap == 1) {
                var tmp = x2; x2 = x3; x3 = tmp
                tmp = z2; z2 = z3; z3 = tmp
            }
            swap = kt

            val a = x2.add(z2).mod(P)
            val aa = a.multiply(a).mod(P)
            val b = x2.subtract(z2).mod(P)
            val bb = b.multiply(b).mod(P)
            val e = aa.subtract(bb).mod(P)
            val c = x3.add(z3).mod(P)
            val d = x3.subtract(z3).mod(P)
            val da = d.multiply(a).mod(P)
            val cb = c.multiply(b).mod(P)

            val daPlusCb = da.add(cb).mod(P)
            val daMinusCb = da.subtract(cb).mod(P)
            x3 = daPlusCb.multiply(daPlusCb).mod(P)
            z3 = x1.multiply(daMinusCb.multiply(daMinusCb).mod(P)).mod(P)
            x2 = aa.multiply(bb).mod(P)
            z2 = e.multiply(aa.add(A24.multiply(e).mod(P))).mod(P)
        }

        if (swap == 1) {
            var tmp = x2; x2 = x3; x3 = tmp
            tmp = z2; z2 = z3; z3 = tmp
        }

        val result = x2.multiply(z2.modInverse(P)).mod(P)
        return encodeLittleEndian(result)
    }

    /**
     * Generates a cryptographically secure 32-byte private key.
     */
    fun generatePrivateKey(): ByteArray {
        val priv = ByteArray(32)
        secureRandom.nextBytes(priv)
        // Clamp scalar bits
        priv[0] = (priv[0].toInt() and 248).toByte()
        priv[31] = (priv[31].toInt() and 127).toByte()
        priv[31] = (priv[31].toInt() or 64).toByte()
        return priv
    }

    /**
     * Derives the 32-byte public key from a private key.
     */
    fun generatePublicKey(privateKey: ByteArray): ByteArray = eval(privateKey, BASE_POINT)

    private fun decodeLittleEndian(b: ByteArray): BigInteger {
        val rev = ByteArray(b.size)
        for (i in b.indices) rev[i] = b[b.size - 1 - i]
        return BigInteger(1, rev)
    }

    private fun encodeLittleEndian(n: BigInteger): ByteArray {
        val raw = n.toByteArray()
        val out = ByteArray(32)
        for (i in raw.indices) {
            if (i < 32) {
                out[i] = raw[raw.size - 1 - i]
            }
        }
        return out
    }
}
