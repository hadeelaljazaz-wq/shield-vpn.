package com.smartadshield.vpn.core.wireguard.crypto

/**
 * Dual-environment Base64 encoder/decoder running seamlessly on both Android runtime
 * and standard JVM unit tests without stub failures.
 */
object Base64Compat {

    fun encode(bytes: ByteArray): String = try {
        android.util.Base64.encodeToString(bytes, android.util.Base64.NO_WRAP)
    } catch (_: Throwable) {
        try {
            java.util.Base64.getEncoder().encodeToString(bytes)
        } catch (_: Throwable) {
            ""
        }
    }

    fun decode(str: String): ByteArray {
        val s = str.trim()
        if (s.isEmpty()) return ByteArray(0)
        return try {
            val res = android.util.Base64.decode(s, android.util.Base64.DEFAULT)
            if (res != null && res.isNotEmpty()) res else {
                try {
                    java.util.Base64.getDecoder().decode(s)
                } catch (_: Throwable) {
                    ByteArray(0)
                }
            }
        } catch (_: Throwable) {
            try {
                java.util.Base64.getDecoder().decode(s)
            } catch (_: Throwable) {
                ByteArray(0)
            }
        }
    }
}
