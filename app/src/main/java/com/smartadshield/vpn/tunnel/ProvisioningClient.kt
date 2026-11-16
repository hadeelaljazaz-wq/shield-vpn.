package com.smartadshield.vpn.tunnel

import android.os.Build
import org.json.JSONObject
import java.io.IOException
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URL
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import java.util.Base64
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.X509TrustManager

/**
 * Talks to the gateway's provisioning API over HTTPS. The server certificate is
 * self-signed, so instead of the system CA store we accept exactly one
 * certificate: the one whose SHA-256 pin came inside the enrollment code.
 */
class ProvisioningClient(private val e: Enrollment) {

    class PinnedTrustManager(private val pinHex: String) : X509TrustManager {
        override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) =
            throw CertificateException("client auth not supported")

        override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {
            val leaf = chain?.firstOrNull() ?: throw CertificateException("empty chain")
            if (!matchesPin(leaf.encoded, pinHex)) throw CertificateException("certificate pin mismatch")
        }

        override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
    }

    private fun open(path: String, method: String): HttpsURLConnection {
        val ctx = SSLContext.getInstance("TLS")
        ctx.init(null, arrayOf(PinnedTrustManager(e.certPinSha256Hex)), SecureRandom())
        val c = URL(e.apiBase + path).openConnection() as HttpsURLConnection
        c.sslSocketFactory = ctx.socketFactory
        // Identity is established by the pin, not by a hostname (server is addressed by IP).
        c.hostnameVerifier = javax.net.ssl.HostnameVerifier { _, _ -> true }
        c.requestMethod = method
        c.connectTimeout = 8000
        c.readTimeout = 12000
        c.useCaches = false
        c.setRequestProperty("Accept", "application/json")
        return c
    }

    fun health(): JSONObject {
        val c = open("/v1/health", "GET")
        try {
            if (c.responseCode != 200) throw IOException("health HTTP ${c.responseCode}")
            return JSONObject(c.inputStream.bufferedReader().readText())
        } finally {
            c.disconnect()
        }
    }

    fun register(wgPublicKeyBase64: String): ProvisionedServer {
        val c = open("/v1/register", "POST")
        try {
            c.doOutput = true
            c.setRequestProperty("Content-Type", "application/json")
            c.setRequestProperty("Authorization", "Bearer ${e.token}")
            val body = JSONObject().put("wg_public_key", wgPublicKeyBase64).put("device", "${Build.MANUFACTURER} ${Build.MODEL}")
            c.outputStream.use { it.write(body.toString().toByteArray()) }
            val code = c.responseCode
            val text = (if (code in 200..299) c.inputStream else c.errorStream)?.bufferedReader()?.readText().orEmpty()
            when (code) {
                200 -> return ProvisionedServer.fromApi(JSONObject(text))
                401 -> throw IOException("رمز التسجيل مرفوض من الخادم (401)")
                409 -> throw IOException("الخادم ممتلئ (409)")
                else -> throw IOException("فشل التسجيل HTTP $code $text")
            }
        } finally {
            c.disconnect()
        }
    }

    companion object {
        /** Pin = SHA-256 of the DER cert, or of its PEM text (Terraform's sha256(cert_pem)). */
        fun matchesPin(der: ByteArray, pinHex: String): Boolean {
            val sha = MessageDigest.getInstance("SHA-256")
            val derHex = sha.digest(der).toHex()
            if (MessageDigest.isEqual(derHex.toByteArray(), pinHex.toByteArray())) return true
            val pemHex = sha.digest(toPem(der).toByteArray(Charsets.US_ASCII)).toHex()
            return MessageDigest.isEqual(pemHex.toByteArray(), pinHex.toByteArray())
        }

        /** Same layout as Go's encoding/pem (64-column lines, trailing newline). */
        fun toPem(der: ByteArray): String {
            val b64 = Base64.getEncoder().encodeToString(der)
            val sb = StringBuilder("-----BEGIN CERTIFICATE-----\n")
            var i = 0
            while (i < b64.length) {
                sb.append(b64, i, minOf(i + 64, b64.length)).append('\n'); i += 64
            }
            return sb.append("-----END CERTIFICATE-----\n").toString()
        }

        private fun ByteArray.toHex() = joinToString("") { "%02x".format(it) }

        /** One TCP handshake to host:port = one network round-trip (a real ping measurement). */
        fun tcpPingMs(host: String, port: Int, timeoutMs: Int = 3000, socketFactory: (() -> Socket)? = null): Long? = runCatching {
            val s = socketFactory?.invoke() ?: Socket()
            s.use {
                val t0 = System.nanoTime()
                it.connect(InetSocketAddress(host, port), timeoutMs)
                (System.nanoTime() - t0) / 1_000_000
            }
        }.getOrNull()
    }
}
