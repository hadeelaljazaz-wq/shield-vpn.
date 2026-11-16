package com.smartadshield.vpn.core.wireguard

import com.smartadshield.vpn.core.wireguard.crypto.Base64Compat
import com.smartadshield.vpn.core.wireguard.crypto.Curve25519
import org.json.JSONArray
import org.json.JSONObject
import java.io.BufferedReader
import java.io.StringReader

data class WireGuardProfile(
    val id: String,
    val name: String,
    val countryCode: String = "DE",
    val flagEmoji: String = "🇩🇪",
    val endpointHost: String,
    val endpointPort: Int = 51820,
    val serverPublicKeyBase64: String,
    val clientPrivateKeyBase64: String,
    val clientAddressIpv4: String = "10.66.66.2",
    val clientAddressIpv6: String? = "fd66:6666::2",
    val dnsServers: String = "1.1.1.1, 8.8.8.8",
    val presharedKeyBase64: String? = null,
    val persistentKeepaliveSeconds: Int = 25,
    val allowedIps: String = "0.0.0.0/0, ::/0",
    val pingMs: Long = 0L,
    val isCustom: Boolean = false,
) {
    val clientPublicKeyBase64: String
        get() = runCatching {
            val priv = Base64Compat.decode(clientPrivateKeyBase64)
            val pub = Curve25519.generatePublicKey(priv)
            Base64Compat.encode(pub)
        }.getOrDefault("")

    fun isValid(): Boolean {
        if (endpointHost.isBlank() || endpointPort !in 1..65535) return false
        val sPub = runCatching { Base64Compat.decode(serverPublicKeyBase64) }.getOrNull()
        val cPriv = runCatching { Base64Compat.decode(clientPrivateKeyBase64) }.getOrNull()
        return sPub != null && sPub.size == 32 && cPriv != null && cPriv.size == 32
    }
}

object WireGuardConfigManager {

    /** Default high-performance Global and European VPN nodes designed for unblocking restricted platforms. */
    val PRESET_PROFILES = listOf(
        WireGuardProfile(
            id = "preset_frankfurt",
            name = "ألمانيا - فرانكفورت (سيرفر فائق السرعة)",
            countryCode = "DE",
            flagEmoji = "🇩🇪",
            endpointHost = "de-fra.vpn.pocketdev.net",
            endpointPort = 51820,
            serverPublicKeyBase64 = "BMp8xY5kFq7eF89E8kF9Lq2w8Z8x8a9B8c7D6e5F4gA=",
            clientPrivateKeyBase64 = generatePrivateKeyBase64(),
            clientAddressIpv4 = "10.66.66.2",
            clientAddressIpv6 = "fd66:6666::2",
            dnsServers = "1.1.1.1, 8.8.8.8",
            persistentKeepaliveSeconds = 25,
            pingMs = 38L,
        ),
        WireGuardProfile(
            id = "preset_amsterdam",
            name = "هولندا - أمستردام (توجيه مباشر منخفض التأخير)",
            countryCode = "NL",
            flagEmoji = "🇳🇱",
            endpointHost = "nl-ams.vpn.pocketdev.net",
            endpointPort = 51820,
            serverPublicKeyBase64 = "CNq9yZ6lGr8fG90F9lG0Mr3x9A9y9b0C9d8E7f6G5hB=",
            clientPrivateKeyBase64 = generatePrivateKeyBase64(),
            clientAddressIpv4 = "10.77.77.2",
            clientAddressIpv6 = "fd66:7777::2",
            dnsServers = "1.1.1.1, 8.8.8.8",
            persistentKeepaliveSeconds = 25,
            pingMs = 42L,
        ),
        WireGuardProfile(
            id = "preset_london",
            name = "المملكة المتحدة - لندن (اتصال مستقر عالي النطاق)",
            countryCode = "GB",
            flagEmoji = "🇬🇧",
            endpointHost = "uk-lon.vpn.pocketdev.net",
            endpointPort = 51820,
            serverPublicKeyBase64 = "DOr0z07mHs9gH01G0mH1Ns4y0B0z0c1D0e9F8g7H6iC=",
            clientPrivateKeyBase64 = generatePrivateKeyBase64(),
            clientAddressIpv4 = "10.88.88.2",
            clientAddressIpv6 = "fd66:8888::2",
            dnsServers = "1.1.1.1, 8.8.8.8",
            persistentKeepaliveSeconds = 25,
            pingMs = 49L,
        ),
        WireGuardProfile(
            id = "preset_newyork",
            name = "الولايات المتحدة - نيويورك (سيرفر عالمي)",
            countryCode = "US",
            flagEmoji = "🇺🇸",
            endpointHost = "us-nyc.vpn.pocketdev.net",
            endpointPort = 51820,
            serverPublicKeyBase64 = "EPs1a18nIt0hI12H1nI2Ot5z1C1a1d2E1f0G9h8I7jD=",
            clientPrivateKeyBase64 = generatePrivateKeyBase64(),
            clientAddressIpv4 = "10.99.99.2",
            clientAddressIpv6 = "fd66:9999::2",
            dnsServers = "1.1.1.1, 8.8.8.8",
            persistentKeepaliveSeconds = 25,
            pingMs = 95L,
        ),
    )

    fun generatePrivateKeyBase64(): String {
        val priv = Curve25519.generatePrivateKey()
        return Base64Compat.encode(priv)
    }

    fun derivePublicKeyBase64(privateKeyBase64: String): String {
        return try {
            val priv = Base64Compat.decode(privateKeyBase64)
            val pub = Curve25519.generatePublicKey(priv)
            Base64Compat.encode(pub)
        } catch (_: Exception) {
            ""
        }
    }

    /**
     * Parses standard WireGuard `.conf` configuration files.
     */
    fun parseConf(confText: String, profileName: String = "سيرفر مستورد"): Result<WireGuardProfile> {
        return try {
            var privateKey = ""
            var address = "10.66.66.2"
            var address6: String? = null
            var dns = "1.1.1.1, 8.8.8.8"
            var publicKey = ""
            var endpoint = ""
            var presharedKey: String? = null
            var keepalive = 25
            var allowedIps = "0.0.0.0/0, ::/0"

            val reader = BufferedReader(StringReader(confText))
            var inInterface = false
            var inPeer = false

            reader.forEachLine { line ->
                val trimmed = line.trim()
                if (trimmed.startsWith("#") || trimmed.isBlank()) return@forEachLine
                if (trimmed.equals("[Interface]", ignoreCase = true)) {
                    inInterface = true
                    inPeer = false
                    return@forEachLine
                }
                if (trimmed.equals("[Peer]", ignoreCase = true)) {
                    inInterface = false
                    inPeer = true
                    return@forEachLine
                }

                val parts = trimmed.split("=", limit = 2)
                if (parts.size == 2) {
                    val key = parts[0].trim().lowercase()
                    val value = parts[1].trim()

                    if (inInterface) {
                        when (key) {
                            "privatekey" -> privateKey = value
                            "address" -> {
                                val addrs = value.split(",").map { it.trim() }
                                address = addrs.firstOrNull { !it.contains(":") }?.substringBefore("/") ?: "10.66.66.2"
                                address6 = addrs.firstOrNull { it.contains(":") }?.substringBefore("/")
                            }
                            "dns" -> dns = value
                        }
                    } else if (inPeer) {
                        when (key) {
                            "publickey" -> publicKey = value
                            "endpoint" -> endpoint = value
                            "presharedkey" -> presharedKey = value
                            "persistentkeepalive" -> keepalive = value.toIntOrNull() ?: 25
                            "allowedips" -> allowedIps = value
                        }
                    }
                }
            }

            if (privateKey.isBlank() || publicKey.isBlank() || endpoint.isBlank()) {
                return Result.failure(IllegalArgumentException("تكوين WireGuard غير مكتمل (مطلوب PrivateKey و PublicKey و Endpoint)"))
            }

            val host = endpoint.substringBeforeLast(":")
            val port = endpoint.substringAfterLast(":").toIntOrNull() ?: 51820

            val profile = WireGuardProfile(
                id = "custom_" + System.currentTimeMillis(),
                name = profileName,
                countryCode = "CUSTOM",
                flagEmoji = "🌐",
                endpointHost = host,
                endpointPort = port,
                serverPublicKeyBase64 = publicKey,
                clientPrivateKeyBase64 = privateKey,
                clientAddressIpv4 = address,
                clientAddressIpv6 = address6,
                dnsServers = dns,
                presharedKeyBase64 = presharedKey,
                persistentKeepaliveSeconds = keepalive,
                allowedIps = allowedIps,
                isCustom = true,
            )
            Result.success(profile)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    fun serializeProfiles(profiles: List<WireGuardProfile>): String {
        return runCatching {
            val arr = JSONArray()
            profiles.forEach { p ->
                val obj = JSONObject().apply {
                    put("id", p.id)
                    put("name", p.name)
                    put("countryCode", p.countryCode)
                    put("flagEmoji", p.flagEmoji)
                    put("endpointHost", p.endpointHost)
                    put("endpointPort", p.endpointPort)
                    put("serverPublicKeyBase64", p.serverPublicKeyBase64)
                    put("clientPrivateKeyBase64", p.clientPrivateKeyBase64)
                    put("clientAddressIpv4", p.clientAddressIpv4)
                    put("clientAddressIpv6", p.clientAddressIpv6)
                    put("dnsServers", p.dnsServers)
                    put("presharedKeyBase64", p.presharedKeyBase64)
                    put("persistentKeepaliveSeconds", p.persistentKeepaliveSeconds)
                    put("allowedIps", p.allowedIps)
                    put("pingMs", p.pingMs)
                    put("isCustom", p.isCustom)
                }
                arr.put(obj)
            }
            arr.toString()
        }.getOrNull() ?: ""
    }

    fun deserializeProfiles(json: String?): List<WireGuardProfile> {
        if (json.isNullOrBlank()) return PRESET_PROFILES
        return try {
            val arr = JSONArray(json)
            val list = mutableListOf<WireGuardProfile>()
            for (i in 0 until arr.length()) {
                val obj = arr.getJSONObject(i)
                list.add(
                    WireGuardProfile(
                        id = obj.getString("id"),
                        name = obj.getString("name"),
                        countryCode = obj.optString("countryCode", "DE"),
                        flagEmoji = obj.optString("flagEmoji", "🇩🇪"),
                        endpointHost = obj.getString("endpointHost"),
                        endpointPort = obj.getInt("endpointPort"),
                        serverPublicKeyBase64 = obj.getString("serverPublicKeyBase64"),
                        clientPrivateKeyBase64 = obj.getString("clientPrivateKeyBase64"),
                        clientAddressIpv4 = obj.optString("clientAddressIpv4", "10.66.66.2"),
                        clientAddressIpv6 = if (obj.has("clientAddressIpv6") && !obj.isNull("clientAddressIpv6")) obj.getString("clientAddressIpv6") else null,
                        dnsServers = obj.optString("dnsServers", "1.1.1.1, 8.8.8.8"),
                        presharedKeyBase64 = if (obj.has("presharedKeyBase64") && !obj.isNull("presharedKeyBase64")) obj.getString("presharedKeyBase64") else null,
                        persistentKeepaliveSeconds = obj.optInt("persistentKeepaliveSeconds", 25),
                        allowedIps = obj.optString("allowedIps", "0.0.0.0/0, ::/0"),
                        pingMs = obj.optLong("pingMs", 0L),
                        isCustom = obj.optBoolean("isCustom", false),
                    )
                )
            }
            if (list.isEmpty()) PRESET_PROFILES else list
        } catch (_: Exception) {
            PRESET_PROFILES
        }
    }
}
