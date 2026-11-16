package com.smartadshield.vpn.tunnel

import android.content.Context
import com.wireguard.crypto.KeyPair
import com.wireguard.crypto.Key
import org.json.JSONArray
import org.json.JSONObject
import java.util.UUID

/**
 * Persists the user's REAL servers (no presets): enrolled gateways and manually
 * imported WireGuard configs. Everything is encrypted with [SecureStore].
 */
class ServerStore(context: Context) {
    private val secure = SecureStore(context.applicationContext)
    private val prefs = context.applicationContext.getSharedPreferences("shield_servers_v1", Context.MODE_PRIVATE)

    @Synchronized
    fun list(): List<ServerEntry> {
        val raw = secure.get(KEY_SERVERS) ?: return emptyList()
        return runCatching {
            val arr = JSONArray(raw)
            (0 until arr.length()).map { decode(arr.getJSONObject(it)) }
        }.getOrDefault(emptyList())
    }

    @Synchronized
    private fun save(all: List<ServerEntry>) {
        val arr = JSONArray()
        all.forEach { arr.put(encode(it)) }
        secure.put(KEY_SERVERS, arr.toString())
    }

    var activeId: String?
        get() = prefs.getString("active", null)?.takeIf { id -> list().any { it.id == id } } ?: list().firstOrNull()?.id
        set(v) = prefs.edit().putString("active", v).apply()

    fun active(): ServerEntry? = activeId?.let { id -> list().find { it.id == id } }

    @Synchronized
    fun addEnrollment(e: Enrollment): ServerEntry {
        val existing = list().find { it.enrollment?.apiBase == e.apiBase }
        val entry = ServerEntry(
            id = existing?.id ?: UUID.randomUUID().toString(),
            name = e.name, kind = ServerEntry.Kind.ENROLLED, enrollment = e,
            provisioned = existing?.provisioned, manualConfig = null,
            lastVerifiedCountry = existing?.lastVerifiedCountry, lastVerifiedIp = existing?.lastVerifiedIp,
        )
        save(list().filterNot { it.id == entry.id } + entry)
        activeId = entry.id
        return entry
    }

    @Synchronized
    fun addManual(name: String, wgQuickText: String): ServerEntry {
        val entry = ServerEntry(
            id = UUID.randomUUID().toString(), name = name, kind = ServerEntry.Kind.MANUAL_WG,
            enrollment = null, provisioned = null, manualConfig = wgQuickText,
            lastVerifiedCountry = null, lastVerifiedIp = null,
        )
        save(list() + entry)
        activeId = entry.id
        return entry
    }

    @Synchronized
    fun update(entry: ServerEntry) {
        save(list().map { if (it.id == entry.id) entry else it })
    }

    @Synchronized
    fun remove(id: String) {
        save(list().filterNot { it.id == id })
        secure.remove("wgkey_$id")
    }

    /** Device WireGuard key pair for this server; the private key never leaves the phone. */
    fun keyPairFor(id: String): KeyPair {
        secure.get("wgkey_$id")?.let { return KeyPair(Key.fromBase64(it)) }
        val kp = KeyPair()
        secure.put("wgkey_$id", kp.privateKey.toBase64())
        return kp
    }

    private fun encode(s: ServerEntry) = JSONObject().apply {
        put("id", s.id); put("name", s.name); put("kind", s.kind.name)
        s.enrollment?.let {
            put("enroll", JSONObject().apply {
                put("api", it.apiBase); put("ip", it.serverIp); put("tok", it.token)
                put("pin", it.certPinSha256Hex); put("name", it.name)
            })
        }
        s.provisioned?.let { put("prov", it.toJson()) }
        s.manualConfig?.let { put("conf", it) }
        s.lastVerifiedCountry?.let { put("cc", it) }
        s.lastVerifiedIp?.let { put("vip", it) }
    }

    private fun decode(o: JSONObject) = ServerEntry(
        id = o.getString("id"),
        name = o.getString("name"),
        kind = ServerEntry.Kind.valueOf(o.getString("kind")),
        enrollment = o.optJSONObject("enroll")?.let {
            Enrollment(it.getString("api"), it.getString("ip"), it.getString("tok"), it.getString("pin"), it.getString("name"))
        },
        provisioned = o.optJSONObject("prov")?.let { ProvisionedServer.fromJson(it) },
        manualConfig = o.optString("conf").ifBlank { null },
        lastVerifiedCountry = o.optString("cc").ifBlank { null },
        lastVerifiedIp = o.optString("vip").ifBlank { null },
    )

    private companion object {
        const val KEY_SERVERS = "servers"
    }
}
