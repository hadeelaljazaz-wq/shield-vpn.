package com.smartadshield.vpn.tunnel

import com.smartadshield.vpn.core.engine.VpnState
import org.json.JSONObject

/** Engines that actually exist in this build. */
enum class TunnelEngine(val labelAr: String) {
    WIREGUARD("WireGuard"),
    XRAY_REALITY("Xray VLESS-REALITY"),
}

/** Parsed `SHIELD1:` enrollment code produced by the server stack. */
data class Enrollment(
    val apiBase: String,
    val serverIp: String,
    val token: String,
    val certPinSha256Hex: String,
    val name: String,
)

/** Credentials returned by the provisioning API for this device. */
data class ProvisionedServer(
    val name: String,
    val publicIp: String,
    val wgServerPublicKey: String,
    val wgEndpointHost: String,
    val wgEndpointPort: Int,
    val wgAddress4: String,
    val wgAddress6: String?,
    val wgMtu: Int,
    val wgKeepalive: Int,
    val xray: XrayParams?,
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("name", name); put("publicIp", publicIp)
        put("wgServerPublicKey", wgServerPublicKey); put("wgEndpointHost", wgEndpointHost)
        put("wgEndpointPort", wgEndpointPort); put("wgAddress4", wgAddress4)
        put("wgAddress6", wgAddress6 ?: JSONObject.NULL); put("wgMtu", wgMtu); put("wgKeepalive", wgKeepalive)
        put("xray", xray?.toJson() ?: JSONObject.NULL)
    }

    companion object {
        fun fromJson(o: JSONObject) = ProvisionedServer(
            name = o.optString("name"),
            publicIp = o.getString("publicIp"),
            wgServerPublicKey = o.getString("wgServerPublicKey"),
            wgEndpointHost = o.getString("wgEndpointHost"),
            wgEndpointPort = o.getInt("wgEndpointPort"),
            wgAddress4 = o.getString("wgAddress4"),
            wgAddress6 = o.optString("wgAddress6").takeIf { it.isNotBlank() && it != "null" },
            wgMtu = o.optInt("wgMtu", 1280),
            wgKeepalive = o.optInt("wgKeepalive", 25),
            xray = o.optJSONObject("xray")?.let { XrayParams.fromJson(it) },
        )

        /** Parses the provisioning API /v1/register response. */
        fun fromApi(o: JSONObject): ProvisionedServer {
            val wg = o.getJSONObject("wg")
            return ProvisionedServer(
                name = o.optString("name"),
                publicIp = o.getString("public_ip"),
                wgServerPublicKey = wg.getString("server_public_key"),
                wgEndpointHost = wg.getString("endpoint_host"),
                wgEndpointPort = wg.getInt("endpoint_port"),
                wgAddress4 = wg.getString("address4"),
                wgAddress6 = wg.optString("address6").takeIf { it.isNotBlank() && it != "null" },
                wgMtu = wg.optInt("mtu", 1280),
                wgKeepalive = wg.optInt("keepalive", 25),
                xray = o.optJSONObject("xray")?.let {
                    XrayParams(
                        address = it.getString("address"), port = it.getInt("port"), uuid = it.getString("uuid"),
                        flow = it.optString("flow", "xtls-rprx-vision"), sni = it.getString("sni"),
                        publicKey = it.getString("public_key"), shortId = it.optString("short_id"),
                        fingerprint = it.optString("fingerprint", "chrome"),
                    )
                },
            )
        }
    }
}

data class XrayParams(
    val address: String,
    val port: Int,
    val uuid: String,
    val flow: String,
    val sni: String,
    val publicKey: String,
    val shortId: String,
    val fingerprint: String,
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("address", address); put("port", port); put("uuid", uuid); put("flow", flow)
        put("sni", sni); put("publicKey", publicKey); put("shortId", shortId); put("fingerprint", fingerprint)
    }

    companion object {
        fun fromJson(o: JSONObject) = XrayParams(
            o.getString("address"), o.getInt("port"), o.getString("uuid"), o.optString("flow"),
            o.getString("sni"), o.getString("publicKey"), o.optString("shortId"), o.optString("fingerprint", "chrome"),
        )
    }
}

/** A server the user can select. Only real (enrolled or imported) servers exist. */
data class ServerEntry(
    val id: String,
    val name: String,
    val kind: Kind,
    /** For ENROLLED: the provisioning endpoint. */
    val enrollment: Enrollment?,
    /** Cached provisioning result (refreshed on every connect). */
    val provisioned: ProvisionedServer?,
    /** For MANUAL_WG: raw wg-quick config text (encrypted at rest). */
    val manualConfig: String?,
    /** Country measured from the real exit IP on the last verified connection. */
    val lastVerifiedCountry: String?,
    val lastVerifiedIp: String?,
) {
    enum class Kind { ENROLLED, MANUAL_WG }

    val supportsXray: Boolean get() = kind == Kind.ENROLLED && provisioned?.xray != null
}

/** Live status shown in the UI; every number here is measured, never constant. */
data class TunnelStatus(
    val state: VpnState = VpnState.DISCONNECTED,
    val engine: TunnelEngine? = null,
    val serverName: String? = null,
    val serverIp: String? = null,
    val verifiedPublicIp: String? = null,
    val verifiedCountry: String? = null,
    val connectedSinceMs: Long = 0L,
    val lastHandshakeMs: Long = 0L,
    val rxBytes: Long = 0L,
    val txBytes: Long = 0L,
    val pingMs: Long? = null,
    val internetOk: Boolean? = null,
    val errorAr: String? = null,
    val log: List<String> = emptyList(),
)
