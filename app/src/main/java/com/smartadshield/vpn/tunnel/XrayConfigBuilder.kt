package com.smartadshield.vpn.tunnel

import org.json.JSONArray
import org.json.JSONObject

/** Client-side Xray JSON: TUN inbound (Android fd) + loopback SOCKS for verification, VLESS-REALITY outbound. */
object XrayConfigBuilder {
    const val TUN_MTU = 1500

    fun build(x: XrayParams, socksPort: Int): String {
        val tunIn = JSONObject()
            .put("tag", "tun-in")
            .put("protocol", "tun")
            .put("settings", JSONObject().put("name", "xray0").put("mtu", TUN_MTU))
            .put("sniffing", JSONObject().put("enabled", true).put("destOverride", JSONArray(listOf("http", "tls", "quic"))).put("routeOnly", true))
        val socksIn = JSONObject()
            .put("tag", "socks-in")
            .put("listen", "127.0.0.1")
            .put("port", socksPort)
            .put("protocol", "socks")
            .put("settings", JSONObject().put("auth", "noauth").put("udp", true))
        val user = JSONObject().put("id", x.uuid).put("encryption", "none")
        if (x.flow.isNotBlank()) user.put("flow", x.flow)
        val proxyOut = JSONObject()
            .put("tag", "proxy")
            .put("protocol", "vless")
            .put("settings", JSONObject().put("vnext", JSONArray().put(
                JSONObject().put("address", x.address).put("port", x.port).put("users", JSONArray().put(user))
            )))
            .put("streamSettings", JSONObject()
                .put("network", "tcp")
                .put("security", "reality")
                .put("realitySettings", JSONObject()
                    .put("serverName", x.sni)
                    .put("fingerprint", x.fingerprint.ifBlank { "chrome" })
                    .put("publicKey", x.publicKey)
                    .put("shortId", x.shortId)
                    .put("spiderX", "/")))
        return JSONObject()
            .put("log", JSONObject().put("loglevel", "warning"))
            .put("inbounds", JSONArray().put(tunIn).put(socksIn))
            .put("outbounds", JSONArray().put(proxyOut).put(JSONObject().put("tag", "block").put("protocol", "blackhole")))
            .toString()
    }
}
