package com.smartadshield.vpn.tunnel

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.MessageDigest
import java.util.Base64

class TunnelUnitTest {

    private fun sha256Hex(b: ByteArray) = MessageDigest.getInstance("SHA-256").digest(b).joinToString("") { "%02x".format(it) }

    private fun code(json: JSONObject) = "SHIELD1:" + Base64.getEncoder().encodeToString(json.toString().toByteArray())

    private val good = JSONObject()
        .put("v", 1).put("api", "https://203.0.113.7:8443").put("ip", "203.0.113.7")
        .put("tok", "a".repeat(48)).put("pin", "0".repeat(64)).put("name", "Oracle Cloud")

    @Test fun parsesTerraformEnrollmentCode() {
        val e = EnrollmentCode.parse(code(good)).getOrThrow()
        assertEquals("https://203.0.113.7:8443", e.apiBase)
        assertEquals("203.0.113.7", e.serverIp)
        assertEquals("Oracle Cloud", e.name)
    }

    @Test fun toleratesLineBreaksFromCopyPaste() {
        val c = code(good)
        val broken = c.chunked(20).joinToString("\n ")
        assertTrue(EnrollmentCode.parse(broken).isSuccess)
    }

    @Test fun rejectsPlainHttpShortTokenAndBadPin() {
        assertTrue(EnrollmentCode.parse(code(JSONObject(good.toString()).put("api", "http://1.2.3.4:8443"))).isFailure)
        assertTrue(EnrollmentCode.parse(code(JSONObject(good.toString()).put("tok", "short"))).isFailure)
        assertTrue(EnrollmentCode.parse(code(JSONObject(good.toString()).put("pin", "xyz"))).isFailure)
        assertTrue(EnrollmentCode.parse("random text").isFailure)
    }

    @Test fun pemReconstructionMatchesGoEncodingLayout() {
        val der = ByteArray(700) { (it * 7).toByte() }
        val pem = ProvisioningClient.toPem(der)
        assertTrue(pem.startsWith("-----BEGIN CERTIFICATE-----\n"))
        assertTrue(pem.endsWith("\n-----END CERTIFICATE-----\n"))
        pem.lines().drop(1).dropLast(2).forEach { assertTrue(it.length <= 64) }
        // both pin flavours are accepted, anything else is rejected
        assertTrue(ProvisioningClient.matchesPin(der, sha256Hex(der)))
        assertTrue(ProvisioningClient.matchesPin(der, sha256Hex(pem.toByteArray())))
        assertFalse(ProvisioningClient.matchesPin(der, "f".repeat(64)))
    }

    @Test fun parsesProvisioningApiResponse() {
        val api = JSONObject("""
            {"name":"Oracle Cloud","cc":"","public_ip":"203.0.113.7",
             "wg":{"server_public_key":"${"A".repeat(43)}=","endpoint_host":"203.0.113.7","endpoint_port":51820,
                   "address4":"10.66.66.2/32","address6":"fd66:66::2/128","mtu":1280,"keepalive":25},
             "xray":{"address":"203.0.113.7","port":443,"uuid":"0b8f1f9e-8d63-4c9a-9d4c-2a7a8d1e6f00","flow":"xtls-rprx-vision",
                     "sni":"www.microsoft.com","public_key":"pbk","short_id":"0123456789abcdef","fingerprint":"chrome"}}
        """.trimIndent())
        val p = ProvisionedServer.fromApi(api)
        assertEquals(51820, p.wgEndpointPort)
        assertEquals("fd66:66::2/128", p.wgAddress6)
        assertEquals("www.microsoft.com", p.xray!!.sni)
        // round-trip through local storage format
        assertEquals(p, ProvisionedServer.fromJson(p.toJson()))
    }

    @Test fun xrayClientConfigHasTunSocksAndRealityOutbound() {
        val x = XrayParams("203.0.113.7", 443, "0b8f1f9e-8d63-4c9a-9d4c-2a7a8d1e6f00", "xtls-rprx-vision",
            "www.microsoft.com", "pbk", "0123456789abcdef", "chrome")
        val cfg = JSONObject(XrayConfigBuilder.build(x, 40123))
        val inbounds = cfg.getJSONArray("inbounds")
        assertEquals("tun", inbounds.getJSONObject(0).getString("protocol"))
        assertEquals("127.0.0.1", inbounds.getJSONObject(1).getString("listen"))
        val out = cfg.getJSONArray("outbounds").getJSONObject(0)
        assertEquals("vless", out.getString("protocol"))
        val rs = out.getJSONObject("streamSettings").getJSONObject("realitySettings")
        assertEquals("pbk", rs.getString("publicKey"))
        assertEquals("www.microsoft.com", rs.getString("serverName"))
    }

    @Test fun ipv6EndpointIsBracketed() {
        assertEquals("[2001:db8::1]:51820", WireGuardEngine.formatEndpoint("2001:db8::1", 51820))
        assertEquals("1.2.3.4:51820", WireGuardEngine.formatEndpoint("1.2.3.4", 51820))
    }
}
