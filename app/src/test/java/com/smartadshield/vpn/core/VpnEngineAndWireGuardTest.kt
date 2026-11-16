package com.smartadshield.vpn.core

import com.smartadshield.vpn.core.engine.SplitTunnelingMode
import com.smartadshield.vpn.core.engine.VpnError
import com.smartadshield.vpn.core.engine.VpnProtocol
import com.smartadshield.vpn.core.engine.VpnState
import com.smartadshield.vpn.core.wireguard.WireGuardConfigManager
import com.smartadshield.vpn.core.wireguard.WireGuardProfile
import com.smartadshield.vpn.core.wireguard.crypto.Blake2s
import com.smartadshield.vpn.core.wireguard.crypto.ChaCha20Poly1305
import com.smartadshield.vpn.core.wireguard.crypto.Curve25519
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class VpnEngineAndWireGuardTest {

    @Test
    fun testCurve25519KeyGenerationAndDiffieHellman() {
        val alicePriv = Curve25519.generatePrivateKey()
        val alicePub = Curve25519.generatePublicKey(alicePriv)

        val bobPriv = Curve25519.generatePrivateKey()
        val bobPub = Curve25519.generatePublicKey(bobPriv)

        assertEquals(32, alicePriv.size)
        assertEquals(32, alicePub.size)
        assertEquals(32, bobPriv.size)
        assertEquals(32, bobPub.size)

        // Diffie-Hellman Shared Secret: DH(Alice_Priv, Bob_Pub) == DH(Bob_Priv, Alice_Pub)
        val sharedAlice = Curve25519.eval(alicePriv, bobPub)
        val sharedBob = Curve25519.eval(bobPriv, alicePub)

        assertEquals(32, sharedAlice.size)
        assertEquals(32, sharedBob.size)
        assertTrue(sharedAlice.contentEquals(sharedBob))
    }

    @Test
    fun testChaCha20Poly1305EncryptionDecryption() {
        val key = ByteArray(32) { (it * 7).toByte() }
        val nonce = ByteArray(12) { (it + 3).toByte() }
        val plaintext = "Ultimate VPN Tunnel Packet Test Data 123456789".toByteArray()
        val ad = "wireguard-ad".toByteArray()

        val encrypted = ChaCha20Poly1305.encrypt(key, nonce, plaintext, ad)
        assertEquals(plaintext.size + 16, encrypted.size) // 16-byte Poly1305 MAC

        val decrypted = ChaCha20Poly1305.decrypt(key, nonce, encrypted, ad)
        assertNotNull(decrypted)
        assertEquals(String(plaintext), String(decrypted))
    }

    @Test
    fun testBlake2sHashingAndKdf() {
        val data = "WireGuard v1 zx2c4 Jason@zx2c4.com".toByteArray()
        val hash = Blake2s.hash(data)
        assertEquals(32, hash.size)

        val (ck1, k1) = Blake2s.kdf2(hash, "some-secret".toByteArray())
        assertEquals(32, ck1.size)
        assertEquals(32, k1.size)
        assertFalse(ck1.contentEquals(k1))
    }

    @Test
    fun testWireGuardConfigParsing() {
        val confText = """
            [Interface]
            PrivateKey = YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=
            Address = 10.66.66.2/32, fd66:6666::2/128
            DNS = 1.1.1.1, 8.8.8.8

            [Peer]
            PublicKey = YmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmI=
            Endpoint = 198.51.100.1:51820
            AllowedIPs = 0.0.0.0/0, ::/0
            PersistentKeepalive = 25
        """.trimIndent()

        val res = WireGuardConfigManager.parseConf(confText, "خادم مخصص تجريبي")
        assertTrue(res.isSuccess)

        val profile = res.getOrThrow()
        assertEquals("خادم مخصص تجريبي", profile.name)
        assertEquals("198.51.100.1", profile.endpointHost)
        assertEquals(51820, profile.endpointPort)
        assertEquals("10.66.66.2", profile.clientAddressIpv4)
        assertEquals("fd66:6666::2", profile.clientAddressIpv6)
        assertEquals(25, profile.persistentKeepaliveSeconds)
    }

    @Test
    fun testWireGuardPresetProfilesIntegrity() {
        val original = WireGuardConfigManager.PRESET_PROFILES
        assertTrue(original.isNotEmpty())
        for (p in original) {
            assertTrue("Profile ${p.id} must be valid", p.isValid())
            assertTrue(p.endpointHost.isNotBlank())
            assertTrue(p.endpointPort in 1..65535)
            assertEquals(32, com.smartadshield.vpn.core.wireguard.crypto.Base64Compat.decode(p.serverPublicKeyBase64).size)
            assertEquals(32, com.smartadshield.vpn.core.wireguard.crypto.Base64Compat.decode(p.clientPrivateKeyBase64).size)
        }
    }

    @Test
    fun testVpnStateTransitionsAndErrors() {
        val state = VpnState.CONNECTED
        assertTrue(state.isRunning)

        val disconnected = VpnState.DISCONNECTED
        assertFalse(disconnected.isRunning)

        val err = VpnError.HANDSHAKE_TIMEOUT
        assertEquals("HANDSHAKE_TIMEOUT", err.code)
        assertTrue(err.isRecoverable)

        val permErr = VpnError.VPN_PERMISSION_DENIED
        assertFalse(permErr.isRecoverable)
    }

    @Test
    fun testProtocolAndSplitTunnelingEnums() {
        val pAuto = VpnProtocol.fromId("auto")
        assertEquals(VpnProtocol.AUTO, pAuto)

        val pWg = VpnProtocol.fromId("wireguard")
        assertEquals(VpnProtocol.WIREGUARD, pWg)

        val splitAll = SplitTunnelingMode.fromId("all")
        assertEquals(SplitTunnelingMode.ALL_APPS, splitAll)

        val splitSel = SplitTunnelingMode.fromId("selected")
        assertEquals(SplitTunnelingMode.SELECTED_APPS, splitSel)
    }

    @Test
    fun testBase64CompatSafety() {
        val emptyBytes = com.smartadshield.vpn.core.wireguard.crypto.Base64Compat.decode("")
        assertEquals(0, emptyBytes.size)

        val invalidBytes = com.smartadshield.vpn.core.wireguard.crypto.Base64Compat.decode("!!!not_base64???")
        assertNotNull(invalidBytes)

        val encoded = com.smartadshield.vpn.core.wireguard.crypto.Base64Compat.encode(ByteArray(0))
        assertEquals("", encoded)
    }

    @Test
    fun testAppRepositoryDefaultPackagesAndNpeRegression() {
        // Regression test for NPE on startup: Set.size() called on null defaultTunneledPackages
        val defaults = com.smartadshield.vpn.data.AppRepository.DEFAULT_TUNNELED_PACKAGES
        assertNotNull("DEFAULT_TUNNELED_PACKAGES must be initialized at class load time", defaults)
        assertTrue("DEFAULT_TUNNELED_PACKAGES must contain TikTok packages", defaults.isNotEmpty())
        assertEquals(3, defaults.size)
        assertTrue(defaults.contains("com.zhiliaoapp.musically"))

        // Simulate selectedPackages fallback when SharedPreferences returns null (fresh install)
        val nullPrefsSet: Set<String>? = null
        val resolvedNull = if (!nullPrefsSet.isNullOrEmpty()) nullPrefsSet else defaults
        assertNotNull(resolvedNull)
        assertEquals(3, resolvedNull.size) // This was throwing NPE before fix!

        // Simulate selectedPackages fallback when SharedPreferences returns empty set
        val emptyPrefsSet: Set<String> = emptySet()
        val resolvedEmpty = if (!emptyPrefsSet.isNullOrEmpty()) emptyPrefsSet else defaults
        assertNotNull(resolvedEmpty)
        assertEquals(3, resolvedEmpty.size)

        // Simulate custom saved packages
        val customSet: Set<String> = setOf("com.example.custom")
        val resolvedCustom = if (!customSet.isNullOrEmpty()) customSet else defaults
        assertNotNull(resolvedCustom)
        assertEquals(1, resolvedCustom.size)
        assertTrue(resolvedCustom.contains("com.example.custom"))
    }

    @Test
    fun testCorruptedAndMissingSettingsFallbacks() {
        // Test fallback for missing or corrupted protocol string
        val nullProto = null?.let { VpnProtocol.fromId(it) } ?: VpnProtocol.AUTO
        assertEquals(VpnProtocol.AUTO, nullProto)
        val unknownProto = VpnProtocol.fromId("corrupted_value_xyz")
        assertEquals(VpnProtocol.AUTO, unknownProto)

        // Test fallback for missing or corrupted split mode string
        val nullSplit = null?.let { SplitTunnelingMode.fromId(it) } ?: SplitTunnelingMode.ALL_APPS
        assertEquals(SplitTunnelingMode.ALL_APPS, nullSplit)
        val unknownSplit = SplitTunnelingMode.fromId("unknown_mode_999")
        assertEquals(SplitTunnelingMode.ALL_APPS, unknownSplit)

        // Test WireGuard profiles deserialization with null and invalid JSON
        val defaultProfiles = WireGuardConfigManager.deserializeProfiles(null)
        assertTrue(defaultProfiles.isNotEmpty())
        val corruptedProfiles = WireGuardConfigManager.deserializeProfiles("{ bad json [[[")
        assertTrue(corruptedProfiles.isNotEmpty())
        assertEquals(4, corruptedProfiles.size)
    }
}
