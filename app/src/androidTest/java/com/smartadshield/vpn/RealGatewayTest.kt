package com.smartadshield.vpn

import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.smartadshield.vpn.core.engine.VpnProtocol
import com.smartadshield.vpn.core.engine.VpnState
import com.smartadshield.vpn.tunnel.TunnelEngine
import com.smartadshield.vpn.tunnel.TunnelManager
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Runs the app's real tunnel code (TunnelManager → GoBackend / libxray) on an
 * Android device or emulator against a real gateway. CI passes the gateway's
 * enrollment code and expected exit IP as instrumentation arguments.
 */
@RunWith(AndroidJUnit4::class)
class RealGatewayTest {

    private fun awaitTerminal(timeoutMs: Long): VpnState {
        val end = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < end) {
            val s = TunnelManager.status.value.state
            if (s == VpnState.CONNECTED || s == VpnState.ERROR) return s
            Thread.sleep(500)
        }
        return TunnelManager.status.value.state
    }

    private fun awaitDisconnected() {
        val end = System.currentTimeMillis() + 15000
        while (System.currentTimeMillis() < end && TunnelManager.status.value.state != VpnState.DISCONNECTED) Thread.sleep(300)
    }

    private fun dumpLog(tag: String) = TunnelManager.status.value.log.forEach { Log.i("RealGatewayTest", "[$tag] $it") }

    @Test
    fun wireguardThenXrayCarryTrafficThroughTheGateway() {
        val args = InstrumentationRegistry.getArguments()
        val code = args.getString("enrollCode")
        val expectedIp = args.getString("expectedExitIp")
        assumeTrue("no gateway supplied", !code.isNullOrBlank() && !expectedIp.isNullOrBlank())
        val ctx = InstrumentationRegistry.getInstrumentation().targetContext
        // Bring the app to the foreground: Android forbids background service starts.
        ctx.startActivity(android.content.Intent(ctx, com.smartadshield.vpn.ui.MainActivity::class.java)
            .addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK))
        Thread.sleep(3000)
        TunnelManager.init(ctx)

        val enrolled = runBlocking { TunnelManager.enroll(code!!) }
        dumpLog("enroll")
        enrolled.getOrThrow()

        for ((proto, engine) in listOf(VpnProtocol.WIREGUARD to TunnelEngine.WIREGUARD, VpnProtocol.XRAY_VLESS to TunnelEngine.XRAY_REALITY)) {
            InstrumentationRegistry.getInstrumentation().runOnMainSync { TunnelManager.connect(proto) }
            val state = awaitTerminal(60_000)
            dumpLog(engine.name)
            val st = TunnelManager.status.value
            assertEquals("${engine.name}: ${st.errorAr}", VpnState.CONNECTED, state)
            assertEquals(engine, st.engine)
            assertEquals(expectedIp, st.verifiedPublicIp)
            val speed = runBlocking { TunnelManager.speedTest() }
            Log.i("RealGatewayTest", "RESULT ${engine.name} exit=${st.verifiedPublicIp} country=${st.verifiedCountry} rtt=${st.pingMs}ms $speed")
            TunnelManager.disconnect()
            awaitDisconnected()
        }
    }
}
