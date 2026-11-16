package com.smartadshield.vpn.tunnel

import android.content.Context
import android.content.Intent
import com.smartadshield.vpn.service.XrayVpnService
import java.net.ServerSocket
import java.util.concurrent.TimeUnit

/** Xray-core (libxray.aar, built from XTLS/Xray-core by CI) running in-process on the VpnService TUN fd. */
class XrayEngine(private val context: Context) {
    @Volatile var socksPort: Int = 0
        private set

    fun start(x: XrayParams, req: XrayVpnService.Request) {
        stop()
        context.startService(Intent(context, XrayVpnService::class.java))
        val svc = XrayVpnService.instance.get(5, TimeUnit.SECONDS)
        val pfd = svc.establish(req)
        socksPort = ServerSocket(0).use { it.localPort }
        val json = XrayConfigBuilder.build(x, socksPort)
        try {
            libxray.Libxray.start(json, pfd.fd.toLong())
        } catch (t: Throwable) {
            svc.closeTun()
            throw IllegalStateException("Xray: ${t.message}", t)
        }
    }

    fun stop() {
        runCatching { libxray.Libxray.stop() }
        runCatching {
            if (XrayVpnService.instance.isDone) {
                val svc = XrayVpnService.instance.getNow(null)
                svc?.closeTun()
                svc?.stopSelf()
            }
        }
        socksPort = 0
    }

    fun isRunning(): Boolean = runCatching { libxray.Libxray.isRunning() }.getOrDefault(false)

    fun version(): String = runCatching { libxray.Libxray.version() }.getOrDefault("?")
}
