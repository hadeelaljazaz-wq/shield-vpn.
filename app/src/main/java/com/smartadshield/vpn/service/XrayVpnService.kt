package com.smartadshield.vpn.service

import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import com.smartadshield.vpn.tunnel.TunnelManager
import com.smartadshield.vpn.tunnel.XrayConfigBuilder
import java.util.concurrent.CompletableFuture

/**
 * TUN for the Xray engine. Our own package is excluded from the VPN so Xray's
 * sockets (running in this process) reach the server directly; every other
 * app's traffic enters the TUN and is handled by Xray's TUN inbound.
 */
class XrayVpnService : VpnService() {

    data class Request(
        val dnsServers: List<String>,
        val includeApps: Set<String>,
        val excludeApps: Set<String>,
    )

    private var pfd: ParcelFileDescriptor? = null

    override fun onCreate() {
        super.onCreate()
        instance.complete(this)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent == null || intent.action == SERVICE_INTERFACE) {
            // Started by the system for always-on VPN.
            TunnelManager.onAlwaysOnStart(this)
        }
        return START_NOT_STICKY
    }

    /** Establishes the TUN and returns its fd (owned by this service). */
    fun establish(req: Request): ParcelFileDescriptor {
        closeTun()
        val b = Builder()
            .setSession("Smart Ad Shield (Xray)")
            .setMtu(XrayConfigBuilder.TUN_MTU)
            .addAddress("10.89.0.2", 30)
            .addRoute("0.0.0.0", 0)
            .setBlocking(false)
        runCatching { b.addAddress("fd89::2", 126); b.addRoute("::", 0) }
        req.dnsServers.forEach { runCatching { b.addDnsServer(it) } }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) b.setMetered(false)
        if (req.includeApps.isNotEmpty()) {
            req.includeApps.filter { it != packageName }.forEach { runCatching { b.addAllowedApplication(it) } }
        } else {
            b.addDisallowedApplication(packageName)
            req.excludeApps.forEach { runCatching { b.addDisallowedApplication(it) } }
        }
        val fd = b.establish() ?: throw IllegalStateException("VPN permission revoked or TUN unavailable")
        pfd = fd
        return fd
    }

    fun closeTun() {
        runCatching { pfd?.close() }
        pfd = null
    }

    override fun onRevoke() {
        TunnelManager.disconnect("ألغى النظام إذن VPN (تطبيق VPN آخر؟)")
        super.onRevoke()
    }

    override fun onDestroy() {
        closeTun()
        instance = CompletableFuture()
        super.onDestroy()
    }

    companion object {
        @Volatile var instance: CompletableFuture<XrayVpnService> = CompletableFuture()
    }
}
