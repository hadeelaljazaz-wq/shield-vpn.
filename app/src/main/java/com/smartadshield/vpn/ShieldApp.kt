package com.smartadshield.vpn

import android.app.Application
import com.wireguard.android.backend.GoBackend
import com.smartadshield.vpn.tunnel.TunnelManager

class ShieldApp : Application() {
    override fun onCreate() {
        super.onCreate()
        TunnelManager.init(this)
        // Android "Always-on VPN" starts GoBackend's VpnService directly; bring the tunnel up.
        GoBackend.setAlwaysOnCallback { TunnelManager.onAlwaysOnStart(this) }
    }
}
