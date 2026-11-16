package com.smartadshield.vpn.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import com.smartadshield.vpn.R
import com.smartadshield.vpn.core.engine.VpnState
import com.smartadshield.vpn.tunnel.TunnelManager
import com.smartadshield.vpn.tunnel.TunnelStatus
import com.smartadshield.vpn.ui.MainActivity
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch

/** Foreground service keeping the real tunnel alive and showing its measured state. */
class ConnectionService : Service() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        TunnelManager.init(this)
        val nm = getSystemService(NotificationManager::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            nm.createNotificationChannel(
                NotificationChannel(CHANNEL, "اتصال VPN", NotificationManager.IMPORTANCE_LOW).apply { setShowBadge(false) }
            )
        }
        val n = build(TunnelManager.status.value)
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(ID, n)
        }
        scope.launch {
            TunnelManager.status.collectLatest { st -> runCatching { nm.notify(ID, build(st)) } }
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_DISCONNECT) {
            TunnelManager.disconnect()
        }
        return START_NOT_STICKY
    }

    private fun build(st: TunnelStatus): Notification {
        val open = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
        val stop = PendingIntent.getService(
            this, 1, Intent(this, ConnectionService::class.java).setAction(ACTION_DISCONNECT), PendingIntent.FLAG_IMMUTABLE
        )
        val text = when (st.state) {
            VpnState.CONNECTED -> "${st.engine?.labelAr} • IP ${st.verifiedPublicIp} (${st.verifiedCountry ?: "?"})"
            VpnState.ERROR -> st.errorAr ?: "خطأ"
            else -> st.serverName ?: ""
        }
        return NotificationCompat.Builder(this, CHANNEL)
            .setSmallIcon(R.drawable.ic_shield)
            .setContentTitle(st.state.labelAr)
            .setContentText(text)
            .setContentIntent(open)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .addAction(0, "قطع الاتصال", stop)
            .build()
    }

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }

    companion object {
        const val ACTION_DISCONNECT = "com.smartadshield.vpn.action.DISCONNECT"
        private const val CHANNEL = "shield_tunnel"
        private const val ID = 2001
    }
}
