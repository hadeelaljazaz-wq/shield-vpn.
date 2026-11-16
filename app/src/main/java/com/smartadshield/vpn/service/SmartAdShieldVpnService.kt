package com.smartadshield.vpn.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.system.OsConstants
import androidx.core.app.NotificationCompat
import com.smartadshield.vpn.R
import com.smartadshield.vpn.core.AppInfo
import com.smartadshield.vpn.core.DnsPacketProcessor
import com.smartadshield.vpn.core.dns.SocketProtector
import com.smartadshield.vpn.core.dns.UpstreamResolver
import com.smartadshield.vpn.core.engine.SplitTunnelingMode
import com.smartadshield.vpn.core.engine.VpnEngineManager
import com.smartadshield.vpn.core.engine.VpnError
import com.smartadshield.vpn.core.engine.VpnProtocol
import com.smartadshield.vpn.core.engine.VpnState
import com.smartadshield.vpn.core.net.ParsedPacket
import com.smartadshield.vpn.data.AppRepository
import com.smartadshield.vpn.ui.MainActivity
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.Socket
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Production-grade Multi-Protocol Android VPN Service.
 *
 * Supports:
 * - 100% Full Encrypted Tunneling (0.0.0.0/0, ::/0) through Remote VPN Gateway.
 * - Split Tunneling (All Apps, Selected Apps only, or Excluded Apps).
 * - Real WireGuard Noise_IKpsk2 Transport & Xray / Anti-Censorship bypass.
 * - In-Tunnel DNS Ad Filtering (Smart Ad Shield) without breaking YouTube/TikTok streaming.
 * - Socket protection via VpnService.protect() and binding to active physical network.
 * - Strict 10-state connection machine with actual external connectivity verification.
 */
class SmartAdShieldVpnService : VpnService() {

    private lateinit var repo: AppRepository
    private var tunPfd: ParcelFileDescriptor? = null
    private var readerThread: Thread? = null
    private var processor: DnsPacketProcessor? = null
    private var engineManager: VpnEngineManager? = null
    private var socketProtector: SocketProtector? = null
    private var upstreamResolver: UpstreamResolver? = null
    private val running = AtomicBoolean(false)

    @Volatile
    private var activePhysicalNetwork: Network? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    private val writeLock = Any()

    override fun onCreate() {
        super.onCreate()
        repo = AppRepository.get(this)
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopVpnTunnel()
                stopSelf()
                return START_NOT_STICKY
            }
            ACTION_RELOAD -> {
                if (running.get()) {
                    rebuildTunnelInterface()
                }
                return START_STICKY
            }
            else -> {
                startForegroundCompat()
                if (running.compareAndSet(false, true)) {
                    startVpnTunnel()
                }
                return START_STICKY
            }
        }
    }

    private fun startForegroundCompat() {
        val notification = buildNotification()
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(
                NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
            )
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    private fun startVpnTunnel() {
        repo.onVpnStateChanged(VpnState.PREPARING, VpnError.NONE)

        val protector = object : SocketProtector {
            override fun protect(socket: DatagramSocket): Boolean {
                val ok = this@SmartAdShieldVpnService.protect(socket)
                runCatching { activePhysicalNetwork?.bindSocket(socket) }
                return ok
            }

            override fun protect(socket: Socket): Boolean {
                val ok = this@SmartAdShieldVpnService.protect(socket)
                runCatching { activePhysicalNetwork?.bindSocket(socket) }
                return ok
            }
        }

        val resolver = UpstreamResolver(protector, timeoutMs = 2500)
        socketProtector = protector
        upstreamResolver = resolver

        updatePhysicalNetworkAndServers()
        registerUnderlyingNetworkCallback()

        repo.engineChangeListener = { newEngine ->
            processor?.engine = newEngine
            updateNotification()
        }
        repo.vpnConfigChangeListener = {
            if (running.get()) {
                processor?.config = repo.currentProcessorConfig()
                rebuildTunnelInterface()
            }
        }

        establishAndStartLoop()
    }

    @Synchronized
    private fun rebuildTunnelInterface() {
        stopReaderAndCloseDescriptor()
        if (running.get()) {
            establishAndStartLoop()
        }
    }

    private fun establishAndStartLoop() {
        val resolver = upstreamResolver ?: return
        val protector = socketProtector ?: SocketProtector.None
        val profile = repo.activeWireGuardProfile()
        val protocol = repo.activeProtocol.value
        val splitMode = repo.splitTunnelingMode.value

        val builder = Builder()
            .setSession("Ultimate VPN Secure Tunnel")
            .setMtu(1420)
            .addAddress("10.66.66.2", 24)
            .addDnsServer("1.1.1.1")
            .addDnsServer("8.8.8.8")
            .addAddress("fd66:6666::2", 64)
            .allowFamily(OsConstants.AF_INET)
            .allowFamily(OsConstants.AF_INET6)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            builder.setMetered(false)
        }

        // Apply Routing: Full VPN vs DNS Only
        if (protocol == VpnProtocol.LOCAL_DNS_SHIELD) {
            builder.addAddress(VIRTUAL_CLIENT_IPV4, 30)
            builder.addDnsServer(VIRTUAL_DNS_IPV4)
            builder.addRoute(VIRTUAL_DNS_IPV4, 32)
            builder.addRoute(VIRTUAL_DNS_IPV6, 128)
        } else {
            // Real Full VPN Tunneling (0.0.0.0/0 & ::/0)
            builder.addRoute("0.0.0.0", 0)
            runCatching { builder.addRoute("::", 0) }
        }

        // Apply Split Tunneling safely (Never mix allowed and disallowed on same builder)
        when (splitMode) {
            SplitTunnelingMode.SELECTED_APPS -> {
                val selected = repo.selectedPackages()
                if (selected.isNotEmpty()) {
                    for (pkg in selected) {
                        runCatching { builder.addAllowedApplication(pkg) }
                    }
                }
            }
            SplitTunnelingMode.EXCLUDED_APPS -> {
                val excluded = repo.excludedPackages()
                for (pkg in excluded) {
                    runCatching { builder.addDisallowedApplication(pkg) }
                }
            }
            SplitTunnelingMode.ALL_APPS -> {
                // All device apps tunneled
            }
        }

        val pfd = try {
            builder.establish()
        } catch (e: Exception) {
            null
        }

        if (pfd == null) {
            running.set(false)
            repo.onVpnStateChanged(VpnState.ERROR, VpnError.TUN_ESTABLISH_FAILED)
            stopSelf()
            return
        }
        tunPfd = pfd

        val outStream = FileOutputStream(pfd.fileDescriptor)
        val vdnsSet = setOf(
            InetAddress.getByName(VIRTUAL_DNS_IPV4),
            InetAddress.getByName(VIRTUAL_DNS_IPV6),
            InetAddress.getByName("1.1.1.1"),
            InetAddress.getByName("8.8.8.8"),
        )

        val proc = DnsPacketProcessor(
            engine = repo.engine,
            cache = repo.dnsCache,
            upstream = resolver,
            virtualDnsAddresses = vdnsSet,
            writer = { bytes ->
                synchronized(writeLock) {
                    runCatching { outStream.write(bytes) }
                }
            },
            listener = { event ->
                repo.onQueryEvent(event)
            },
            appResolver = { pkt -> resolvePacketOwner(pkt) },
            config = repo.currentProcessorConfig(),
            dpiBypass = null,
        )
        processor = proc

        val manager = VpnEngineManager(
            socketProtector = protector,
            tunWriter = { decryptedPacket ->
                synchronized(writeLock) {
                    runCatching { outStream.write(decryptedPacket) }
                }
            },
            onStateChanged = { state, error ->
                repo.onVpnStateChanged(state, error)
                updateNotification()
            }
        )
        manager.dnsProcessor = proc
        engineManager = manager

        manager.start(profile, protocol)

        val inStream = FileInputStream(pfd.fileDescriptor)
        val thread = Thread({
            val buf = ByteArray(16384)
            while (running.get() && !Thread.currentThread().isInterrupted) {
                val n = try {
                    inStream.read(buf)
                } catch (_: Exception) {
                    break
                }
                if (n < 0) break
                if (n > 0) {
                    manager.handleTunPacket(buf, n)
                }
            }
        }, "vpn-tun-reader").apply {
            isDaemon = true
            start()
        }
        readerThread = thread
    }

    private fun resolvePacketOwner(p: ParsedPacket): AppInfo? {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return null
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager ?: return null
        val proto = when (p.protocol) {
            17 -> OsConstants.IPPROTO_UDP
            6 -> OsConstants.IPPROTO_TCP
            else -> return null
        }
        return try {
            val srcAddr = InetAddress.getByAddress(p.src)
            val dstAddr = InetAddress.getByAddress(p.dst)
            val uid = cm.getConnectionOwnerUid(
                proto,
                java.net.InetSocketAddress(srcAddr, p.srcPort),
                java.net.InetSocketAddress(dstAddr, p.dstPort)
            )
            if (uid > 0) repo.resolveUid(uid) else null
        } catch (_: Exception) {
            null
        }
    }

    private fun stopReaderAndCloseDescriptor() {
        readerThread?.interrupt()
        readerThread = null
        engineManager?.stop()
        engineManager = null
        processor?.shutdown()
        processor = null
        runCatching { tunPfd?.close() }
        tunPfd = null
    }

    private fun stopVpnTunnel() {
        running.set(false)
        unregisterUnderlyingNetworkCallback()
        stopReaderAndCloseDescriptor()
        repo.onVpnStateChanged(VpnState.DISCONNECTED, VpnError.NONE)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            stopForeground(STOP_FOREGROUND_REMOVE)
        } else {
            @Suppress("DEPRECATION")
            stopForeground(true)
        }
    }

    override fun onRevoke() {
        stopVpnTunnel()
        super.onRevoke()
    }

    override fun onDestroy() {
        stopVpnTunnel()
        super.onDestroy()
    }

    private fun updatePhysicalNetworkAndServers() {
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager ?: return
        val net = cm.activeNetwork
        activePhysicalNetwork = net
        if (net != null) {
            val lp = cm.getLinkProperties(net)
            val servers = lp?.dnsServers ?: emptyList()
            if (repo.usePublicUpstreamDns || servers.isEmpty()) {
                upstreamResolver?.servers = listOf(
                    InetAddress.getByName("1.1.1.1"),
                    InetAddress.getByName("8.8.8.8"),
                    InetAddress.getByName("9.9.9.9"),
                )
            } else {
                upstreamResolver?.servers = servers
            }
            repo.updateNetworkInfo(
                networkName = lp?.interfaceName ?: "متصل",
                servers = upstreamResolver?.servers?.mapNotNull { it.hostAddress } ?: emptyList()
            )
        }
    }

    private fun registerUnderlyingNetworkCallback() {
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager ?: return
        val req = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build()

        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                activePhysicalNetwork = network
                setUnderlyingNetworks(arrayOf(network))
                updatePhysicalNetworkAndServers()
                engineManager?.onNetworkChanged(network)
            }

            override fun onLost(network: Network) {
                if (activePhysicalNetwork == network) {
                    activePhysicalNetwork = null
                    engineManager?.onNetworkLost()
                }
            }

            override fun onLinkPropertiesChanged(network: Network, linkProperties: LinkProperties) {
                if (activePhysicalNetwork == network) {
                    updatePhysicalNetworkAndServers()
                }
            }
        }
        networkCallback = cb
        runCatching { cm.registerNetworkCallback(req, cb) }
    }

    private fun unregisterUnderlyingNetworkCallback() {
        val cb = networkCallback ?: return
        networkCallback = null
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager ?: return
        runCatching { cm.unregisterNetworkCallback(cb) }
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val nm = getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager ?: return
            val ch = NotificationChannel(
                CHANNEL_ID,
                "خدمة Ultimate VPN المشفرة",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "إشعار تشغيل نفق الـ VPN المشفر وحماية الاتصال"
                setShowBadge(false)
            }
            nm.createNotificationChannel(ch)
        }
    }

    private fun buildNotification(): Notification {
        val openIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val stopIntent = PendingIntent.getService(
            this,
            1,
            Intent(this, SmartAdShieldVpnService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val st = repo.stats.value
        val state = repo.vpnState.value
        val server = repo.activeWireGuardProfile().name
        val title = "Ultimate VPN: ${state.labelAr}"
        val text = "السيرفر: $server | محجوب: ${st.blockedQueries} | القواعد: ${st.totalActiveRules}"

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_shield)
            .setContentTitle(title)
            .setContentText(text)
            .setContentIntent(openIntent)
            .setOngoing(true)
            .addAction(0, "قطع الاتصال", stopIntent)
            .build()
    }

    private fun updateNotification() {
        if (!running.get()) return
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager ?: return
        runCatching { nm.notify(NOTIFICATION_ID, buildNotification()) }
    }

    companion object {
        const val ACTION_START = "com.smartadshield.vpn.action.START"
        const val ACTION_STOP = "com.smartadshield.vpn.action.STOP"
        const val ACTION_RELOAD = "com.smartadshield.vpn.action.RELOAD"

        const val VIRTUAL_CLIENT_IPV4 = "10.111.222.1"
        const val VIRTUAL_DNS_IPV4 = "10.111.222.53"
        const val VIRTUAL_CLIENT_IPV6 = "fd66:6164:7368::1"
        const val VIRTUAL_DNS_IPV6 = "fd66:6164:7368::53"

        private const val CHANNEL_ID = "ultimate_vpn_channel"
        private const val NOTIFICATION_ID = 1001
    }
}
