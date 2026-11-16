package com.smartadshield.vpn.tunnel

import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.TrafficStats
import android.os.Process
import android.util.Log
import androidx.core.content.ContextCompat
import com.smartadshield.vpn.core.engine.SplitTunnelingMode
import com.smartadshield.vpn.core.engine.VpnProtocol
import com.smartadshield.vpn.core.engine.VpnState
import com.smartadshield.vpn.data.AppRepository
import com.smartadshield.vpn.service.ConnectionService
import com.smartadshield.vpn.service.SmartAdShieldVpnService
import com.smartadshield.vpn.service.XrayVpnService
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Single owner of the real VPN connection.
 *
 * Rules enforced here:
 *  * CONNECTED is published only after (1) a protocol-level proof (WireGuard
 *    handshake timestamp / Xray tunnel up) AND (2) an HTTPS request that went
 *    through the tunnel reports the server's public IP as our exit IP.
 *  * Only one VpnService is active at a time (DNS shield is stopped first).
 *  * Every number shown (ping, bytes, IP, country) is measured.
 */
object TunnelManager {
    private const val TAG = "ShieldTunnel"
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    private lateinit var app: Context
    lateinit var servers: ServerStore
        private set
    private var wg: WireGuardEngine? = null
    private var xray: XrayEngine? = null

    private val _status = MutableStateFlow(TunnelStatus())
    val status: StateFlow<TunnelStatus> = _status.asStateFlow()

    private var connectJob: Job? = null
    private var monitorJob: Job? = null
    private var netCallback: ConnectivityManager.NetworkCallback? = null
    @Volatile private var lastPreference: VpnProtocol = VpnProtocol.AUTO
    @Volatile private var userWantsConnected = false
    private var rxBase = 0L
    private var txBase = 0L
    private val logFmt = SimpleDateFormat("HH:mm:ss", Locale.US)

    @Volatile var adBlockDns: Boolean = true

    fun init(context: Context) {
        if (::app.isInitialized) return
        app = context.applicationContext
        servers = ServerStore(app)
        adBlockDns = app.getSharedPreferences("shield_tunnel", Context.MODE_PRIVATE).getBoolean("adblock_dns", true)
        AppRepository.get(app).serverNameProvider = { servers.active()?.name ?: "" }
    }

    fun setAdBlockDns(on: Boolean) {
        adBlockDns = on
        app.getSharedPreferences("shield_tunnel", Context.MODE_PRIVATE).edit().putBoolean("adblock_dns", on).apply()
    }

    private fun dnsServers(): List<String> =
        if (adBlockDns) listOf("94.140.14.14", "94.140.15.15") // AdGuard DNS (official public ad-blocking resolver)
        else listOf("1.1.1.1", "1.0.0.1")

    // ------------------------------------------------------------------ public API

    fun connect(preference: VpnProtocol) {
        if (preference == VpnProtocol.LOCAL_DNS_SHIELD) return
        lastPreference = preference
        userWantsConnected = true
        connectJob?.cancel()
        monitorJob?.cancel()
        ContextCompat.startForegroundService(app, Intent(app, ConnectionService::class.java))
        connectJob = scope.launch { connectFlow(preference, reconnect = false) }
    }

    fun disconnect(reason: String? = null) {
        userWantsConnected = false
        connectJob?.cancel()
        monitorJob?.cancel()
        unregisterNetworkCallback()
        scope.launch {
            set { it.copy(state = VpnState.DISCONNECTING) }
            stopEngines()
            _status.value = TunnelStatus(
                state = if (reason != null) VpnState.ERROR else VpnState.DISCONNECTED,
                errorAr = reason,
                log = _status.value.log,
            )
            app.stopService(Intent(app, ConnectionService::class.java))
        }
    }

    /** System-initiated start (always-on VPN). */
    fun onAlwaysOnStart(context: Context) {
        init(context)
        if (_status.value.state == VpnState.CONNECTED || connectJob?.isActive == true) return
        connect(lastPreference)
    }

    fun isActive(): Boolean = _status.value.state.let { it != VpnState.DISCONNECTED && it != VpnState.ERROR }

    // ------------------------------------------------------------------ enrollment

    /** Parses the code, stores it encrypted and provisions this device. */
    suspend fun enroll(code: String): Result<ServerEntry> = runCatching {
        val e = EnrollmentCode.parse(code).getOrThrow()
        val entry = servers.addEnrollment(e)
        provision(entry)
    }

    private fun provision(entry: ServerEntry): ServerEntry {
        val e = entry.enrollment ?: return entry
        val kp = servers.keyPairFor(entry.id)
        val p = ProvisioningClient(e).register(kp.publicKey.toBase64())
        val updated = entry.copy(provisioned = p, name = p.name.ifBlank { entry.name })
        servers.update(updated)
        log("تم تسجيل الجهاز لدى الخادم ${p.publicIp} (WireGuard${if (p.xray != null) " + Xray" else ""})")
        return updated
    }

    // ------------------------------------------------------------------ connection flow

    private suspend fun connectFlow(preference: VpnProtocol, reconnect: Boolean) {
        try {
            // One VpnService at a time: stop the local DNS shield if it runs.
            runCatching {
                app.startService(Intent(app, SmartAdShieldVpnService::class.java).setAction(SmartAdShieldVpnService.ACTION_STOP))
            }
            var server = servers.active()
                ?: return fail("لا يوجد خادم حقيقي مضاف. أضف رمز التسجيل (Enrollment) من شاشة الخوادم.")

            set {
                it.copy(
                    state = if (reconnect) VpnState.RECONNECTING else VpnState.CONNECTING,
                    serverName = server.name, errorAr = null, verifiedPublicIp = null, verifiedCountry = null,
                )
            }
            stopEngines()

            if (server.kind == ServerEntry.Kind.ENROLLED) {
                log("طلب إعدادات الاتصال من ${server.enrollment?.apiBase}")
                server = try {
                    provision(server)
                } catch (t: Throwable) {
                    if (server.provisioned != null) {
                        log("تعذر الوصول إلى API (${t.message}) — استخدام الإعدادات المحفوظة")
                        server
                    } else {
                        return fail("تعذر الوصول إلى خادم التسجيل: ${t.message}")
                    }
                }
            }

            val engines = when (preference) {
                VpnProtocol.WIREGUARD -> listOf(TunnelEngine.WIREGUARD)
                VpnProtocol.XRAY_VLESS -> listOf(TunnelEngine.XRAY_REALITY)
                else -> listOfNotNull(TunnelEngine.WIREGUARD, TunnelEngine.XRAY_REALITY.takeIf { server.supportsXray })
            }
            if (TunnelEngine.XRAY_REALITY in engines && !server.supportsXray) {
                return fail("هذا الخادم لا يوفر Xray (ملف WireGuard يدوي أو خادم بدون Xray).")
            }

            var lastErr = "?"
            for (engine in engines) {
                val res = runCatching { tryEngine(engine, server) }
                if (res.isSuccess) {
                    startMonitor(engine, server)
                    return
                }
                lastErr = res.exceptionOrNull()?.let { if (it is CancellationException) throw it else it.message } ?: "?"
                log("${engine.labelAr}: فشل — $lastErr")
                stopEngines()
            }
            fail("فشل الاتصال الحقيقي بالخادم: $lastErr")
        } catch (c: CancellationException) {
            throw c
        } catch (t: Throwable) {
            Log.e(TAG, "connect", t)
            stopEngines()
            fail("خطأ غير متوقع: ${t.message}")
        }
    }

    private suspend fun tryEngine(engine: TunnelEngine, server: ServerEntry) {
        set { it.copy(state = VpnState.CONNECTING, engine = engine) }
        val repo = AppRepository.get(app)
        val split = splitFor(repo)
        when (engine) {
            TunnelEngine.WIREGUARD -> {
                val e = wg ?: WireGuardEngine(app).also { wg = it }
                val cfg = when (server.kind) {
                    ServerEntry.Kind.ENROLLED -> e.buildFromProvisioned(server.provisioned!!, servers.keyPairFor(server.id), dnsServers(), split)
                    ServerEntry.Kind.MANUAL_WG -> e.buildFromWgQuick(server.manualConfig!!, dnsServers(), split)
                }
                log("WireGuard ${e.version()}: تشغيل النفق → ${server.provisioned?.wgEndpointHost ?: "ملف يدوي"}")
                val startedAt = System.currentTimeMillis()
                e.up(cfg)
                set { it.copy(state = VpnState.AUTHENTICATING) }
                // Wait for a real handshake (wireguard-go reports its timestamp).
                var hs = 0L
                for (i in 0 until 24) { // up to ~12 s
                    delay(500)
                    hs = e.stats()?.lastHandshakeMs ?: 0L
                    if (hs >= startedAt - 1000) break
                }
                if (hs < startedAt - 1000) {
                    throw IllegalStateException("لم تكتمل مصافحة WireGuard خلال 12 ثانية (UDP محجوب أو المفتاح غير مسجل)")
                }
                log("مصافحة WireGuard ناجحة")
                set { it.copy(state = VpnState.VERIFYING_CONNECTIVITY, lastHandshakeMs = hs) }
                verifyExit(NetProbe(), server)
            }
            TunnelEngine.XRAY_REALITY -> {
                val x = server.provisioned?.xray ?: throw IllegalStateException("لا توجد بيانات Xray")
                val e = xray ?: XrayEngine(app).also { xray = it }
                log("Xray ${e.version()}: VLESS-REALITY → ${x.address}:${x.port} (SNI ${x.sni})")
                e.start(x, XrayVpnService.Request(dnsServers(), split.include, split.exclude))
                set { it.copy(state = VpnState.VERIFYING_CONNECTIVITY) }
                verifyExit(NetProbe.socks(e.socksPort), server)
            }
        }
        rxBase = TrafficStats.getUidRxBytes(Process.myUid())
        txBase = TrafficStats.getUidTxBytes(Process.myUid())
    }

    /** Proof that traffic exits through the server: exit IP must be the server's public IP. */
    private suspend fun verifyExit(probe: NetProbe, server: ServerEntry) {
        var exit: NetProbe.Exit? = null
        var err: Throwable? = null
        for (i in 0 until 3) {
            val r = probe.exitInfo()
            if (r.isSuccess) { exit = r.getOrNull(); break }
            err = r.exceptionOrNull()
            delay(1000)
        }
        val ex = exit ?: throw IllegalStateException("لا يوجد اتصال إنترنت عبر النفق: ${err?.message}")
        val expected = server.provisioned?.publicIp ?: server.enrollment?.serverIp
        if (expected != null && ex.ip != expected) {
            throw IllegalStateException("عنوان الخروج ${ex.ip} لا يطابق عنوان الخادم $expected — البيانات لا تمر عبر الخادم")
        }
        if (expected == null && server.lastVerifiedIp == null) {
            log("ملف يدوي: عنوان الخروج ${ex.ip} (لا يوجد عنوان متوقع للمقارنة)")
        }
        val ping = probe.tcpRttMs()
        servers.update(server.copy(lastVerifiedCountry = ex.country, lastVerifiedIp = ex.ip))
        log("تم التحقق: IP الخروج ${ex.ip} (${ex.country ?: "?"}) — زمن RTT ${ping ?: "?"}ms")
        set {
            it.copy(
                state = VpnState.CONNECTED,
                serverIp = expected ?: ex.ip,
                verifiedPublicIp = ex.ip,
                verifiedCountry = ex.country,
                connectedSinceMs = if (it.connectedSinceMs > 0 && it.state == VpnState.RECONNECTING) it.connectedSinceMs else System.currentTimeMillis(),
                pingMs = ping,
                internetOk = true,
                errorAr = null,
            )
        }
    }

    private fun splitFor(repo: AppRepository): WireGuardEngine.Split {
        val self = app.packageName
        return when (repo.splitTunnelingMode.value) {
            // Our package is added so that verification requests use the tunnel too.
            SplitTunnelingMode.SELECTED_APPS -> WireGuardEngine.Split(repo.selectedPackages() + self, emptySet())
            SplitTunnelingMode.EXCLUDED_APPS -> WireGuardEngine.Split(emptySet(), repo.excludedPackages() - self)
            SplitTunnelingMode.ALL_APPS -> WireGuardEngine.Split(emptySet(), emptySet())
        }
    }

    // ------------------------------------------------------------------ monitoring & reconnection

    private fun startMonitor(engine: TunnelEngine, server: ServerEntry) {
        registerNetworkCallback()
        monitorJob?.cancel()
        monitorJob = scope.launch {
            var failures = 0
            var tick = 0
            while (isActive) {
                delay(5000)
                tick++
                val rx = TrafficStats.getUidRxBytes(Process.myUid())
                val tx = TrafficStats.getUidTxBytes(Process.myUid())
                var healthy = true
                when (engine) {
                    TunnelEngine.WIREGUARD -> {
                        val st = wg?.stats()
                        if (st != null) {
                            set { it.copy(rxBytes = st.rx, txBytes = st.tx, lastHandshakeMs = st.lastHandshakeMs) }
                            // wireguard-go re-handshakes every 2 min; >3 min without one means the path is dead.
                            if (System.currentTimeMillis() - st.lastHandshakeMs > 180_000) healthy = false
                        } else healthy = false
                    }
                    TunnelEngine.XRAY_REALITY -> {
                        // Xray runs in our process, so our UID's counters are the encrypted tunnel traffic.
                        set { it.copy(rxBytes = rx - rxBase, txBytes = tx - txBase) }
                        if (xray?.isRunning() != true) healthy = false
                    }
                }
                // Active end-to-end probe every 30 s.
                if (healthy && tick % 6 == 0) {
                    val probe = if (engine == TunnelEngine.XRAY_REALITY) NetProbe.socks(xray?.socksPort ?: 0) else NetProbe()
                    val ok = probe.exitInfo(6000).isSuccess
                    val ping = if (ok) probe.tcpRttMs() else null
                    set { it.copy(internetOk = ok, pingMs = ping ?: it.pingMs) }
                    if (!ok) healthy = false
                }
                failures = if (healthy) 0 else failures + 1
                if (failures >= 2 && userWantsConnected) {
                    log("فقدان الاتصال عبر النفق — إعادة الاتصال")
                    reconnect()
                    return@launch
                }
            }
        }
    }

    private fun reconnect() {
        if (!userWantsConnected) return
        connectJob?.cancel()
        connectJob = scope.launch {
            var attempt = 0
            while (userWantsConnected && isActive) {
                connectFlow(lastPreference, reconnect = true)
                if (_status.value.state == VpnState.CONNECTED) return@launch
                attempt++
                val wait = minOf(60_000L, 2_000L shl minOf(attempt, 5))
                log("إعادة المحاولة بعد ${wait / 1000} ثانية")
                set { it.copy(state = VpnState.RECONNECTING) }
                delay(wait)
            }
        }
    }

    private fun registerNetworkCallback() {
        if (netCallback != null) return
        val cm = app.getSystemService(ConnectivityManager::class.java) ?: return
        val req = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build()
        var current: Network? = null
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                val prev = current
                current = network
                if (prev != null && prev != network && _status.value.state == VpnState.CONNECTED) {
                    log("تغيّرت الشبكة (Wi-Fi/بيانات) — التحقق من النفق")
                    when (_status.value.engine) {
                        // wireguard-go roams by itself; just re-verify soon via the monitor.
                        TunnelEngine.WIREGUARD -> Unit
                        // Xray's TCP session is bound to the old network: rebuild it.
                        TunnelEngine.XRAY_REALITY -> reconnect()
                        null -> Unit
                    }
                }
            }
        }
        netCallback = cb
        runCatching { cm.registerNetworkCallback(req, cb) }
    }

    private fun unregisterNetworkCallback() {
        val cb = netCallback ?: return
        netCallback = null
        runCatching { app.getSystemService(ConnectivityManager::class.java)?.unregisterNetworkCallback(cb) }
    }

    // ------------------------------------------------------------------ speed test (real)

    suspend fun speedTest(): String {
        val st = _status.value
        val probe = when {
            st.state == VpnState.CONNECTED && st.engine == TunnelEngine.XRAY_REALITY -> NetProbe.socks(xray?.socksPort ?: 0)
            else -> NetProbe()
        }
        val path = if (st.state == VpnState.CONNECTED) "عبر ${st.engine?.labelAr} (${st.serverName})" else "بدون VPN"
        val rtt = probe.tcpRttMs()
        val dl = probe.downloadMbps()
        val line = "سرعة $path: تنزيل ${dl.getOrNull()?.let { "%.1f".format(it) } ?: "فشل (${dl.exceptionOrNull()?.message})"} Mbps • RTT ${rtt ?: "?"} ms"
        log(line)
        return line
    }

    // ------------------------------------------------------------------ helpers

    private fun stopEngines() {
        runCatching { wg?.down() }
        runCatching { xray?.stop() }
    }

    private fun fail(msg: String) {
        log("خطأ: $msg")
        set { it.copy(state = VpnState.ERROR, errorAr = msg, internetOk = null, verifiedPublicIp = null) }
        if (!userWantsConnected) app.stopService(Intent(app, ConnectionService::class.java))
    }

    private inline fun set(f: (TunnelStatus) -> TunnelStatus) = _status.update(f)

    fun log(line: String) {
        Log.i(TAG, line)
        val stamped = "${logFmt.format(Date())}  $line"
        _status.update { it.copy(log = (it.log + stamped).takeLast(80)) }
    }
}
