package com.smartadshield.vpn.data

import android.content.Context
import android.content.SharedPreferences
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.os.Build
import android.provider.Settings
import com.smartadshield.vpn.core.AppInfo
import com.smartadshield.vpn.core.ProcessorConfig
import com.smartadshield.vpn.core.QueryEvent
import com.smartadshield.vpn.core.dns.BlockStyle
import com.smartadshield.vpn.core.dns.DnsCache
import com.smartadshield.vpn.core.filter.AppMode
import com.smartadshield.vpn.core.filter.CompiledList
import com.smartadshield.vpn.core.filter.DomainHashSet
import com.smartadshield.vpn.core.filter.EngineOptions
import com.smartadshield.vpn.core.filter.FilterEngine
import com.smartadshield.vpn.core.filter.FilterListParser
import com.smartadshield.vpn.core.filter.NamedList
import com.smartadshield.vpn.core.filter.ProtectionSets
import com.smartadshield.vpn.core.engine.SplitTunnelingMode
import com.smartadshield.vpn.core.engine.VpnError
import com.smartadshield.vpn.core.engine.VpnProtocol
import com.smartadshield.vpn.core.engine.VpnState
import com.smartadshield.vpn.core.video.VideoCompatibilityMonitor
import com.smartadshield.vpn.core.video.VideoIncident
import com.smartadshield.vpn.core.wireguard.TunnelStats
import com.smartadshield.vpn.core.wireguard.WireGuardConfigManager
import com.smartadshield.vpn.core.wireguard.WireGuardProfile
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import org.json.JSONArray
import org.json.JSONObject
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.URL
import java.util.Collections
import java.util.concurrent.atomic.AtomicLong

data class FilterSubscription(
    val id: String,
    val name: String,
    val url: String,
    val description: String,
    val enabled: Boolean,
    val ruleCount: Int = 0,
    val lastUpdated: Long = 0L,
    val lastError: String? = null,
)

data class PrivateDnsStatus(
    val mode: String, // "off", "opportunistic", "hostname", "unknown"
    val specifier: String?,
    val isActiveConflict: Boolean,
    val summaryAr: String,
    val detailAr: String,
)

data class VpnStats(
    val running: Boolean = false,
    val connectedSince: Long = 0L,
    val totalQueries: Long = 0L,
    val blockedQueries: Long = 0L,
    val cachedQueries: Long = 0L,
    val trackerBlocked: Long = 0L,
    val protectedVideoQueries: Long = 0L,
    val protectedRecommendationQueries: Long = 0L,
    val upstreamServers: List<String> = emptyList(),
    val activeNetworkName: String = "غير متصل",
    val totalActiveRules: Int = 0,
    val cacheSize: Int = 0,
    val lastLatencyMs: Long = 0L,
    val wireGuardServerName: String = "ألمانيا - فرانكفورت",
    val wireGuardStatus: String = "غير متصل",
    val tunneledAppsCount: Int = 3,
    val vpnState: VpnState = VpnState.DISCONNECTED,
    val vpnError: VpnError = VpnError.NONE,
    val verifiedPublicIp: String? = null,
    val activeProtocol: VpnProtocol = VpnProtocol.AUTO,
    val splitMode: SplitTunnelingMode = SplitTunnelingMode.ALL_APPS,
)

data class InstalledAppItem(
    val uid: Int,
    val packageName: String,
    val label: String,
    val isSystem: Boolean,
    val mode: AppMode,
    val isRecommendedCompat: Boolean,
)

/**
 * Singleton repository coordinating filter engine, preferences, live statistics, query log,
 * per-app modes, and remote filter subscriptions.
 */
class AppRepository private constructor(private val context: Context) {

    val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val prefs: SharedPreferences =
        context.getSharedPreferences("smart_ad_shield_prefs", Context.MODE_PRIVATE)

    val dnsCache = DnsCache(maxEntries = 2048)
    val videoMonitor = VideoCompatibilityMonitor()

    private val totalQueriesCount = AtomicLong(0)
    private val blockedQueriesCount = AtomicLong(0)
    private val cachedQueriesCount = AtomicLong(0)
    private val trackerBlockedCount = AtomicLong(0)
    private val videoProtectedCount = AtomicLong(0)
    private val recProtectedCount = AtomicLong(0)

    private val _vpnRunning = MutableStateFlow(false)
    val vpnRunning: StateFlow<Boolean> = _vpnRunning.asStateFlow()

    private val _vpnState = MutableStateFlow(VpnState.DISCONNECTED)
    val vpnState: StateFlow<VpnState> = _vpnState.asStateFlow()

    private val _lastVpnError = MutableStateFlow(VpnError.NONE)
    val lastVpnError: StateFlow<VpnError> = _lastVpnError.asStateFlow()

    private val _activeProtocol = MutableStateFlow(VpnProtocol.AUTO)
    val activeProtocol: StateFlow<VpnProtocol> = _activeProtocol.asStateFlow()

    private val _splitTunnelingMode = MutableStateFlow(SplitTunnelingMode.ALL_APPS)
    val splitTunnelingMode: StateFlow<SplitTunnelingMode> = _splitTunnelingMode.asStateFlow()

    private val _verifiedPublicIp = MutableStateFlow<String?>(null)
    val verifiedPublicIp: StateFlow<String?> = _verifiedPublicIp.asStateFlow()

    private val _selectedPackages = MutableStateFlow<Set<String>>(emptySet())
    val selectedPackagesFlow: StateFlow<Set<String>> = _selectedPackages.asStateFlow()

    private val _stats = MutableStateFlow(VpnStats())
    val stats: StateFlow<VpnStats> = _stats.asStateFlow()

    private val queryLogBuffer = ArrayDeque<QueryEvent>(500)
    private val _queryLog = MutableStateFlow<List<QueryEvent>>(emptyList())
    val queryLog: StateFlow<List<QueryEvent>> = _queryLog.asStateFlow()

    private val _videoIncidents = MutableStateFlow<List<VideoIncident>>(emptyList())
    val videoIncidents: StateFlow<List<VideoIncident>> = _videoIncidents.asStateFlow()

    private val _wireGuardStats = MutableStateFlow<TunnelStats?>(null)
    val wireGuardStats: StateFlow<TunnelStats?> = _wireGuardStats.asStateFlow()

    private val _subscriptions = MutableStateFlow<List<FilterSubscription>>(emptyList())
    val subscriptions: StateFlow<List<FilterSubscription>> = _subscriptions.asStateFlow()

    private val _userAllow = MutableStateFlow<Set<String>>(emptySet())
    val userAllow: StateFlow<Set<String>> = _userAllow.asStateFlow()

    private val _userBlock = MutableStateFlow<Set<String>>(emptySet())
    val userBlock: StateFlow<Set<String>> = _userBlock.asStateFlow()

    private val _appModes = MutableStateFlow<Map<String, AppMode>>(emptyMap())
    val appModes: StateFlow<Map<String, AppMode>> = _appModes.asStateFlow()

    @Volatile
    var engine: FilterEngine = FilterEngine.EMPTY
        private set

    var engineChangeListener: ((FilterEngine) -> Unit)? = null
    var vpnConfigChangeListener: (() -> Unit)? = null

    private var confirmedAdsSet: DomainHashSet = DomainHashSet.EMPTY
    private var trackersSet: DomainHashSet = DomainHashSet.EMPTY
    private var dnsBypassSet: DomainHashSet = DomainHashSet.EMPTY
    private val compiledRemoteLists = Collections.synchronizedMap(LinkedHashMap<String, NamedList>())

    private val uidAppCache = Collections.synchronizedMap(HashMap<Int, AppInfo>())

    @Volatile
    private var connectedSinceMs: Long = 0L

    @Volatile
    private var currentUpstreams: List<String> = emptyList()

    @Volatile
    private var currentNetworkLabel: String = "الشبكة الافتراضية"

    @Volatile
    private var lastLatency: Long = 0L

    init {
        totalQueriesCount.set(prefs.getLong("stat_total", 0L))
        blockedQueriesCount.set(prefs.getLong("stat_blocked", 0L))
        cachedQueriesCount.set(prefs.getLong("stat_cached", 0L))
        trackerBlockedCount.set(prefs.getLong("stat_tracker", 0L))
        videoProtectedCount.set(prefs.getLong("stat_video_prot", 0L))
        recProtectedCount.set(prefs.getLong("stat_rec_prot", 0L))

        _userAllow.value = loadStringSet("user_allow")
        _userBlock.value = loadStringSet("user_block")
        _appModes.value = loadAppModes()
        _subscriptions.value = loadSubscriptions()

        val savedProto = prefs.getString("active_protocol", null)?.let { VpnProtocol.fromId(it) } ?: VpnProtocol.AUTO
        _activeProtocol.value = savedProto

        val savedSplit = prefs.getString("split_mode", null)?.let { SplitTunnelingMode.fromId(it) } ?: SplitTunnelingMode.ALL_APPS
        _splitTunnelingMode.value = savedSplit

        _selectedPackages.value = selectedPackages()

        loadBundledAssets()
        loadCachedCompiledLists()

        // Rebuild initial engine without premature publishStats call
        rebuildEngineInternal(publishAfter = false)

        // Sync rule counts from compiled lists into subscriptions if not set
        val currentSubs = _subscriptions.value
        val updatedSubs = currentSubs.map { sub ->
            val list = compiledRemoteLists[sub.id]
            if (list != null && sub.ruleCount != list.list.ruleCount) {
                sub.copy(ruleCount = list.list.ruleCount)
            } else sub
        }
        if (updatedSubs != currentSubs) {
            _subscriptions.value = updatedSubs
            saveSubscriptions(updatedSubs)
        }

        // Publish initial stats once everything is 100% constructed
        publishStats()

        if (autoUpdateLists) {
            scope.launch {
                try {
                    kotlinx.coroutines.delay(10_000)
                    updateAllEnabledSubscriptions()
                } catch (_: Exception) {}
            }
        }
    }

    // ------------------------------------------------------------------ preferences & options

    var videoCompatEnabled: Boolean
        get() = prefs.getBoolean("opt_video_compat", true)
        set(v) {
            prefs.edit().putBoolean("opt_video_compat", v).apply()
            rebuildEngine()
        }

    var recommendationProtectionEnabled: Boolean
        get() = prefs.getBoolean("opt_rec_protection", true)
        set(v) {
            prefs.edit().putBoolean("opt_rec_protection", v).apply()
            rebuildEngine()
        }

    var blockTrackersEnabled: Boolean
        get() = prefs.getBoolean("opt_block_trackers", true)
        set(v) {
            prefs.edit().putBoolean("opt_block_trackers", v).apply()
            rebuildEngine()
        }

    var preventDnsBypassEnabled: Boolean
        get() = prefs.getBoolean("opt_prevent_dns_bypass", true)
        set(v) {
            prefs.edit().putBoolean("opt_prevent_dns_bypass", v).apply()
            rebuildEngine()
        }

    var interceptPublicDnsResolvers: Boolean
        get() = prefs.getBoolean("opt_intercept_public_dns", true)
        set(v) {
            prefs.edit().putBoolean("opt_intercept_public_dns", v).apply()
            vpnConfigChangeListener?.invoke()
        }

    var dpiBypassEnabled: Boolean
        get() = prefs.getBoolean("opt_dpi_bypass", false)
        set(v) {
            prefs.edit().putBoolean("opt_dpi_bypass", v).apply()
            vpnConfigChangeListener?.invoke()
        }

    var usePublicUpstreamDns: Boolean
        get() = prefs.getBoolean("opt_use_public_upstream_dns", true)
        set(v) {
            prefs.edit().putBoolean("opt_use_public_upstream_dns", v).apply()
            vpnConfigChangeListener?.invoke()
        }

    var blockStyle: BlockStyle
        get() = if (prefs.getString("opt_block_style", "NULL_IP") == "NXDOMAIN") BlockStyle.NXDOMAIN else BlockStyle.NULL_IP
        set(v) {
            prefs.edit().putString("opt_block_style", v.name).apply()
            vpnConfigChangeListener?.invoke()
        }

    var autoUpdateLists: Boolean
        get() = prefs.getBoolean("opt_auto_update", true)
        set(v) {
            prefs.edit().putBoolean("opt_auto_update", v).apply()
        }

    fun currentProcessorConfig(): ProcessorConfig = ProcessorConfig(
        blockStyle = blockStyle,
        blockedTtl = 10,
        identifyApps = true,
    )

    // ------------------------------------------------------------------ WireGuard & Hybrid Routing

    var wireGuardEnabled: Boolean
        get() = prefs.getBoolean("opt_wireguard_enabled", true)
        set(v) {
            prefs.edit().putBoolean("opt_wireguard_enabled", v).apply()
            vpnConfigChangeListener?.invoke()
        }

    var killSwitchEnabled: Boolean
        get() = prefs.getBoolean("opt_kill_switch", true)
        set(v) {
            prefs.edit().putBoolean("opt_kill_switch", v).apply()
            vpnConfigChangeListener?.invoke()
        }

    fun listWireGuardProfiles(): List<WireGuardProfile> {
        val raw = prefs.getString("wg_profiles_json", null)
        return WireGuardConfigManager.deserializeProfiles(raw)
    }

    fun saveWireGuardProfiles(profiles: List<WireGuardProfile>) {
        val json = WireGuardConfigManager.serializeProfiles(profiles)
        prefs.edit().putString("wg_profiles_json", json).apply()
    }

    var activeWireGuardProfileId: String
        get() = prefs.getString("active_wg_profile_id", null) ?: listWireGuardProfiles().firstOrNull()?.id ?: "preset_frankfurt"
        set(v) {
            prefs.edit().putString("active_wg_profile_id", v).apply()
            vpnConfigChangeListener?.invoke()
        }

    fun activeWireGuardProfile(): WireGuardProfile {
        val all = listWireGuardProfiles()
        return all.find { it.id == activeWireGuardProfileId } ?: all.firstOrNull() ?: WireGuardConfigManager.PRESET_PROFILES.first()
    }

    fun addWireGuardProfile(profile: WireGuardProfile) {
        val current = listWireGuardProfiles().filterNot { it.id == profile.id }
        saveWireGuardProfiles(current + profile)
    }

    fun removeWireGuardProfile(id: String): Boolean {
        val current = listWireGuardProfiles()
        if (current.size <= 1) return false
        val next = current.filterNot { it.id == id }
        saveWireGuardProfiles(next)
        if (activeWireGuardProfileId == id) {
            activeWireGuardProfileId = next.first().id
        }
        return true
    }

    val defaultTunneledPackages: Set<String>
        get() = DEFAULT_TUNNELED_PACKAGES

    fun tunneledPackages(): Set<String> {
        val saved = prefs.getStringSet("tunneled_pkgs", null)
        return if (!saved.isNullOrEmpty()) saved else DEFAULT_TUNNELED_PACKAGES
    }

    fun setAppTunneled(packageName: String, tunneled: Boolean) {
        val current = tunneledPackages().toMutableSet()
        if (tunneled) current.add(packageName) else current.remove(packageName)
        prefs.edit().putStringSet("tunneled_pkgs", current).apply()
        vpnConfigChangeListener?.invoke()
    }

    fun isAppTunneled(packageName: String): Boolean = packageName in tunneledPackages()

    fun updateWireGuardStats(st: TunnelStats) {
        _wireGuardStats.value = st
        publishStats()
    }

    // ------------------------------------------------------------------ bundled & remote lists

    private fun loadBundledAssets() {
        confirmedAdsSet = loadAssetSet("filters/ads_confirmed.txt")
        trackersSet = loadAssetSet("filters/trackers.txt")
        dnsBypassSet = loadAssetSet("filters/dns_bypass.txt")
    }

    private fun loadAssetSet(path: String): DomainHashSet = runCatching {
        context.assets.open(path).bufferedReader().useLines { lines ->
            val b = DomainHashSet.Builder(256)
            FilterListParser.parseDomains(lines).forEach { b.add(it) }
            b.build()
        }
    }.getOrDefault(DomainHashSet.EMPTY)

    private fun compiledFile(id: String): File =
        File(File(context.filesDir, "lists").apply { mkdirs() }, "$id.bin")

    private fun loadCachedCompiledLists() {
        compiledRemoteLists.clear()
        for (sub in _subscriptions.value) {
            if (!sub.enabled) continue
            val f = compiledFile(sub.id)
            if (f.exists()) {
                runCatching {
                    DataInputStream(BufferedInputStream(f.inputStream())).use {
                        val cl = CompiledList.read(it)
                        compiledRemoteLists[sub.id] = NamedList(sub.id, sub.name, cl)
                    }
                }
            } else {
                runCatching {
                    context.assets.open("filters/${sub.id}.bin").use { assetStream ->
                        DataInputStream(BufferedInputStream(assetStream)).use { dis ->
                            val cl = CompiledList.read(dis)
                            compiledRemoteLists[sub.id] = NamedList(sub.id, sub.name, cl)
                            runCatching {
                                DataOutputStream(BufferedOutputStream(f.outputStream())).use { cl.write(it) }
                            }
                        }
                    }
                }
            }
        }
    }

    @Synchronized
    fun rebuildEngine() {
        rebuildEngineInternal(publishAfter = true)
    }

    private fun rebuildEngineInternal(publishAfter: Boolean) {
        val activeRemote = _subscriptions.value.filter { it.enabled }.mapNotNull { compiledRemoteLists[it.id] }
        val next = FilterEngine(
            confirmedAds = confirmedAdsSet,
            trackers = trackersSet,
            dnsBypass = dnsBypassSet,
            remote = activeRemote,
            userAllow = _userAllow.value,
            userBlock = _userBlock.value,
            options = EngineOptions(
                videoCompat = videoCompatEnabled,
                recommendationProtection = recommendationProtectionEnabled,
                blockTrackers = blockTrackersEnabled,
                preventDnsBypass = preventDnsBypassEnabled,
            ),
            protection = ProtectionSets.DEFAULT,
        )
        engine = next
        dnsCache.clear()
        engineChangeListener?.invoke(next)
        if (publishAfter) {
            publishStats()
        }
    }

    // ------------------------------------------------------------------ user allow / block rules

    fun normalizeDomainInput(raw: String): String? {
        var s = raw.trim().lowercase()
        if (s.startsWith("http://")) s = s.removePrefix("http://")
        if (s.startsWith("https://")) s = s.removePrefix("https://")
        s = s.substringBefore('/').substringBefore(':').trim('.')
        if (s.startsWith("||")) s = s.removePrefix("||").trimEnd('^')
        return if (FilterListParser.isValidHostname(s)) s else null
    }

    fun addUserAllow(domain: String): Boolean {
        val d = normalizeDomainInput(domain) ?: return false
        val next = LinkedHashSet(_userAllow.value).apply { add(d) }
        _userAllow.value = next
        saveStringSet("user_allow", next)
        // Also remove from userBlock if present
        if (d in _userBlock.value) {
            val nb = LinkedHashSet(_userBlock.value).apply { remove(d) }
            _userBlock.value = nb
            saveStringSet("user_block", nb)
        }
        videoMonitor.dismiss(d)
        _videoIncidents.value = videoMonitor.snapshot()
        rebuildEngine()
        return true
    }

    fun removeUserAllow(domain: String) {
        val next = LinkedHashSet(_userAllow.value).apply { remove(domain) }
        _userAllow.value = next
        saveStringSet("user_allow", next)
        rebuildEngine()
    }

    fun addUserBlock(domain: String): Boolean {
        val d = normalizeDomainInput(domain) ?: return false
        val next = LinkedHashSet(_userBlock.value).apply { add(d) }
        _userBlock.value = next
        saveStringSet("user_block", next)
        if (d in _userAllow.value) {
            val na = LinkedHashSet(_userAllow.value).apply { remove(d) }
            _userAllow.value = na
            saveStringSet("user_allow", na)
        }
        rebuildEngine()
        return true
    }

    fun removeUserBlock(domain: String) {
        val next = LinkedHashSet(_userBlock.value).apply { remove(domain) }
        _userBlock.value = next
        saveStringSet("user_block", next)
        rebuildEngine()
    }

    // ------------------------------------------------------------------ per-app modes

    fun getAppMode(packageName: String): AppMode {
        _appModes.value[packageName]?.let { return it }
        return if (packageName in ProtectionSets.COMPAT_PACKAGES) AppMode.COMPAT else AppMode.FILTER
    }

    fun setAppMode(packageName: String, mode: AppMode) {
        val next = HashMap(_appModes.value)
        next[packageName] = mode
        _appModes.value = next
        saveAppModes(next)
        uidAppCache.clear()
        val wasExcludedChanged = true
        if (wasExcludedChanged) vpnConfigChangeListener?.invoke()
    }

    fun excludedPackages(): Set<String> =
        _appModes.value.filterValues { it == AppMode.EXCLUDED }.keys + context.packageName

    fun resolveUid(uid: Int): AppInfo? {
        if (uid <= 0) return null
        uidAppCache[uid]?.let { return it }
        val pm = context.packageManager
        val pkgs = runCatching { pm.getPackagesForUid(uid) }.getOrNull()
        val pkg = pkgs?.firstOrNull() ?: return null
        val label = runCatching {
            val ai = pm.getApplicationInfo(pkg, 0)
            pm.getApplicationLabel(ai).toString()
        }.getOrDefault(pkg)
        val info = AppInfo(uid, pkg, label, getAppMode(pkg))
        uidAppCache[uid] = info
        return info
    }

    fun listInstalledApps(): List<InstalledAppItem> {
        val pm = context.packageManager
        val apps = runCatching {
            pm.getInstalledApplications(PackageManager.GET_META_DATA)
        }.getOrDefault(emptyList())
        return apps
            .filter { it.packageName != context.packageName }
            .filter {
                runCatching {
                    pm.checkPermission(android.Manifest.permission.INTERNET, it.packageName) ==
                        PackageManager.PERMISSION_GRANTED
                }.getOrDefault(false)
            }
            .map { ai ->
                val pkg = ai.packageName
                val label = runCatching { pm.getApplicationLabel(ai).toString() }.getOrDefault(pkg)
                val isSystem = (ai.flags and ApplicationInfo.FLAG_SYSTEM) != 0 &&
                    (ai.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) == 0
                val isRecCompat = pkg in ProtectionSets.COMPAT_PACKAGES
                InstalledAppItem(
                    uid = ai.uid,
                    packageName = pkg,
                    label = label,
                    isSystem = isSystem,
                    mode = getAppMode(pkg),
                    isRecommendedCompat = isRecCompat,
                )
            }
            .sortedWith(
                compareByDescending<InstalledAppItem> { it.isRecommendedCompat }
                    .thenBy { it.isSystem }
                    .thenBy { it.label.lowercase() }
            )
    }

    // ------------------------------------------------------------------ filter list subscriptions

    fun setSubscriptionEnabled(id: String, enabled: Boolean) {
        val updated = _subscriptions.value.map {
            if (it.id == id) it.copy(enabled = enabled) else it
        }
        _subscriptions.value = updated
        saveSubscriptions(updated)
        loadCachedCompiledLists()
        rebuildEngine()
    }

    fun addCustomSubscription(name: String, url: String): Boolean {
        val cleanUrl = url.trim()
        if (!cleanUrl.startsWith("https://") && !cleanUrl.startsWith("http://")) return false
        val id = "custom_" + System.currentTimeMillis()
        val sub = FilterSubscription(
            id = id,
            name = name.trim().ifEmpty { cleanUrl.substringAfter("://").take(32) },
            url = cleanUrl,
            description = "قائمة خارجية مضافة بواسطة المستخدم",
            enabled = true,
        )
        val updated = _subscriptions.value + sub
        _subscriptions.value = updated
        saveSubscriptions(updated)
        return true
    }

    fun removeSubscription(id: String) {
        if (id.startsWith("builtin_")) return
        val updated = _subscriptions.value.filterNot { it.id == id }
        _subscriptions.value = updated
        saveSubscriptions(updated)
        compiledRemoteLists.remove(id)
        compiledFile(id).delete()
        rebuildEngine()
    }

    /**
     * Downloads, validates, compiles and atomically activates a subscription list.
     * Rejects HTML error pages or empty/corrupt downloads so broken responses never wipe rules.
     */
    fun updateSubscriptionNow(id: String): Result<FilterSubscription> {
        val sub = _subscriptions.value.find { it.id == id }
            ?: return Result.failure(IllegalArgumentException("القائمة غير موجودة"))
        return try {
            val conn = (URL(sub.url).openConnection() as HttpURLConnection).apply {
                connectTimeout = 15_000
                readTimeout = 30_000
                requestMethod = "GET"
                setRequestProperty("Accept", "text/plain, */*")
            }
            val code = conn.responseCode
            if (code !in 200..299) {
                throw IllegalStateException("HTTP $code")
            }
            val parsed = conn.inputStream.bufferedReader().use { reader ->
                FilterListParser.parse(reader, sampleCap = 0)
            }
            if (parsed.looksLikeHtml) {
                throw IllegalStateException("الملف المحمّل صفحة HTML وليس قائمة فلترة")
            }
            if (parsed.ruleCount < 10) {
                throw IllegalStateException("عدد القواعد المتوافقة قليل جدًا (${parsed.ruleCount}) - تم رفض التحديث حفاظًا على السلامة")
            }
            val compiled = CompiledList.from(parsed)
            val target = compiledFile(sub.id)
            val tmp = File(target.parentFile, "${sub.id}.tmp")
            DataOutputStream(BufferedOutputStream(tmp.outputStream())).use { compiled.write(it) }
            if (!tmp.renameTo(target)) {
                tmp.copyTo(target, overwrite = true)
                tmp.delete()
            }
            if (sub.enabled) {
                compiledRemoteLists[sub.id] = NamedList(sub.id, sub.name, compiled)
            }
            val newSub = sub.copy(
                ruleCount = compiled.ruleCount,
                lastUpdated = System.currentTimeMillis(),
                lastError = null,
            )
            updateSubscriptionRecord(newSub)
            rebuildEngine()
            Result.success(newSub)
        } catch (e: Exception) {
            val err = e.message ?: e.javaClass.simpleName
            val failedSub = sub.copy(lastError = err)
            updateSubscriptionRecord(failedSub)
            Result.failure(e)
        }
    }

    fun updateAllEnabledSubscriptions(onProgress: (String) -> Unit = {}): Int {
        var success = 0
        for (sub in _subscriptions.value.filter { it.enabled }) {
            onProgress("جاري تحديث ${sub.name}...")
            if (updateSubscriptionNow(sub.id).isSuccess) success++
        }
        return success
    }

    private fun updateSubscriptionRecord(newSub: FilterSubscription) {
        val updated = _subscriptions.value.map { if (it.id == newSub.id) newSub else it }
        _subscriptions.value = updated
        saveSubscriptions(updated)
    }

    // ------------------------------------------------------------------ events & stats

    fun onVpnStateChanged(state: VpnState, error: VpnError) {
        _vpnState.value = state
        _lastVpnError.value = error
        _vpnRunning.value = state.isRunning
        if (state == VpnState.CONNECTED && connectedSinceMs == 0L) {
            connectedSinceMs = System.currentTimeMillis()
        } else if (!state.isRunning) {
            connectedSinceMs = 0L
        }
        publishStats()
    }

    fun onVpnStateChanged(running: Boolean, upstreams: List<InetAddress> = emptyList(), netLabel: String = "نشط") {
        onVpnStateChanged(if (running) VpnState.CONNECTED else VpnState.DISCONNECTED, VpnError.NONE)
        currentUpstreams = upstreams.map { it.hostAddress ?: it.toString() }
        currentNetworkLabel = netLabel
        publishStats()
    }

    fun setSplitTunnelingMode(mode: SplitTunnelingMode) {
        _splitTunnelingMode.value = mode
        prefs.edit().putString("split_mode", mode.id).apply()
        vpnConfigChangeListener?.invoke()
        publishStats()
    }

    fun setActiveProtocol(protocol: VpnProtocol) {
        _activeProtocol.value = protocol
        prefs.edit().putString("active_protocol", protocol.id).apply()
        vpnConfigChangeListener?.invoke()
        publishStats()
    }

    fun selectedPackages(): Set<String> {
        val set = prefs.getStringSet("selected_split_pkgs", null)
        return if (!set.isNullOrEmpty()) set else DEFAULT_TUNNELED_PACKAGES
    }

    fun setSelectedPackages(pkgs: Set<String>) {
        _selectedPackages.value = pkgs
        prefs.edit().putStringSet("selected_split_pkgs", pkgs).apply()
        vpnConfigChangeListener?.invoke()
    }

    fun toggleSelectedPackage(pkg: String) {
        val current = selectedPackages().toMutableSet()
        if (current.contains(pkg)) current.remove(pkg) else current.add(pkg)
        setSelectedPackages(current)
    }

    fun updateVerifiedPublicIp(ip: String?) {
        _verifiedPublicIp.value = ip
        publishStats()
    }

    fun updateNetworkInfo(networkName: String, servers: List<String>) {
        currentNetworkLabel = networkName
        currentUpstreams = servers
        publishStats()
    }

    fun onQueryEvent(event: QueryEvent) {
        val total = totalQueriesCount.incrementAndGet()
        if (event.decision.blocked) blockedQueriesCount.incrementAndGet()
        if (event.cached) cachedQueriesCount.incrementAndGet()
        if (event.decision.reason == com.smartadshield.vpn.core.filter.Reason.TRACKER) {
            trackerBlockedCount.incrementAndGet()
        }
        if (event.decision.reason == com.smartadshield.vpn.core.filter.Reason.VIDEO_PROTECTED ||
            event.decision.reason == com.smartadshield.vpn.core.filter.Reason.PLATFORM_PROTECTED
        ) {
            videoProtectedCount.incrementAndGet()
        }
        if (event.decision.reason == com.smartadshield.vpn.core.filter.Reason.RECOMMENDATION_PROTECTED) {
            recProtectedCount.incrementAndGet()
        }
        if (event.latencyMs > 0 && !event.cached) {
            lastLatency = event.latencyMs
        }

        synchronized(queryLogBuffer) {
            queryLogBuffer.addFirst(event)
            while (queryLogBuffer.size > 400) queryLogBuffer.removeLast()
            _queryLog.value = ArrayList(queryLogBuffer)
        }

        videoMonitor.onEvent(event)
        _videoIncidents.value = videoMonitor.snapshot()

        if (total % 15L == 0L) {
            prefs.edit()
                .putLong("stat_total", totalQueriesCount.get())
                .putLong("stat_blocked", blockedQueriesCount.get())
                .putLong("stat_cached", cachedQueriesCount.get())
                .putLong("stat_tracker", trackerBlockedCount.get())
                .putLong("stat_video_prot", videoProtectedCount.get())
                .putLong("stat_rec_prot", recProtectedCount.get())
                .apply()
        }
        publishStats()
    }

    fun clearQueryLog() {
        synchronized(queryLogBuffer) {
            queryLogBuffer.clear()
            _queryLog.value = emptyList()
        }
    }

    fun resetStatistics() {
        totalQueriesCount.set(0)
        blockedQueriesCount.set(0)
        cachedQueriesCount.set(0)
        trackerBlockedCount.set(0)
        videoProtectedCount.set(0)
        recProtectedCount.set(0)
        prefs.edit()
            .putLong("stat_total", 0L)
            .putLong("stat_blocked", 0L)
            .putLong("stat_cached", 0L)
            .putLong("stat_tracker", 0L)
            .putLong("stat_video_prot", 0L)
            .putLong("stat_rec_prot", 0L)
            .apply()
        videoMonitor.clear()
        _videoIncidents.value = emptyList()
        publishStats()
    }

    fun publishStats() {
        val server = activeWireGuardProfile()
        val currentSelected = selectedPackages()
        _stats.value = VpnStats(
            running = _vpnRunning.value,
            connectedSince = connectedSinceMs,
            totalQueries = totalQueriesCount.get(),
            blockedQueries = blockedQueriesCount.get(),
            cachedQueries = cachedQueriesCount.get(),
            trackerBlocked = trackerBlockedCount.get(),
            protectedVideoQueries = videoProtectedCount.get(),
            protectedRecommendationQueries = recProtectedCount.get(),
            upstreamServers = currentUpstreams,
            activeNetworkName = currentNetworkLabel,
            totalActiveRules = engine.totalRules,
            cacheSize = dnsCache.size(),
            lastLatencyMs = lastLatency,
            wireGuardServerName = server.name,
            wireGuardStatus = _vpnState.value.labelAr,
            tunneledAppsCount = currentSelected.size,
            vpnState = _vpnState.value,
            vpnError = _lastVpnError.value,
            verifiedPublicIp = _verifiedPublicIp.value,
            activeProtocol = _activeProtocol.value,
            splitMode = _splitTunnelingMode.value,
        )
    }

    // ------------------------------------------------------------------ Private DNS detection

    fun detectPrivateDnsStatus(): PrivateDnsStatus = runCatching {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
        val activeNet = cm?.activeNetwork
        val lp: LinkProperties? = if (activeNet != null) cm.getLinkProperties(activeNet) else null

        val isPrivateActive = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && lp != null) {
            runCatching { lp.isPrivateDnsActive }.getOrDefault(false)
        } else false
        val serverName = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && lp != null) {
            runCatching { lp.privateDnsServerName }.getOrNull()
        } else null

        val globalMode = runCatching {
            Settings.Global.getString(context.contentResolver, "private_dns_mode")
        }.getOrNull()
        val globalSpecifier = runCatching {
            Settings.Global.getString(context.contentResolver, "private_dns_specifier")
        }.getOrNull()

        val mode = globalMode ?: when {
            serverName != null -> "hostname"
            isPrivateActive -> "opportunistic"
            else -> "off"
        }

        when {
            serverName != null || mode == "hostname" -> PrivateDnsStatus(
                mode = "hostname",
                specifier = serverName ?: globalSpecifier,
                isActiveConflict = true,
                summaryAr = "تعارض نشط: Private DNS مفعّل على مضيف مخصص (${serverName ?: globalSpecifier ?: "DoT"})",
                detailAr = "عند تفعيل نظام Android لوضع Private DNS مع خادم محدد (DNS-over-TLS على المنفذ 853)، قد يقوم النظام بتشفير استعلامات DNS وتمريرها خارج مسار UDP/53 المعتاد. للحصول على حجب كامل ودقيق، يُنصح بضبط (DNS الخاص / Private DNS) في إعدادات Android إلى «تلقائي» أو «إيقاف».",
            )
            isPrivateActive || mode == "opportunistic" -> PrivateDnsStatus(
                mode = "opportunistic",
                specifier = null,
                isActiveConflict = false,
                summaryAr = "متوافق (الوضع التلقائي Opportunistic)",
                detailAr = "يرفض VPN المحلي اتصالات TCP/853 على خادم DNS الافتراضي فورًا عبر حزمة RST قياسية، مما يجعل نظام Android يعود تلقائيًا إلى مسار UDP/53 المحلي دون تأخير.",
            )
            else -> PrivateDnsStatus(
                mode = "off",
                specifier = null,
                isActiveConflict = false,
                summaryAr = "متوافق تمامًا (Private DNS متوقف)",
                detailAr = "جميع استعلامات DNS تمر عبر محرك الفلترة المحلي على الجهاز مباشرة.",
            )
        }
    }.getOrDefault(
        PrivateDnsStatus(
            mode = "unknown",
            specifier = null,
            isActiveConflict = false,
            summaryAr = "متوافق (حالة افتراضية)",
            detailAr = "استعلامات DNS تمر عبر محرك الفلترة والـ VPN المحلي.",
        )
    )

    // ------------------------------------------------------------------ JSON persistence helpers

    private fun loadStringSet(key: String): Set<String> {
        val raw = prefs.getString(key, null) ?: return emptySet()
        return runCatching {
            val arr = JSONArray(raw)
            val set = LinkedHashSet<String>(arr.length())
            for (i in 0 until arr.length()) set.add(arr.getString(i))
            set
        }.getOrDefault(emptySet())
    }

    private fun saveStringSet(key: String, set: Set<String>) {
        val arr = JSONArray()
        set.forEach { arr.put(it) }
        prefs.edit().putString(key, arr.toString()).apply()
    }

    private fun loadAppModes(): Map<String, AppMode> {
        val raw = prefs.getString("app_modes_json", null) ?: return emptyMap()
        return runCatching {
            val obj = JSONObject(raw)
            val map = HashMap<String, AppMode>()
            val keys = obj.keys()
            while (keys.hasNext()) {
                val k = keys.next()
                val v = runCatching { AppMode.valueOf(obj.getString(k)) }.getOrDefault(AppMode.FILTER)
                map[k] = v
            }
            map
        }.getOrDefault(emptyMap())
    }

    private fun saveAppModes(map: Map<String, AppMode>) {
        val obj = JSONObject()
        for ((k, v) in map) obj.put(k, v.name)
        prefs.edit().putString("app_modes_json", obj.toString()).apply()
    }

    private fun loadSubscriptions(): List<FilterSubscription> {
        val raw = prefs.getString("subscriptions_json", null)
        if (raw != null) {
            runCatching {
                val arr = JSONArray(raw)
                val list = ArrayList<FilterSubscription>(arr.length())
                for (i in 0 until arr.length()) {
                    val o = arr.getJSONObject(i)
                    list.add(
                        FilterSubscription(
                            id = o.getString("id"),
                            name = o.getString("name"),
                            url = o.getString("url"),
                            description = o.optString("description", ""),
                            enabled = o.optBoolean("enabled", true),
                            ruleCount = o.optInt("ruleCount", 0),
                            lastUpdated = o.optLong("lastUpdated", 0L),
                            lastError = o.optString("lastError", "").ifEmpty { null },
                        )
                    )
                }
                if (list.isNotEmpty()) return list
            }
        }
        return listOf(
            FilterSubscription(
                id = "builtin_adguard_dns",
                name = "AdGuard DNS Filter",
                url = "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
                description = "قائمة شاملة مخصصة لفلترة DNS تجمع AdGuard Base وEasyList وEasyPrivacy",
                enabled = true,
                ruleCount = 190072,
            ),
            FilterSubscription(
                id = "builtin_stevenblack",
                name = "StevenBlack Unified Hosts",
                url = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
                description = "قائمة Hosts موحدة للنطاقات الإعلانية والمتتبعات المعروفة",
                enabled = true,
            ),
            FilterSubscription(
                id = "builtin_easylist",
                name = "EasyList (قواعد النطاقات فقط)",
                url = "https://easylist.to/easylist/easylist.txt",
                description = "يستخلص المحرك منها فقط قواعد حجب النطاقات الكاملة المتوافقة مع DNS",
                enabled = false,
            ),
            FilterSubscription(
                id = "builtin_easyprivacy",
                name = "EasyPrivacy (قواعد النطاقات فقط)",
                url = "https://easylist.to/easylist/easyprivacy.txt",
                description = "قواعد نطاقات التتبع الصرفة المتوافقة مع DNS",
                enabled = false,
            ),
        )
    }

    private fun saveSubscriptions(list: List<FilterSubscription>) {
        val arr = JSONArray()
        for (s in list) {
            arr.put(
                JSONObject().apply {
                    put("id", s.id)
                    put("name", s.name)
                    put("url", s.url)
                    put("description", s.description)
                    put("enabled", s.enabled)
                    put("ruleCount", s.ruleCount)
                    put("lastUpdated", s.lastUpdated)
                    if (s.lastError != null) put("lastError", s.lastError)
                }
            )
        }
        prefs.edit().putString("subscriptions_json", arr.toString()).apply()
    }

    companion object {
        val DEFAULT_TUNNELED_PACKAGES: Set<String> = Collections.unmodifiableSet(
            linkedSetOf(
                "com.zhiliaoapp.musically",
                "com.ss.android.ugc.trill",
                "com.zhiliaoapp.musically.go",
            )
        )

        @Volatile
        private var instance: AppRepository? = null

        fun get(context: Context): AppRepository =
            instance ?: synchronized(this) {
                instance ?: AppRepository(context.applicationContext).also { instance = it }
            }

        fun resetForTesting() {
            synchronized(this) {
                instance = null
            }
        }
    }
}
