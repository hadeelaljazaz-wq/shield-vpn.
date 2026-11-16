package com.smartadshield.vpn.ui

import android.Manifest
import android.app.AlertDialog
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.text.InputType
import android.text.TextUtils
import android.util.TypedValue
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.HorizontalScrollView
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.Switch
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import com.smartadshield.vpn.core.QueryEvent
import com.smartadshield.vpn.core.dns.BlockStyle
import com.smartadshield.vpn.core.dns.DnsMessage
import com.smartadshield.vpn.core.engine.SplitTunnelingMode
import com.smartadshield.vpn.core.engine.VpnError
import com.smartadshield.vpn.core.engine.VpnProtocol
import com.smartadshield.vpn.core.engine.VpnState
import com.smartadshield.vpn.core.filter.AppMode
import com.smartadshield.vpn.core.video.VideoIncident
import com.smartadshield.vpn.tunnel.EnrollmentCode
import com.smartadshield.vpn.tunnel.ServerEntry
import com.smartadshield.vpn.tunnel.TunnelManager
import com.smartadshield.vpn.tunnel.TunnelStatus
import com.smartadshield.vpn.data.AppRepository
import com.smartadshield.vpn.data.FilterSubscription
import com.smartadshield.vpn.data.InstalledAppItem
import com.smartadshield.vpn.data.PrivateDnsStatus
import com.smartadshield.vpn.data.VpnStats
import com.smartadshield.vpn.diagnostics.CheckStatus
import com.smartadshield.vpn.diagnostics.DiagnosticReport
import com.smartadshield.vpn.diagnostics.DiagnosticsRunner
import com.smartadshield.vpn.service.SmartAdShieldVpnService
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.net.InetAddress
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class MainActivity : AppCompatActivity() {

    private val uiScope = CoroutineScope(SupervisorJob() + Dispatchers.Main)
    private lateinit var repo: AppRepository
    private lateinit var contentContainer: FrameLayout
    private val navButtons = ArrayList<TextView>(5)
    private var currentTab = 0

    // Dashboard dynamic views
    private var powerCircle: LinearLayout? = null
    private var powerStateTitle: TextView? = null
    private var powerStateSubtitle: TextView? = null
    private var statBlockedTv: TextView? = null
    private var statTotalTv: TextView? = null
    private var statCacheTv: TextView? = null
    private var statRulesTv: TextView? = null
    private var statVideoProtTv: TextView? = null
    private var statRecProtTv: TextView? = null
    private var dnsStatusTitleTv: TextView? = null
    private var dnsStatusDetailTv: TextView? = null
    private var privateDnsTitleTv: TextView? = null
    private var privateDnsDetailTv: TextView? = null
    private var publicIpTv: TextView? = null
    private var incidentsContainer: LinearLayout? = null

    // Log tab views
    private var logListContainer: LinearLayout? = null
    private var logBlockedOnly = false
    private var logSearchQuery = ""

    // Lists tab views
    private var listsContainer: LinearLayout? = null
    private var allowChipsContainer: LinearLayout? = null
    private var blockChipsContainer: LinearLayout? = null
    private var updateListsStatusTv: TextView? = null

    // Apps tab views
    private var appsListContainer: LinearLayout? = null
    private var cachedInstalledApps: List<InstalledAppItem>? = null
    private var showSystemApps = false

    // Diagnostics tab views
    private var diagContainer: LinearLayout? = null
    private var diagStatusTv: TextView? = null
    private var lastReport: DiagnosticReport? = null
    private var baselinePublicIp: String? = null

    private val timeFormat = SimpleDateFormat("HH:mm:ss", Locale.US)

    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { _ ->
        val action = pendingAfterPermission
        pendingAfterPermission = null
        if (VpnService.prepare(this) == null) {
            action?.invoke()
        } else {
            Toast.makeText(this, "لم يتم منح إذن VPN", Toast.LENGTH_SHORT).show()
        }
    }
    private var pendingAfterPermission: (() -> Unit)? = null
    private var serverTitleTv: TextView? = null
    private var serverDetailTv: TextView? = null
    private var serverFlagTv: TextView? = null
    private var tunnelLogTv: TextView? = null

    private val notifPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { _ -> }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        try {
            repo = AppRepository.get(this)
            val root = buildRootLayout()
            setContentView(root)
            runCatching { window.decorView.layoutDirection = View.LAYOUT_DIRECTION_RTL }

            switchTab(0)
            observeRepository()
            refreshPublicIpBanner()
            requestNotificationPermissionIfNeeded()
        } catch (t: Throwable) {
            android.util.Log.e("MainActivity", "Error during MainActivity initialization", t)
            showCrashRecoveryView(t)
        }
    }

    private fun requestNotificationPermissionIfNeeded() {
        if (Build.VERSION.SDK_INT >= 33) {
            runCatching {
                if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) !=
                    PackageManager.PERMISSION_GRANTED
                ) {
                    notifPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
                }
            }
        }
    }

    private fun showCrashRecoveryView(t: Throwable) {
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(COLOR_BG_PRIMARY)
            layoutDirection = View.LAYOUT_DIRECTION_RTL
            setPadding(dp(20), dp(40), dp(20), dp(20))
        }
        root.addView(TextView(this).apply {
            text = "⚠️ تنبيه في بدء تشغيل التطبيق"
            setTextColor(COLOR_STATUS_AMBER)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 18f)
            setTypeface(typeface, Typeface.BOLD)
            setPadding(0, 0, 0, dp(10))
        })
        root.addView(TextView(this).apply {
            text = "واجه التطبيق استثناءً أثناء التهيئة الأولية: ${t.localizedMessage ?: t.javaClass.simpleName}\n\nتم تفعيل وضع الحماية الآمن لمنع الإغلاق المفاجئ."
            setTextColor(COLOR_TEXT_PRIMARY)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 13f)
            setPadding(0, 0, 0, dp(16))
        })
        root.addView(Button(this).apply {
            text = "إعادة المحاولة والتشغيل"
            setBackgroundColor(COLOR_ACCENT_BLUE)
            setTextColor(COLOR_BG_PRIMARY)
            setOnClickListener { recreate() }
        })
        val scroll = ScrollView(this).apply {
            addView(TextView(this@MainActivity).apply {
                text = t.stackTraceToString()
                setTextColor(COLOR_TEXT_MUTED)
                setTextSize(TypedValue.COMPLEX_UNIT_SP, 10f)
                setPadding(0, dp(16), 0, 0)
            })
        }
        root.addView(scroll)
        runCatching { setContentView(root) }
    }

    override fun onDestroy() {
        uiScope.cancel()
        super.onDestroy()
    }

    private fun observeRepository() {
        uiScope.launch {
            TunnelManager.status.collectLatest { ts ->
                updateDashboardStats(repo.stats.value)
                tunnelLogTv?.text = ts.log.reversed().joinToString("\n").ifEmpty { "لا توجد أحداث بعد." }
            }
        }
        uiScope.launch {
            repo.stats.collectLatest { st ->
                updateDashboardStats(st)
            }
        }
        uiScope.launch {
            repo.queryLog.collectLatest { events ->
                if (currentTab == 1) renderLogEvents(events)
            }
        }
        uiScope.launch {
            repo.videoIncidents.collectLatest { incidents ->
                if (currentTab == 0) renderVideoIncidents(incidents)
            }
        }
        uiScope.launch {
            repo.subscriptions.collectLatest {
                if (currentTab == 2) renderSubscriptionsAndRules()
            }
        }
    }

    private fun refreshPublicIpBanner() {
        uiScope.launch {
            val ip = withContext(Dispatchers.IO) { DiagnosticsRunner.fetchPublicIp(4000).getOrNull() }
            if (isFinishing || isDestroyed) return@launch
            if (ip != null && baselinePublicIp == null) baselinePublicIp = ip
            if (ip != null) repo.updateVerifiedPublicIp(ip)
            val ts = TunnelManager.status.value
            publicIpTv?.text = when {
                ts.state == VpnState.CONNECTED -> "✓ IP الخروج المتحقق منه عبر النفق: ${ts.verifiedPublicIp} (${ts.verifiedCountry ?: "?"})"
                ip != null -> "عنوان IP العام الحالي (بدون VPN): $ip"
                else -> "عنوان IP العام: تعذر القياس"
            }
        }
    }

    // ------------------------------------------------------------------ Root & Navigation

    private fun buildRootLayout(): View {
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutDirection = View.LAYOUT_DIRECTION_RTL
            setBackgroundColor(COLOR_BG_PRIMARY)
            layoutParams = ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT
            )
        }

        // Top App Bar
        val header = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setBackgroundColor(COLOR_BG_SURFACE)
            setPadding(dp(16), dp(14), dp(16), dp(14))
        }
        val titleCol = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
        }
        titleCol.addView(TextView(this).apply {
            text = "درع الإعلانات الذكي • Smart Ad Shield"
            setTextColor(COLOR_TEXT_PRIMARY)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 17f)
            setTypeface(typeface, Typeface.BOLD)
        })
        titleCol.addView(TextView(this).apply {
            text = "فلترة DNS محلية عالية الأداء • دون تغيير IP أو خوارزميات التوصيات"
            setTextColor(COLOR_ACCENT_BLUE)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 11.5f)
        })
        header.addView(titleCol)
        root.addView(header)

        // Divider
        root.addView(View(this).apply {
            setBackgroundColor(COLOR_BORDER)
            layoutParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(1))
        })

        // Main Content Frame
        contentContainer = FrameLayout(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                0,
                1f
            )
        }
        root.addView(contentContainer)

        // Bottom Navigation Bar
        root.addView(View(this).apply {
            setBackgroundColor(COLOR_BORDER)
            layoutParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(1))
        })

        val navBar = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            setBackgroundColor(COLOR_BG_SURFACE)
            setPadding(dp(4), dp(6), dp(4), dp(6))
        }
        val tabs = listOf(
            "الحماية",
            "السجل اللحظي",
            "القوائم والاستثناءات",
            "التطبيقات",
            "فحص السلامة",
        )
        navButtons.clear()
        tabs.forEachIndexed { idx, label ->
            val btn = TextView(this).apply {
                text = label
                gravity = Gravity.CENTER
                setTextSize(TypedValue.COMPLEX_UNIT_SP, 11.5f)
                setPadding(dp(4), dp(10), dp(4), dp(10))
                layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
                setOnClickListener { switchTab(idx) }
            }
            navButtons.add(btn)
            navBar.addView(btn)
        }
        root.addView(navBar)
        return root
    }

    private fun switchTab(index: Int) {
        currentTab = index
        navButtons.forEachIndexed { i, tv ->
            val selected = i == index
            tv.setTextColor(if (selected) COLOR_ACCENT_BLUE else COLOR_TEXT_SECONDARY)
            tv.setTypeface(null, if (selected) Typeface.BOLD else Typeface.NORMAL)
            tv.background = if (selected) roundedDrawable(COLOR_ACCENT_SOFT, COLOR_ACCENT_BLUE, dp(10), dp(1)) else null
        }
        contentContainer.removeAllViews()
        when (index) {
            0 -> contentContainer.addView(buildDashboardTab())
            1 -> contentContainer.addView(buildQueryLogTab())
            2 -> contentContainer.addView(buildListsAndRulesTab())
            3 -> contentContainer.addView(buildAppsTab())
            4 -> contentContainer.addView(buildDiagnosticsTab())
        }
    }

    // ------------------------------------------------------------------ Tab 0: Dashboard

    private fun buildDashboardTab(): View {
        val scroll = ScrollView(this)
        val col = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(16), dp(16), dp(16), dp(28))
        }

        // Power Button Hero Card
        val heroCard = cardLayout().apply {
            gravity = Gravity.CENTER_HORIZONTAL
            setPadding(dp(20), dp(22), dp(20), dp(22))
        }

        val ring = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER
            layoutParams = LinearLayout.LayoutParams(dp(132), dp(132))
            setOnClickListener { toggleVpnProtection() }
        }
        val ringIconTv = TextView(this).apply {
            text = "🛡️"
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 34f)
            gravity = Gravity.CENTER
        }
        val ringActionTv = TextView(this).apply {
            text = "تشغيل"
            setTextColor(COLOR_TEXT_PRIMARY)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 15f)
            setTypeface(typeface, Typeface.BOLD)
            gravity = Gravity.CENTER
        }
        ring.addView(ringIconTv)
        ring.addView(ringActionTv)
        powerCircle = ring
        heroCard.addView(ring)

        powerStateTitle = TextView(this).apply {
            setTextColor(COLOR_TEXT_PRIMARY)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 18f)
            setTypeface(typeface, Typeface.BOLD)
            gravity = Gravity.CENTER
            setPadding(0, dp(14), 0, dp(4))
        }
        heroCard.addView(powerStateTitle)

        powerStateSubtitle = TextView(this).apply {
            setTextColor(COLOR_TEXT_SECONDARY)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 12.5f)
            gravity = Gravity.CENTER
        }
        heroCard.addView(powerStateSubtitle)

        publicIpTv = TextView(this).apply {
            text = "عنوان IP العام: محفوظ محليًا (Split-Tunnel DNS)"
            setTextColor(COLOR_ACCENT_BLUE)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f)
            gravity = Gravity.CENTER
            setPadding(dp(10), dp(10), dp(10), 0)
        }
        heroCard.addView(publicIpTv)
        col.addView(heroCard)

        // Server Location Card
        val serverCard = cardLayout().apply {
            layoutParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                topMargin = dp(12)
            }
        }
        serverCard.addView(sectionTitle("خادم الـ VPN"))
        val serverRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(0, dp(4), 0, dp(4))
        }
        val flagTv = TextView(this).apply {
            text = "🖥️"
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 28f)
            setPadding(dp(4), 0, dp(10), 0)
        }
        val serverInfoCol = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
        }
        val serverTitleTv = TextView(this).apply {
            text = ""
            setTextColor(COLOR_TEXT_PRIMARY)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 14f)
            setTypeface(typeface, Typeface.BOLD)
        }
        val serverDetailTv = TextView(this).apply {
            text = ""
            setTextColor(COLOR_TEXT_SECONDARY)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 11.5f)
        }
        serverInfoCol.addView(serverTitleTv)
        serverInfoCol.addView(serverDetailTv)
        serverRow.addView(flagTv)
        serverRow.addView(serverInfoCol)
        serverCard.addView(serverRow)
        this.serverFlagTv = flagTv
        this.serverTitleTv = serverTitleTv
        this.serverDetailTv = serverDetailTv
        serverCard.addView(actionButton("🌍 الخوادم: إضافة رمز تسجيل / اختيار / استيراد .conf") {
            showServerSelectionDialog()
        })
        serverCard.addView(switchRow(
            title = "حجب الإعلانات داخل نفق VPN (AdGuard DNS)",
            subtitle = "عند الاتصال بخادم VPN تُرسل استعلامات DNS عبر النفق إلى AdGuard DNS العام لحجب الإعلانات. أوقفه إذا تعطل تطبيق ما (يستخدم 1.1.1.1 بدلًا منه). يُطبّق عند الاتصال التالي.",
            checked = TunnelManager.adBlockDns
        ) { TunnelManager.updateAdBlockDns(it) })
        serverCard.addView(actionButton("🔒 Kill Switch / Always-on: فتح إعدادات VPN في Android") {
            Toast.makeText(this, "فعّل «VPN دائم التشغيل» و«حظر الاتصالات بدون VPN» لهذا التطبيق", Toast.LENGTH_LONG).show()
            runCatching { startActivity(Intent(Settings.ACTION_VPN_SETTINGS)) }
        })
        col.addView(serverCard)

        // Protocol Selector Card
        val protocolCard = cardLayout().apply {
            layoutParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                topMargin = dp(12)
            }
        }
        protocolCard.addView(sectionTitle("بروتوكول الـ VPN (Protocol)"))
        val protoRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(0, dp(4), 0, dp(4))
        }
        VpnProtocol.values().forEach { proto ->
            val isActive = repo.activeProtocol.value == proto
            protoRow.addView(smallPillButton(proto.displayNameAr.substringBefore(" ("), isActive) {
                repo.setActiveProtocol(proto)
                Toast.makeText(this, "تم اختيار: ${proto.displayNameAr}", Toast.LENGTH_SHORT).show()
                switchTab(0)
            })
        }
        val protoScroll = HorizontalScrollView(this).apply {
            isHorizontalScrollBarEnabled = false
            addView(protoRow)
        }
        protocolCard.addView(protoScroll)
        col.addView(protocolCard)

        // Statistics 2x3 Grid
        val statsRow1 = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                topMargin = dp(12)
            }
        }
        val (cardBlocked, tvBlocked) = statBox("الإعلانات المحجوبة", "0", COLOR_STATUS_GREEN)
        val (cardTotal, tvTotal) = statBox("إجمالي فحوصات DNS", "0", COLOR_ACCENT_BLUE)
        statBlockedTv = tvBlocked
        statTotalTv = tvTotal
        statsRow1.addView(cardBlocked, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply { leftMargin = dp(6) })
        statsRow1.addView(cardTotal, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply { rightMargin = dp(6) })
        col.addView(statsRow1)

        val statsRow2 = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                topMargin = dp(10)
            }
        }
        val (cardVideoProt, tvVideoProt) = statBox("طلبات فيديو محمية", "0", COLOR_ACCENT_BLUE)
        val (cardRecProt, tvRecProt) = statBox("إشارات توصيات محمية", "0", COLOR_ACCENT_BLUE)
        statVideoProtTv = tvVideoProt
        statRecProtTv = tvRecProt
        statsRow2.addView(cardVideoProt, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply { leftMargin = dp(6) })
        statsRow2.addView(cardRecProt, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply { rightMargin = dp(6) })
        col.addView(statsRow2)

        val statsRow3 = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            layoutParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                topMargin = dp(10)
            }
        }
        val (cardCache, tvCache) = statBox("إجابات الكاش السريعة", "0", COLOR_TEXT_PRIMARY)
        val (cardRules, tvRules) = statBox("القواعد النشطة", "0", COLOR_TEXT_PRIMARY)
        statCacheTv = tvCache
        statRulesTv = tvRules
        statsRow3.addView(cardCache, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply { leftMargin = dp(6) })
        statsRow3.addView(cardRules, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply { rightMargin = dp(6) })
        col.addView(statsRow3)

        // DNS & Private DNS Status Card
        val dnsCard = cardLayout().apply {
            layoutParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                topMargin = dp(14)
            }
        }
        dnsCard.addView(sectionTitle("مؤشر حالة DNS والشبكة"))
        dnsStatusTitleTv = TextView(this).apply {
            setTextColor(COLOR_TEXT_PRIMARY)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 13.5f)
            setTypeface(typeface, Typeface.BOLD)
            setPadding(0, dp(4), 0, dp(2))
        }
        dnsStatusDetailTv = TextView(this).apply {
            setTextColor(COLOR_TEXT_SECONDARY)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f)
        }
        dnsCard.addView(dnsStatusTitleTv)
        dnsCard.addView(dnsStatusDetailTv)

        val pDns = repo.detectPrivateDnsStatus()
        privateDnsTitleTv = TextView(this).apply {
            text = "حالة Android Private DNS: ${pDns.summaryAr}"
            setTextColor(if (pDns.isActiveConflict) COLOR_STATUS_AMBER else COLOR_STATUS_GREEN)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 12.5f)
            setTypeface(typeface, Typeface.BOLD)
            setPadding(0, dp(10), 0, dp(2))
        }
        privateDnsDetailTv = TextView(this).apply {
            text = pDns.detailAr
            setTextColor(COLOR_TEXT_SECONDARY)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 11.5f)
        }
        dnsCard.addView(privateDnsTitleTv)
        dnsCard.addView(privateDnsDetailTv)

        if (pDns.isActiveConflict) {
            dnsCard.addView(actionButton("فتح إعدادات الشبكة لضبط Private DNS") {
                runCatching { startActivity(Intent(Settings.ACTION_WIRELESS_SETTINGS)) }
            })
        }
        col.addView(dnsCard)

        // Protection Modes Card (Recommendation Protection & Video Compatibility)
        val modesCard = cardLayout().apply {
            layoutParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                topMargin = dp(14)
            }
        }
        modesCard.addView(sectionTitle("أوضاع الذكاء وحماية التوصيات والفيديو"))

        modesCard.addView(
            switchRow(
                title = "وضع حماية خوارزميات التوصيات (موصى به)",
                subtitle = "يحافظ على سجل المشاهدة وإشارات التفاعل والبحث في YouTube وTikTok وInstagram وFacebook دون تغيير IP أو اللغة أو الجلسات",
                checked = repo.recommendationProtectionEnabled
            ) { repo.recommendationProtectionEnabled = it }
        )

        modesCard.addView(
            switchRow(
                title = "محرك توافق الفيديو (Video Compatibility Engine)",
                subtitle = "يمنع حجب نطاقات CDN المسؤولة عن بث الفيديو والصور المصغرة والتعليقات والتشغيل التلقائي وجودة البث",
                checked = repo.videoCompatEnabled
            ) { repo.videoCompatEnabled = it }
        )

        modesCard.addView(
            switchRow(
                title = "حجب نطاقات التتبع والتحليلات الخارجية",
                subtitle = "يحجب متتبعات الطرف الثالث في المواقع والتطبيقات مع استثناء النطاقات المشتركة للمنصات",
                checked = repo.blockTrackersEnabled
            ) { repo.blockTrackersEnabled = it }
        )

        modesCard.addView(
            switchRow(
                title = "منع تجاوز DNS (DoH Canary & Bootstrap)",
                subtitle = "يمنع المتصفحات من التحول الصامت إلى خوادم DoH خارجية تتجاوز الفلترة المحلية",
                checked = repo.preventDnsBypassEnabled
            ) { repo.preventDnsBypassEnabled = it }
        )

        modesCard.addView(
            switchRow(
                title = "اعتراض خوادم DNS العامة المبرمجة داخل التطبيقات",
                subtitle = "يوجّه الاستعلامات المرسلة مباشرة إلى 8.8.8.8 أو 1.1.1.1 عبر الفلتر المحلي لمنع تسرب DNS",
                checked = repo.interceptPublicDnsResolvers
            ) { repo.interceptPublicDnsResolvers = it }
        )

        modesCard.addView(
            switchRow(
                title = "استخدام خوادم DNS عالمية نقية (Cloudflare / Google)",
                subtitle = "يتجاوز خوادم مزود الخدمة المحلية لمنع تسميم أو حجب نطاقات TikTok والمواقع المحجوبة",
                checked = repo.usePublicUpstreamDns
            ) { repo.usePublicUpstreamDns = it }
        )
        col.addView(modesCard)

        // Google Chrome Ad Shield Card & Assistant
        col.addView(buildChromeAssistantCard())

        // TikTok & Blocked Apps Assistant Card
        col.addView(buildTikTokAssistantCard())

        // Video Compatibility Incident Monitor Card
        val incCard = cardLayout().apply {
            layoutParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                topMargin = dp(14)
            }
        }
        incCard.addView(sectionTitle("مراقب أعطال الفيديو الفوري (إلغاء القاعدة بنقرة)"))
        incCard.addView(TextView(this).apply {
            text = "يرصد المحرك تلقائيًا أي نطاق محجوب يُعاد طلبه بكثافة أو يُطلب من تطبيق فيديو لتعطيل القاعدة المتسببة فورًا:"
            setTextColor(COLOR_TEXT_SECONDARY)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 11.5f)
            setPadding(0, 0, 0, dp(8))
        })
        incidentsContainer = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
        }
        incCard.addView(incidentsContainer)
        col.addView(incCard)

        // Honest Technical Transparency Card
        val noteCard = cardLayout().apply {
            layoutParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                topMargin = dp(14)
            }
        }
        noteCard.addView(sectionTitle("توضيح تقني شفاف حول إعلانات المنصات"))
        noteCard.addView(TextView(this).apply {
            text = "• يحجب التطبيق بفعالية جميع نطاقات شبكات الإعلانات والمتتبعات في المتصفحات والتطبيقات والألعاب، بالإضافة إلى النطاقات الإعلانية المخصصة مثل ads.youtube.com وan.facebook.com.\n" +
                "• الإعلانات المدمجة داخل نفس تدفق الفيديو الأساسي في تطبيقي YouTube وTikTok تُقدَّم من نفس خوادم محتوى الفيديو (googlevideo.com / tiktokcdn.com) عبر اتصال HTTPS مشفر.\n" +
                "• لا يمكن تقنيًا لأي فلتر DNS حجب تلك الإعلانات المدمجة دون قطع الفيديو نفسه أو كسر تشفير HTTPS (MITM)، وهو ما يرفضه هذا التطبيق حفاظًا على أمانك واستقرار تشغيل الفيديو وتوصياتك."
            setTextColor(COLOR_TEXT_SECONDARY)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f)
        })
        col.addView(noteCard)

        scroll.addView(col)
        updateDashboardStats(repo.stats.value)
        renderVideoIncidents(repo.videoIncidents.value)
        return scroll
    }

    private fun buildChromeAssistantCard(): View {
        val card = cardLayout().apply {
            layoutParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                topMargin = dp(14)
            }
        }
        card.addView(sectionTitle("🌐 حل مشكلة إعلانات متصفح Google Chrome"))

        val isChromeInstalled = isPackageInstalled("com.android.chrome")
        val statusText = if (isChromeInstalled) "✓ متصفح Google Chrome مثبت على هذا الهاتف" else "ℹ متصفح Google Chrome غير مثبت"
        card.addView(TextView(this).apply {
            text = statusText
            setTextColor(if (isChromeInstalled) COLOR_STATUS_GREEN else COLOR_TEXT_SECONDARY)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f)
            setTypeface(typeface, Typeface.BOLD)
            setPadding(0, 0, 0, dp(4))
        })

        card.addView(TextView(this).apply {
            text = "متصفح Chrome يحتوي على ميزة مدمجة تسمى (استخدام نظام DNS الآمن / Use secure DNS) قد تتجاوز VPN المحلي وتستدعي خوادم مشفرة مباشرة، كما يحتفظ كروم بذاكرة كاش سابقة للإعلانات. اتبع الخطوتين التاليتين لتفعيل الحظر الكامل:"
            setTextColor(COLOR_TEXT_SECONDARY)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f)
            setPadding(0, 0, 0, dp(8))
        })

        // Step 1
        card.addView(TextView(this).apply {
            text = "الخطوة 1: ضبط DNS داخل Google Chrome\nافتح Chrome > القائمة (⋮) > الإعدادات > الخصوصية والأمان > استخدام نظام DNS الآمن > اختر «إيقاف»."
            setTextColor(COLOR_TEXT_PRIMARY)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f)
            setPadding(dp(8), dp(6), dp(8), dp(6))
            background = roundedDrawable(COLOR_BG_SURFACE, COLOR_BORDER, dp(8), dp(1))
        })

        // Step 2
        card.addView(TextView(this).apply {
            text = "الخطوة 2: مسح كاش كروم وإعادة فتحه\nاضغط على الزر أدناه لإيقاف كروم إجباريًا ومسح ذاكرة التخزين المؤقتة لإنهاء الجلسات الإعلانية القديمة."
            setTextColor(COLOR_TEXT_PRIMARY)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f)
            setPadding(dp(8), dp(6), dp(8), dp(6))
            background = roundedDrawable(COLOR_BG_SURFACE, COLOR_BORDER, dp(8), dp(1))
            (layoutParams as? ViewGroup.MarginLayoutParams)?.topMargin = dp(6)
        })

        // Quick Chrome Ad Test Button
        card.addView(actionButton("⚡ فحص حظر نطاقات إعلانات Chrome الآن") {
            testChromeAdBlockingLive()
        })

        // Clear Chrome Cache Button
        card.addView(actionButton("⚙️ فتح إعدادات تطبيق Chrome (لمسح الكاش)") {
            openChromeAppSettings()
        })

        // Launch Chrome Button
        card.addView(actionButton("🚀 فتح متصفح Google Chrome للتجربة") {
            openChromeBrowser()
        })

        return card
    }

    private fun buildTikTokAssistantCard(): View {
        val card = cardLayout().apply {
            layoutParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                topMargin = dp(14)
            }
        }
        card.addView(sectionTitle("🎵 مساعد تشغيل TikTok وتوضيح الحظر في الأردن"))

        val tiktokPkgs = listOf("com.zhiliaoapp.musically", "com.ss.android.ugc.trill", "com.zhiliaoapp.musically.go")
        val installedPkg = tiktokPkgs.firstOrNull { isPackageInstalled(it) }
        val isTikTokInstalled = installedPkg != null

        val statusText = if (isTikTokInstalled) "✓ تطبيق TikTok مثبت على هذا الجهاز ($installedPkg)" else "ℹ تطبيق TikTok غير مثبت كحزمة قياسية"
        card.addView(TextView(this).apply {
            text = statusText
            setTextColor(if (isTikTokInstalled) COLOR_STATUS_GREEN else COLOR_TEXT_SECONDARY)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f)
            setTypeface(typeface, Typeface.BOLD)
            setPadding(0, 0, 0, dp(4))
        })

        card.addView(TextView(this).apply {
            text = "يتطلب TikTok على شبكة محجوبة اتصالًا حقيقيًا بخادم VPN (WireGuard أو Xray) — درع DNS المحلي وحده لا يكفي لأنه لا يغيّر عنوان IP.\n" +
                "• يجب أن يمر TikTok داخل النفق (غير مستثنى).\n" +
                "• لا يوجد بروتوكول يضمن تجاوز كل أشكال الحجب؛ إذا فشل WireGuard (UDP) جرّب Xray REALITY.\n" +
                "• تغيير IP قد يؤثر على المحتوى المقترح لأن الخدمة تستخدم الموقع ومعلومات الشبكة.\n" +
                "• حالة الاختبار: لم يُختبر بعد على هاتف وشبكة محجوبة."
            setTextColor(COLOR_TEXT_SECONDARY)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f)
            setPadding(0, 0, 0, dp(8))
        })

        val excluded = tiktokPkgs.filter { repo.getAppMode(it) == AppMode.EXCLUDED }
        if (excluded.isNotEmpty()) {
            card.addView(actionButton("⚠ TikTok مستثنى من النفق — اضغط لإعادته داخل VPN") {
                for (pkg in tiktokPkgs) repo.setAppMode(pkg, AppMode.FILTER)
                Toast.makeText(this, "TikTok سيمر عبر النفق عند الاتصال التالي", Toast.LENGTH_SHORT).show()
                recreate()
            })
        }

        if (isTikTokInstalled && installedPkg != null) {
            // Launch TikTok
            card.addView(actionButton("🚀 فتح تطبيق TikTok لتجربة الاتصال") {
                val launchIntent = packageManager.getLaunchIntentForPackage(installedPkg)
                if (launchIntent != null) {
                    startActivity(launchIntent)
                } else {
                    Toast.makeText(this, "تعذر تشغيل تطبيق TikTok", Toast.LENGTH_SHORT).show()
                }
            })
        }

        return card
    }

    private fun isPackageInstalled(pkg: String): Boolean = runCatching {
        packageManager.getPackageInfo(pkg, 0) != null
    }.getOrDefault(false)

    private fun openChromeAppSettings() {
        val intent = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
            data = Uri.parse("package:com.android.chrome")
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        runCatching { startActivity(intent) }.onFailure {
            Toast.makeText(this, "تعذر فتح إعدادات Chrome، تأكد من تثبيته", Toast.LENGTH_SHORT).show()
        }
    }

    private fun openChromeBrowser() {
        val launchIntent = packageManager.getLaunchIntentForPackage("com.android.chrome")
        if (launchIntent != null) {
            startActivity(launchIntent)
        } else {
            runCatching {
                startActivity(Intent(Intent.ACTION_VIEW, Uri.parse("https://google.com")))
            }.onFailure {
                Toast.makeText(this, "تعذر تشغيل Chrome", Toast.LENGTH_SHORT).show()
            }
        }
    }

    private fun testChromeAdBlockingLive() {
        val targets = listOf(
            "googleads.g.doubleclick.net" to "Google Ads / DoubleClick",
            "pagead2.googlesyndication.com" to "Google AdSense",
            "adservice.google.com" to "Google AdService العالمي",
            "adservice.google.com.eg" to "Google AdService الإقليمي (مصر/العالم العربي)",
            "pagead2.googleadservices.com" to "Google AdServices Script",
            "securepubads.g.doubleclick.net" to "DoubleClick PubAds",
            "dns.google" to "Google DoH Bypass Endpoint",
            "chrome.cloudflare-dns.com" to "Chrome Cloudflare DoH",
        )
        val sb = StringBuilder()
        var allPassed = true
        for ((domain, label) in targets) {
            val dec = repo.engine.evaluate(domain, AppMode.FILTER)
            val pass = dec.blocked
            if (!pass) allPassed = false
            val icon = if (pass) "✅ محجوب" else "❌ مسموح"
            sb.append("$icon : $label\n   $domain [${dec.reason.labelAr}]\n\n")
        }
        val summary = if (allPassed) {
            "🎉 ممتاز! جميع نطاقات إعلانات Chrome ونطاقات تجاوز DoH محجوبة بنجاح (8/8).\nإذا استمر ظهور الإعلانات، قم بإيقاف خيار (DNS الآمن) داخل كروم وامسح الكاش كما هو مشروح أعلاه."
        } else {
            "⚠️ تنبيه: بعض النطاقات لم تُحجب. تأكد من تفعيل الحماية وقوائم الفلترة."
        }
        AlertDialog.Builder(this)
            .setTitle("نتيجة فحص حظر إعلانات Chrome")
            .setMessage("$summary\n\n$sb")
            .setPositiveButton("حسنًا", null)
            .setNeutralButton("فتح إعدادات Chrome") { _, _ -> openChromeAppSettings() }
            .show()
    }

    private fun updateDashboardStats(st: VpnStats) {
        val dnsMode = repo.activeProtocol.value == VpnProtocol.LOCAL_DNS_SHIELD
        val ts: TunnelStatus = TunnelManager.status.value
        val state: VpnState = if (dnsMode) st.vpnState else ts.state
        val ring = powerCircle
        val busy = state.isBusy
        if (ring != null) {
            val strokeColor = when {
                state == VpnState.CONNECTED -> COLOR_STATUS_GREEN
                state == VpnState.LOCAL_DNS_ONLY -> COLOR_ACCENT_BLUE
                busy -> COLOR_STATUS_AMBER
                state == VpnState.ERROR -> COLOR_STATUS_RED
                else -> COLOR_ACCENT_BLUE
            }
            val fillColor = when {
                state == VpnState.CONNECTED -> COLOR_STATUS_GREEN_SOFT
                busy -> COLOR_STATUS_AMBER_SOFT
                state == VpnState.ERROR -> COLOR_STATUS_RED_SOFT
                else -> COLOR_ACCENT_SOFT
            }
            ring.background = GradientDrawable().apply {
                shape = GradientDrawable.OVAL
                setColor(fillColor)
                setStroke(dp(4), strokeColor)
            }
            (ring.getChildAt(1) as? TextView)?.text = when {
                state == VpnState.CONNECTED || state == VpnState.LOCAL_DNS_ONLY -> "إيقاف"
                busy -> "إلغاء"
                state == VpnState.ERROR -> "إعادة المحاولة"
                dnsMode -> "تشغيل الحجب"
                else -> "اتصال"
            }
        }

        powerStateTitle?.text = when {
            state == VpnState.ERROR && !dnsMode -> "فشل الاتصال"
            else -> state.labelAr
        }
        powerStateTitle?.setTextColor(
            when {
                state == VpnState.CONNECTED -> COLOR_STATUS_GREEN
                busy -> COLOR_STATUS_AMBER
                state == VpnState.ERROR -> COLOR_STATUS_RED
                else -> COLOR_TEXT_PRIMARY
            }
        )

        powerStateSubtitle?.text = if (dnsMode) {
            when (state) {
                VpnState.LOCAL_DNS_ONLY -> "فلترة DNS على الجهاز فقط — لا يوجد خادم، لا تشفير لحركة المرور، وعنوان IP لم يتغير"
                else -> "وضع درع DNS المحلي (ليس VPN)"
            }
        } else {
            val since = if (ts.connectedSinceMs > 0) (System.currentTimeMillis() - ts.connectedSinceMs) / 1000 else 0
            when (state) {
                VpnState.CONNECTED -> buildString {
                    append("${ts.engine?.labelAr} • ${ts.serverName}\n")
                    append("IP المتحقق منه: ${ts.verifiedPublicIp} • الدولة: ${ts.verifiedCountry ?: "?"}\n")
                    append("RTT: ${ts.pingMs?.let { "$it ms" } ?: "—"} • الإنترنت: ${if (ts.internetOk == true) "يعمل" else "؟"}\n")
                    append("مدة الاتصال: ${since / 60}د ${since % 60}ث • ↓ ${fmtBytes(ts.rxBytes)} ↑ ${fmtBytes(ts.txBytes)}")
                    if (ts.lastHandshakeMs > 0) append("\nآخر مصافحة: منذ ${(System.currentTimeMillis() - ts.lastHandshakeMs) / 1000} ث")
                }
                VpnState.ERROR -> ts.errorAr ?: "خطأ غير معروف"
                VpnState.DISCONNECTED -> TunnelManager.servers.active()?.let { "الخادم: ${it.name}" } ?: "لا يوجد خادم — اضغط «اتصال» لإضافة رمز التسجيل"
                else -> "${ts.engine?.labelAr ?: ""} ${ts.serverName ?: ""}"
            }
        }

        val active = TunnelManager.servers.active()
        serverTitleTv?.text = active?.name ?: "لا يوجد خادم مضاف"
        serverDetailTv?.text = when {
            active == null -> "لا توجد خوادم وهمية في هذا الإصدار. أضف خادمك الحقيقي برمز التسجيل."
            else -> {
                val ip = active.provisioned?.publicIp ?: active.enrollment?.serverIp ?: "ملف يدوي"
                val proto = if (active.supportsXray) "WireGuard + Xray REALITY" else "WireGuard"
                val cc = active.lastVerifiedCountry?.let { "دولة الخروج المقاسة: $it" } ?: "الدولة: لم يُتحقق بعد"
                "$ip • $proto • $cc"
            }
        }
        if (ts.state == VpnState.CONNECTED) {
            publicIpTv?.text = "✓ IP الخروج المتحقق منه عبر النفق: ${ts.verifiedPublicIp} (${ts.verifiedCountry ?: "?"})"
        }

        statBlockedTv?.text = st.blockedQueries.toString()
        statTotalTv?.text = st.totalQueries.toString()
        statVideoProtTv?.text = st.protectedVideoQueries.toString()
        statRecProtTv?.text = st.protectedRecommendationQueries.toString()
        statCacheTv?.text = "${st.cachedQueries} (${st.cacheSize})"
        statRulesTv?.text = st.totalActiveRules.toString()

        dnsStatusTitleTv?.text = when {
            !dnsMode && ts.state == VpnState.CONNECTED -> "DNS عبر النفق: ${if (TunnelManager.adBlockDns) "AdGuard DNS (حجب إعلانات)" else "Cloudflare 1.1.1.1"}"
            dnsMode && st.running -> "درع DNS المحلي يعمل (بدون خادم VPN)"
            else -> "غير نشط"
        }
        val up = if (st.upstreamServers.isNotEmpty()) st.upstreamServers.joinToString(" , ") else "—"
        dnsStatusDetailTv?.text = "تقسيم النفق: ${st.splitMode.titleAr}" + if (dnsMode) " | خوادم DNS المحلية: $up | آخر زمن DNS: ${st.lastLatencyMs} ms" else ""
    }

    private fun fmtBytes(b: Long): String = when {
        b >= 1L shl 30 -> "%.2f GB".format(b / (1L shl 30).toDouble())
        b >= 1L shl 20 -> "%.1f MB".format(b / (1L shl 20).toDouble())
        b >= 1L shl 10 -> "%.0f KB".format(b / 1024.0)
        else -> "$b B"
    }

    private fun renderVideoIncidents(incidents: List<VideoIncident>) {
        val box = incidentsContainer ?: return
        box.removeAllViews()
        if (incidents.isEmpty()) {
            box.addView(TextView(this).apply {
                text = "لا توجد أي قواعد حجب متعارضة مع تشغيل الفيديو حاليًا ✓"
                setTextColor(COLOR_STATUS_GREEN)
                setTextSize(TypedValue.COMPLEX_UNIT_SP, 12.5f)
            })
            return
        }
        for (inc in incidents.take(10)) {
            val row = LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL
                background = roundedDrawable(COLOR_BG_CARD_ELEVATED, COLOR_STATUS_AMBER, dp(10), dp(1))
                setPadding(dp(12), dp(10), dp(12), dp(10))
                layoutParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                    bottomMargin = dp(8)
                }
            }
            row.addView(TextView(this).apply {
                text = "نطاق محجوب: ${inc.domain} (تكرر ${inc.count}×)"
                setTextColor(COLOR_TEXT_PRIMARY)
                setTextSize(TypedValue.COMPLEX_UNIT_SP, 13f)
                setTypeface(typeface, Typeface.BOLD)
            })
            row.addView(TextView(this).apply {
                text = "القاعدة: ${inc.rule ?: inc.domain} (${inc.source ?: "قائمة"}) | ${inc.signals.joinToString(" • ")}"
                setTextColor(COLOR_TEXT_SECONDARY)
                setTextSize(TypedValue.COMPLEX_UNIT_SP, 11.5f)
            })
            row.addView(actionButton("تعطيل القاعدة والسماح لـ ${inc.domain} فورًا") {
                val target = inc.rule?.removePrefix("||")?.trimEnd('^')?.takeIf { !it.contains('*') } ?: inc.domain
                repo.addUserAllow(target)
                Toast.makeText(this, "تم استثناء $target وتفريغ الكاش فورًا", Toast.LENGTH_SHORT).show()
            })
            box.addView(row)
        }
    }

    private fun toggleVpnProtection() {
        val proto = repo.activeProtocol.value
        if (proto == VpnProtocol.LOCAL_DNS_SHIELD) {
            if (TunnelManager.isActive()) TunnelManager.disconnect()
            if (repo.vpnRunning.value) {
                startService(Intent(this, SmartAdShieldVpnService::class.java).setAction(SmartAdShieldVpnService.ACTION_STOP))
            } else {
                withVpnPermission { startVpnServiceInternal() }
            }
            return
        }
        if (repo.vpnRunning.value) {
            startService(Intent(this, SmartAdShieldVpnService::class.java).setAction(SmartAdShieldVpnService.ACTION_STOP))
        }
        if (TunnelManager.isActive()) {
            TunnelManager.disconnect()
        } else {
            if (TunnelManager.servers.list().isEmpty()) {
                showAddEnrollmentDialog()
                return
            }
            withVpnPermission { TunnelManager.connect(proto) }
        }
    }

    private fun withVpnPermission(action: () -> Unit) {
        val prep = VpnService.prepare(this)
        if (prep != null) {
            pendingAfterPermission = action
            vpnPermissionLauncher.launch(prep)
        } else {
            action()
        }
    }

    private fun startVpnServiceInternal() {
        val intent = Intent(this, SmartAdShieldVpnService::class.java).setAction(SmartAdShieldVpnService.ACTION_START)
        ContextCompat.startForegroundService(this, intent)
    }

    // ------------------------------------------------------------------ Tab 1: Live Query Log

    private fun buildQueryLogTab(): View {
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(14), dp(12), dp(14), dp(12))
        }

        val controls = cardLayout()
        controls.addView(sectionTitle("سجل طلبات DNS اللحظي (اضغط على أي نطاق للسماح أو الحجب الفوري)"))

        val searchInput = EditText(this).apply {
            hint = "ابحث عن نطاق أو تطبيق..."
            setHintTextColor(COLOR_TEXT_MUTED)
            setTextColor(COLOR_TEXT_PRIMARY)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 13f)
            setText(logSearchQuery)
        }
        controls.addView(searchInput)

        val filterRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(0, dp(6), 0, 0)
        }
        val btnAll = smallPillButton("الكل", !logBlockedOnly) {
            logBlockedOnly = false
            logSearchQuery = searchInput.text.toString().trim()
            switchTab(1)
        }
        val btnBlocked = smallPillButton("المحجوب فقط", logBlockedOnly) {
            logBlockedOnly = true
            logSearchQuery = searchInput.text.toString().trim()
            switchTab(1)
        }
        val btnSearch = smallPillButton("تطبيق البحث", false) {
            logSearchQuery = searchInput.text.toString().trim()
            renderLogEvents(repo.queryLog.value)
        }
        val btnClear = smallPillButton("مسح السجل", false) {
            repo.clearQueryLog()
        }
        filterRow.addView(btnAll)
        filterRow.addView(btnBlocked)
        filterRow.addView(btnSearch)
        filterRow.addView(btnClear)
        controls.addView(filterRow)
        root.addView(controls)

        val scroll = ScrollView(this).apply {
            layoutParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f).apply {
                topMargin = dp(10)
            }
        }
        logListContainer = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
        }
        scroll.addView(logListContainer)
        root.addView(scroll)

        renderLogEvents(repo.queryLog.value)
        return root
    }

    private fun renderLogEvents(events: List<QueryEvent>) {
        val container = logListContainer ?: return
        container.removeAllViews()

        val q = logSearchQuery.lowercase()
        val filtered = events.filter { e ->
            (!logBlockedOnly || e.decision.blocked) &&
                (q.isEmpty() || e.domain.contains(q) || (e.app?.label?.lowercase()?.contains(q) == true))
        }

        if (filtered.isEmpty()) {
            container.addView(TextView(this).apply {
                text = "لا توجد طلبات مسجلة تطابق الفلتر الحالي."
                setTextColor(COLOR_TEXT_SECONDARY)
                gravity = Gravity.CENTER
                setPadding(dp(16), dp(32), dp(16), dp(32))
            })
            return
        }

        for (e in filtered.take(150)) {
            val blocked = e.decision.blocked
            val badgeColor = when {
                blocked -> COLOR_STATUS_RED
                e.decision.reason.name.contains("PROTECTED") -> COLOR_ACCENT_BLUE
                else -> COLOR_STATUS_GREEN
            }
            val row = LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL
                background = roundedDrawable(COLOR_BG_CARD, COLOR_BORDER, dp(10), dp(1))
                setPadding(dp(12), dp(10), dp(12), dp(10))
                layoutParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                    bottomMargin = dp(8)
                }
            }

            val topLine = LinearLayout(this).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
            }
            topLine.addView(TextView(this).apply {
                text = if (blocked) "محجوب" else "مسموح"
                setTextColor(badgeColor)
                setTextSize(TypedValue.COMPLEX_UNIT_SP, 11.5f)
                setTypeface(typeface, Typeface.BOLD)
                setPadding(dp(8), dp(2), dp(8), dp(2))
                background = roundedDrawable(
                    if (blocked) COLOR_STATUS_RED_SOFT else COLOR_STATUS_GREEN_SOFT,
                    badgeColor,
                    dp(6),
                    dp(1)
                )
            })
            topLine.addView(TextView(this).apply {
                text = "  ${e.domain}"
                setTextColor(COLOR_TEXT_PRIMARY)
                setTextSize(TypedValue.COMPLEX_UNIT_SP, 13f)
                setTypeface(typeface, Typeface.BOLD)
                ellipsize = TextUtils.TruncateAt.MIDDLE
                setSingleLine(true)
                layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
            })
            topLine.addView(TextView(this).apply {
                text = timeFormat.format(Date(e.time))
                setTextColor(COLOR_TEXT_MUTED)
                setTextSize(TypedValue.COMPLEX_UNIT_SP, 11f)
            })
            row.addView(topLine)

            val appName = e.app?.label ?: "النظام / مشترك"
            val qtype = DnsMessage.typeName(e.qtype)
            val cacheTag = if (e.cached) " • كاش" else " • ${e.latencyMs}ms"
            val ruleInfo = if (e.decision.rule != null) " (${e.decision.rule})" else ""
            row.addView(TextView(this).apply {
                text = "$appName • $qtype • ${e.decision.reason.labelAr}$ruleInfo$cacheTag"
                setTextColor(COLOR_TEXT_SECONDARY)
                setTextSize(TypedValue.COMPLEX_UNIT_SP, 11.5f)
                setPadding(0, dp(4), 0, dp(4))
            })

            val actionBtn = TextView(this).apply {
                text = if (blocked) "إلغاء الحجب (إضافة إلى Allowlist)" else "حجب هذا النطاق (إضافة إلى Blocklist)"
                setTextColor(COLOR_ACCENT_BLUE)
                setTextSize(TypedValue.COMPLEX_UNIT_SP, 11.5f)
                setTypeface(typeface, Typeface.BOLD)
                setOnClickListener {
                    if (blocked) {
                        repo.addUserAllow(e.domain)
                        Toast.makeText(this@MainActivity, "تم السماح بـ ${e.domain} فورًا", Toast.LENGTH_SHORT).show()
                    } else {
                        repo.addUserBlock(e.domain)
                        Toast.makeText(this@MainActivity, "تم حجب ${e.domain} فورًا", Toast.LENGTH_SHORT).show()
                    }
                    renderLogEvents(repo.queryLog.value)
                }
            }
            row.addView(actionBtn)
            container.addView(row)
        }
    }

    // ------------------------------------------------------------------ Tab 2: Lists & Custom Rules

    private fun buildListsAndRulesTab(): View {
        val scroll = ScrollView(this)
        val col = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(16), dp(14), dp(16), dp(28))
        }

        // Subscriptions Card
        val subCard = cardLayout()
        subCard.addView(sectionTitle("قوائم الفلترة القابلة للتحديث (مع التحقق من السلامة)"))
        subCard.addView(TextView(this).apply {
            text = "يستخلص المحرك فقط القواعد المتوافقة مع DNS (Hosts و ||domain^) ويتجاهل قواعد التجميل (##) والقواعد التي قد تسبب كسر المواقع."
            setTextColor(COLOR_TEXT_SECONDARY)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 11.5f)
            setPadding(0, 0, 0, dp(8))
        })

        updateListsStatusTv = TextView(this).apply {
            setTextColor(COLOR_ACCENT_BLUE)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f)
            visibility = View.GONE
        }
        subCard.addView(updateListsStatusTv)

        val btnRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            setPadding(0, 0, 0, dp(8))
        }
        btnRow.addView(actionButton("تحديث القوائم المفعلة الآن") {
            triggerUpdateAllSubscriptions()
        }.apply {
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply { leftMargin = dp(6) }
        })
        btnRow.addView(actionButton("+ إضافة قائمة خارجية") {
            showAddSubscriptionDialog()
        }.apply {
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
        })
        subCard.addView(btnRow)

        listsContainer = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        subCard.addView(listsContainer)
        col.addView(subCard)

        // Allowlist Card
        val allowCard = cardLayout().apply {
            layoutParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                topMargin = dp(14)
            }
        }
        allowCard.addView(sectionTitle("قائمة السماح المخصصة (Allowlist - أولوية قصوى)"))
        val allowInputRow = domainInputRow("أدخل نطاقًا لاستثنائه مثل example.com", "إضافة للسماح") { d ->
            if (repo.addUserAllow(d)) {
                renderSubscriptionsAndRules()
            } else {
                Toast.makeText(this, "صيغة النطاق غير صحيحة", Toast.LENGTH_SHORT).show()
            }
        }
        allowCard.addView(allowInputRow)
        allowChipsContainer = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(0, dp(8), 0, 0)
        }
        allowCard.addView(allowChipsContainer)
        col.addView(allowCard)

        // Blocklist Card
        val blockCard = cardLayout().apply {
            layoutParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                topMargin = dp(14)
            }
        }
        blockCard.addView(sectionTitle("قائمة الحجب المخصصة (Blocklist)"))
        val blockInputRow = domainInputRow("أدخل نطاقًا لحجبه مثل ads.example.com", "إضافة للحجب") { d ->
            if (repo.addUserBlock(d)) {
                renderSubscriptionsAndRules()
            } else {
                Toast.makeText(this, "صيغة النطاق غير صحيحة", Toast.LENGTH_SHORT).show()
            }
        }
        blockCard.addView(blockInputRow)
        blockChipsContainer = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(0, dp(8), 0, 0)
        }
        blockCard.addView(blockChipsContainer)
        col.addView(blockCard)

        scroll.addView(col)
        renderSubscriptionsAndRules()
        return scroll
    }

    private fun renderSubscriptionsAndRules() {
        val listBox = listsContainer ?: return
        listBox.removeAllViews()
        for (sub in repo.subscriptions.value) {
            val item = LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL
                background = roundedDrawable(COLOR_BG_CARD_ELEVATED, COLOR_BORDER, dp(10), dp(1))
                setPadding(dp(12), dp(10), dp(12), dp(10))
                layoutParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                    bottomMargin = dp(8)
                }
            }
            val header = LinearLayout(this).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
            }
            header.addView(TextView(this).apply {
                text = sub.name
                setTextColor(COLOR_TEXT_PRIMARY)
                setTextSize(TypedValue.COMPLEX_UNIT_SP, 13.5f)
                setTypeface(typeface, Typeface.BOLD)
                layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
            })
            val sw = Switch(this).apply {
                isChecked = sub.enabled
                setOnCheckedChangeListener { _, checked ->
                    repo.setSubscriptionEnabled(sub.id, checked)
                }
            }
            header.addView(sw)
            item.addView(header)

            item.addView(TextView(this).apply {
                text = sub.description
                setTextColor(COLOR_TEXT_SECONDARY)
                setTextSize(TypedValue.COMPLEX_UNIT_SP, 11.5f)
            })

            val statusText = buildString {
                append("القواعد المحملة: ${sub.ruleCount}")
                if (sub.lastUpdated > 0) {
                    append(" • آخر تحديث: ${timeFormat.format(Date(sub.lastUpdated))}")
                } else {
                    append(" • لم يتم التحميل بعد (اضغط تحديث)")
                }
                if (sub.lastError != null) {
                    append(" • خطأ: ${sub.lastError}")
                }
            }
            item.addView(TextView(this).apply {
                text = statusText
                setTextColor(if (sub.lastError != null) COLOR_STATUS_AMBER else COLOR_ACCENT_BLUE)
                setTextSize(TypedValue.COMPLEX_UNIT_SP, 11.5f)
                setPadding(0, dp(4), 0, dp(4))
            })

            val actions = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
            actions.addView(smallPillButton("تحديث هذه القائمة", false) {
                triggerUpdateSingleSubscription(sub)
            })
            if (!sub.id.startsWith("builtin_")) {
                actions.addView(smallPillButton("حذف", false) {
                    repo.removeSubscription(sub.id)
                })
            }
            item.addView(actions)
            listBox.addView(item)
        }

        // Render Allowlist
        val allowBox = allowChipsContainer ?: return
        allowBox.removeAllViews()
        val allows = repo.userAllow.value
        if (allows.isEmpty()) {
            allowBox.addView(TextView(this).apply {
                text = "لا توجد نطاقات مضافة في قائمة السماح الخاصة."
                setTextColor(COLOR_TEXT_MUTED)
                setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f)
            })
        } else {
            for (d in allows) {
                allowBox.addView(domainRuleRow(d, true) {
                    repo.removeUserAllow(d)
                    renderSubscriptionsAndRules()
                })
            }
        }

        // Render Blocklist
        val blockBox = blockChipsContainer ?: return
        blockBox.removeAllViews()
        val blocks = repo.userBlock.value
        if (blocks.isEmpty()) {
            blockBox.addView(TextView(this).apply {
                text = "لا توجد نطاقات مضافة في قائمة الحجب الخاصة."
                setTextColor(COLOR_TEXT_MUTED)
                setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f)
            })
        } else {
            for (d in blocks) {
                blockBox.addView(domainRuleRow(d, false) {
                    repo.removeUserBlock(d)
                    renderSubscriptionsAndRules()
                })
            }
        }
    }

    private fun triggerUpdateSingleSubscription(sub: FilterSubscription) {
        updateListsStatusTv?.visibility = View.VISIBLE
        updateListsStatusTv?.text = "جاري تنزيل وفحص سلامة ${sub.name}..."
        uiScope.launch {
            val res = withContext(Dispatchers.IO) { repo.updateSubscriptionNow(sub.id) }
            updateListsStatusTv?.text = res.fold(
                onSuccess = { "تم تحديث ${it.name} بنجاح (${it.ruleCount} قاعدة متوافقة مع DNS) ✓" },
                onFailure = { "فشل تحديث ${sub.name}: ${it.message}" }
            )
            renderSubscriptionsAndRules()
        }
    }

    private fun triggerUpdateAllSubscriptions() {
        updateListsStatusTv?.visibility = View.VISIBLE
        uiScope.launch {
            val count = withContext(Dispatchers.IO) {
                repo.updateAllEnabledSubscriptions { msg ->
                    runOnUiThread { updateListsStatusTv?.text = msg }
                }
            }
            updateListsStatusTv?.text = "اكتمل تحديث $count قوائم والتحقق من سلامتها وتفعيلها ✓"
            renderSubscriptionsAndRules()
        }
    }

    private fun showAddSubscriptionDialog() {
        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), dp(12), dp(20), dp(8))
        }
        val nameEt = EditText(this).apply { hint = "اسم القائمة (مثال: AdGuard Mobile)" }
        val urlEt = EditText(this).apply {
            hint = "رابط https://..."
            inputType = InputType.TYPE_TEXT_VARIATION_URI
        }
        layout.addView(nameEt)
        layout.addView(urlEt)
        AlertDialog.Builder(this)
            .setTitle("إضافة قائمة فلترة خارجية")
            .setView(layout)
            .setPositiveButton("إضافة") { _, _ ->
                if (!repo.addCustomSubscription(nameEt.text.toString(), urlEt.text.toString())) {
                    Toast.makeText(this, "يرجى إدخال رابط يبدأ بـ https://", Toast.LENGTH_SHORT).show()
                }
            }
            .setNegativeButton("إلغاء", null)
            .show()
    }

    private fun showServerSelectionDialog() {
        val list = TunnelManager.servers.list()
        val activeId = TunnelManager.servers.activeId
        val names = list.map { e ->
            val where = e.provisioned?.publicIp ?: e.enrollment?.serverIp ?: "ملف WireGuard"
            val cc = e.lastVerifiedCountry?.let { " • دولة الخروج المقاسة: $it" } ?: " • لم يُتحقق بعد"
            val proto = if (e.supportsXray) "WireGuard + Xray" else "WireGuard"
            "${e.name} ($where) — $proto$cc"
        }.toTypedArray()
        val b = AlertDialog.Builder(this).setTitle(if (list.isEmpty()) "لا توجد خوادم بعد" else "اختر الخادم")
        if (list.isEmpty()) {
            b.setMessage("أضف خادمك الحقيقي عبر رمز التسجيل SHIELD1 (من مخرجات Oracle) أو استورد ملف WireGuard.")
        } else {
            b.setSingleChoiceItems(names, list.indexOfFirst { it.id == activeId }.coerceAtLeast(0)) { d, which ->
                TunnelManager.servers.activeId = list[which].id
                d.dismiss()
                switchTab(0)
            }
        }
        b.setPositiveButton("إضافة رمز تسجيل") { _, _ -> showAddEnrollmentDialog() }
            .setNeutralButton("استيراد .conf") { _, _ -> showImportWireGuardDialog() }
            .setNegativeButton(if (list.isEmpty()) "إغلاق" else "حذف المحدد") { _, _ ->
                val cur = TunnelManager.servers.active() ?: return@setNegativeButton
                if (list.isNotEmpty()) {
                    AlertDialog.Builder(this).setMessage("حذف ${cur.name} من الجهاز؟")
                        .setPositiveButton("حذف") { _, _ -> TunnelManager.servers.remove(cur.id); switchTab(0) }
                        .setNegativeButton("إلغاء", null).show()
                }
            }
            .show()
    }

    private fun showAddEnrollmentDialog() {
        val et = EditText(this).apply {
            hint = "SHIELD1:..."
            minLines = 3
            gravity = Gravity.TOP or Gravity.START
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
        }
        val clip = (getSystemService(CLIPBOARD_SERVICE) as? android.content.ClipboardManager)
            ?.primaryClip?.getItemAt(0)?.coerceToText(this)?.toString()
        if (clip != null && clip.trim().startsWith(EnrollmentCode.PREFIX)) et.setText(clip.trim())
        AlertDialog.Builder(this)
            .setTitle("إضافة خادم برمز التسجيل")
            .setMessage("الصق قيمة enrollment_code من صفحة Outputs في Oracle Cloud. تُحفظ مشفّرة على الهاتف، ويُولَّد مفتاح WireGuard الخاص على الهاتف فقط.")
            .setView(et)
            .setPositiveButton("تسجيل") { _, _ ->
                val code = et.text.toString()
                Toast.makeText(this, "جاري التسجيل لدى الخادم...", Toast.LENGTH_SHORT).show()
                uiScope.launch {
                    val r = withContext(Dispatchers.IO) { TunnelManager.enroll(code) }
                    r.fold(
                        onSuccess = { Toast.makeText(this@MainActivity, "تم تسجيل الجهاز لدى ${it.name} ✓", Toast.LENGTH_LONG).show() },
                        onFailure = { Toast.makeText(this@MainActivity, "فشل التسجيل: ${it.message}", Toast.LENGTH_LONG).show() },
                    )
                    switchTab(0)
                }
            }
            .setNegativeButton("إلغاء", null)
            .show()
    }

    private fun showImportWireGuardDialog() {
        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), dp(12), dp(20), dp(8))
        }
        val nameEt = EditText(this).apply {
            hint = "اسم الخادم"
            setSingleLine(true)
        }
        val confEt = EditText(this).apply {
            hint = "[Interface]\nPrivateKey = ...\nAddress = ...\n\n[Peer]\nPublicKey = ...\nEndpoint = ...\nAllowedIPs = 0.0.0.0/0"
            minLines = 6
            gravity = Gravity.TOP or Gravity.START
        }
        layout.addView(nameEt)
        layout.addView(confEt)
        AlertDialog.Builder(this)
            .setTitle("استيراد ملف WireGuard (اختياري)")
            .setView(layout)
            .setPositiveButton("استيراد") { _, _ ->
                val text = confEt.text.toString().trim()
                val ok = runCatching {
                    com.wireguard.config.Config.parse(java.io.BufferedReader(java.io.StringReader(text)))
                }
                ok.fold(
                    onSuccess = {
                        TunnelManager.servers.addManual(nameEt.text.toString().trim().ifEmpty { "WireGuard مستورد" }, text)
                        Toast.makeText(this, "تم الاستيراد ✓", Toast.LENGTH_SHORT).show()
                        switchTab(0)
                    },
                    onFailure = { Toast.makeText(this, "ملف غير صالح: ${it.message}", Toast.LENGTH_LONG).show() },
                )
            }
            .setNegativeButton("إلغاء", null)
            .show()
    }

    // ------------------------------------------------------------------ Tab 3: Per-App Protection & Split Tunneling

    private fun buildAppsTab(): View {
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(14), dp(12), dp(14), dp(12))
        }

        // Split Tunneling Mode Card
        val splitCard = cardLayout()
        splitCard.addView(sectionTitle("وضع تقسيم النفق (Split Tunneling)"))
        val modeRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(0, dp(4), 0, dp(4))
        }
        SplitTunnelingMode.values().forEach { mode ->
            val isActive = repo.splitTunnelingMode.value == mode
            modeRow.addView(smallPillButton(mode.titleAr.substringBefore(" ("), isActive) {
                repo.setSplitTunnelingMode(mode)
                Toast.makeText(this, "تم تفعيل: ${mode.titleAr}", Toast.LENGTH_SHORT).show()
                switchTab(3)
            })
        }
        val modeScroll = HorizontalScrollView(this).apply {
            isHorizontalScrollBarEnabled = false
            addView(modeRow)
        }
        splitCard.addView(modeScroll)
        splitCard.addView(TextView(this).apply {
            text = repo.splitTunnelingMode.value.descriptionAr
            setTextColor(COLOR_ACCENT_BLUE)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f)
            setPadding(0, dp(6), 0, 0)
        })
        root.addView(splitCard)

        val headerCard = cardLayout().apply {
            layoutParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                topMargin = dp(10)
            }
        }
        headerCard.addView(sectionTitle("إدارة التطبيقات والفلترة"))
        headerCard.addView(TextView(this).apply {
            text = "• حجب كامل: تطبيق جميع قوائم الإعلانات والتتبع.\n" +
                "• وضع التوافق الذكي: مفعّل تلقائيًا لـ YouTube وTikTok وInstagram وFacebook؛ يحمي التوصيات والفيديو ويحجب النطاقات الإعلانية المؤكدة فقط.\n" +
                "• مستثنى بالكامل: يمر اتصال التطبيق خارج الـ VPN المحلي تمامًا."
            setTextColor(COLOR_TEXT_SECONDARY)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 11.5f)
        })
        headerCard.addView(
            switchRow(
                title = "إظهار تطبيقات النظام",
                subtitle = "عرض خدمات النظام إلى جانب تطبيقات المستخدم",
                checked = showSystemApps
            ) {
                showSystemApps = it
                renderInstalledApps()
            }
        )
        root.addView(headerCard)

        val scroll = ScrollView(this).apply {
            layoutParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f).apply {
                topMargin = dp(10)
            }
        }
        appsListContainer = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        scroll.addView(appsListContainer)
        root.addView(scroll)

        uiScope.launch {
            val apps = cachedInstalledApps ?: withContext(Dispatchers.IO) { repo.listInstalledApps() }.also {
                cachedInstalledApps = it
            }
            renderInstalledApps(apps)
        }
        return root
    }

    private fun renderInstalledApps(source: List<InstalledAppItem>? = cachedInstalledApps) {
        val box = appsListContainer ?: return
        box.removeAllViews()
        if (source == null) {
            box.addView(TextView(this).apply {
                text = "جاري قراءة قائمة التطبيقات..."
                setTextColor(COLOR_TEXT_SECONDARY)
                gravity = Gravity.CENTER
                setPadding(dp(16), dp(24), dp(16), dp(24))
            })
            return
        }

        val visible = source.filter { showSystemApps || !it.isSystem || it.isRecommendedCompat }
        for (app in visible.take(150)) {
            val mode = repo.getAppMode(app.packageName)
            val card = LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL
                background = roundedDrawable(COLOR_BG_CARD, COLOR_BORDER, dp(10), dp(1))
                setPadding(dp(12), dp(10), dp(12), dp(10))
                layoutParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                    bottomMargin = dp(8)
                }
            }
            card.addView(TextView(this).apply {
                text = if (app.isRecommendedCompat) "★ ${app.label} (منصة فيديو/توصيات)" else app.label
                setTextColor(if (app.isRecommendedCompat) COLOR_ACCENT_BLUE else COLOR_TEXT_PRIMARY)
                setTextSize(TypedValue.COMPLEX_UNIT_SP, 13.5f)
                setTypeface(typeface, Typeface.BOLD)
            })
            card.addView(TextView(this).apply {
                text = app.packageName
                setTextColor(COLOR_TEXT_MUTED)
                setTextSize(TypedValue.COMPLEX_UNIT_SP, 11f)
                setPadding(0, 0, 0, dp(6))
            })

            val modeRow = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
            modeRow.addView(smallPillButton("حجب كامل", mode == AppMode.FILTER) {
                repo.setAppMode(app.packageName, AppMode.FILTER)
                renderInstalledApps()
            })
            modeRow.addView(smallPillButton("وضع التوافق", mode == AppMode.COMPAT) {
                repo.setAppMode(app.packageName, AppMode.COMPAT)
                renderInstalledApps()
            })
            modeRow.addView(smallPillButton("مستثنى", mode == AppMode.EXCLUDED) {
                repo.setAppMode(app.packageName, AppMode.EXCLUDED)
                renderInstalledApps()
            })
            card.addView(modeRow)
            box.addView(card)
        }
    }

    // ------------------------------------------------------------------ Tab 4: Diagnostics & Health Check

    private fun buildDiagnosticsTab(): View {
        val scroll = ScrollView(this)
        val col = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(16), dp(14), dp(16), dp(28))
        }

        val topCard = cardLayout()
        topCard.addView(sectionTitle("اختبار سلامة الاتصال والفحص الميداني الشامل (10 اختبارات)"))
        topCard.addView(TextView(this).apply {
            text = "ينفّذ هذا الفاحص اختبارات شبكية ومحلية حقيقية (دون أي بيانات وهمية) للتحقق من ثبات عنوان IP العام، سرعة DNS والكاش، حجب الإعلانات، توافق YouTube/TikTok/Instagram/Facebook، حماية الفيديو والـ CDN، تعارض Private DNS، دعم IPv6، وحماية إشارات التوصيات."
            setTextColor(COLOR_TEXT_SECONDARY)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f)
        })

        diagStatusTv = TextView(this).apply {
            text = "اضغط الزر أدناه لتنفيذ الاختبارات العشرة الآن."
            setTextColor(COLOR_ACCENT_BLUE)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 12.5f)
            setPadding(0, dp(8), 0, dp(8))
        }
        topCard.addView(diagStatusTv)

        topCard.addView(actionButton("تشغيل الاختبارات العشرة الشاملة الآن") {
            executeDiagnosticsSuite()
        })
        col.addView(topCard)

        val vpnCard = cardLayout().apply {
            layoutParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                topMargin = dp(12)
            }
        }
        vpnCard.addView(sectionTitle("تشخيص اتصال VPN الحقيقي"))
        val speedTv = TextView(this).apply {
            text = "اختبار السرعة يقيس تنزيل 10MB من Cloudflare: بدون VPN أو عبر النفق الحالي."
            setTextColor(COLOR_TEXT_SECONDARY)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f)
        }
        vpnCard.addView(speedTv)
        vpnCard.addView(actionButton("قياس السرعة الآن (بيانات حقيقية)") {
            speedTv.text = "جاري القياس..."
            uiScope.launch { speedTv.text = withContext(Dispatchers.IO) { TunnelManager.speedTest() } }
        })
        tunnelLogTv = TextView(this).apply {
            text = TunnelManager.status.value.log.reversed().joinToString("\n").ifEmpty { "لا توجد أحداث بعد." }
            setTextColor(COLOR_TEXT_PRIMARY)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 11f)
            typeface = Typeface.MONOSPACE
            setPadding(0, dp(8), 0, 0)
            setTextIsSelectable(true)
        }
        vpnCard.addView(tunnelLogTv)
        col.addView(vpnCard)

        diagContainer = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                topMargin = dp(12)
            }
        }
        col.addView(diagContainer)

        scroll.addView(col)
        lastReport?.let { renderDiagnosticReport(it) }
        return scroll
    }

    private fun executeDiagnosticsSuite() {
        diagStatusTv?.text = "جاري تنفيذ الاختبارات العشرة الفعلية... يرجى الانتظار ثواني قليلة"
        uiScope.launch {
            val upstreams = repo.stats.value.upstreamServers.mapNotNull {
                runCatching { InetAddress.getByName(it) }.getOrNull()
            }
            val pDns = repo.detectPrivateDnsStatus()
            val report = withContext(Dispatchers.IO) {
                DiagnosticsRunner.runFullSuite(
                    engine = repo.engine,
                    upstreamServers = upstreams,
                    privateDnsStatus = pDns,
                    baselinePublicIp = baselinePublicIp,
                )
            }
            if (report.publicIp != null && baselinePublicIp == null) {
                baselinePublicIp = report.publicIp
            }
            lastReport = report
            diagStatusTv?.text = "اكتملت الاختبارات في ${timeFormat.format(Date(report.timestamp))} ✓"
            renderDiagnosticReport(report)
        }
    }

    private fun renderDiagnosticReport(report: DiagnosticReport) {
        val box = diagContainer ?: return
        box.removeAllViews()
        for (item in report.items) {
            val (badgeColor, badgeBg, badgeLabel) = when (item.status) {
                CheckStatus.PASS -> Triple(COLOR_STATUS_GREEN, COLOR_STATUS_GREEN_SOFT, "ناجح ✓")
                CheckStatus.WARN -> Triple(COLOR_STATUS_AMBER, COLOR_STATUS_AMBER_SOFT, "تنبيه !")
                CheckStatus.FAIL -> Triple(COLOR_STATUS_RED, COLOR_STATUS_RED_SOFT, "فشل ✗")
            }
            val card = LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL
                background = roundedDrawable(COLOR_BG_CARD, badgeColor, dp(12), dp(1))
                setPadding(dp(14), dp(12), dp(14), dp(12))
                layoutParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                    bottomMargin = dp(10)
                }
            }
            val head = LinearLayout(this).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
            }
            head.addView(TextView(this).apply {
                text = item.titleAr
                setTextColor(COLOR_TEXT_PRIMARY)
                setTextSize(TypedValue.COMPLEX_UNIT_SP, 13.5f)
                setTypeface(typeface, Typeface.BOLD)
                layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
            })
            head.addView(TextView(this).apply {
                text = badgeLabel
                setTextColor(badgeColor)
                setTextSize(TypedValue.COMPLEX_UNIT_SP, 11.5f)
                setTypeface(typeface, Typeface.BOLD)
                setPadding(dp(8), dp(2), dp(8), dp(2))
                background = roundedDrawable(badgeBg, badgeColor, dp(6), dp(1))
            })
            card.addView(head)

            card.addView(TextView(this).apply {
                text = "القياس الفعلي: ${item.measuredValue}"
                setTextColor(COLOR_ACCENT_BLUE)
                setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f)
                setTypeface(typeface, Typeface.BOLD)
                setPadding(0, dp(4), 0, dp(4))
            })
            card.addView(TextView(this).apply {
                text = item.detailsAr
                setTextColor(COLOR_TEXT_SECONDARY)
                setTextSize(TypedValue.COMPLEX_UNIT_SP, 11.5f)
            })
            box.addView(card)
        }
    }

    // ------------------------------------------------------------------ UI building helpers

    private fun dp(v: Int): Int =
        TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, v.toFloat(), resources.displayMetrics).toInt()

    private fun roundedDrawable(fill: Int, stroke: Int, radiusPx: Int, strokeWidthPx: Int): GradientDrawable =
        GradientDrawable().apply {
            shape = GradientDrawable.RECTANGLE
            cornerRadius = radiusPx.toFloat()
            setColor(fill)
            setStroke(strokeWidthPx, stroke)
        }

    private fun cardLayout(): LinearLayout = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        background = roundedDrawable(COLOR_BG_CARD, COLOR_BORDER, dp(14), dp(1))
        setPadding(dp(14), dp(14), dp(14), dp(14))
        layoutParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT)
    }

    private fun sectionTitle(text: String): TextView = TextView(this).apply {
        this.text = text
        setTextColor(COLOR_ACCENT_BLUE)
        setTextSize(TypedValue.COMPLEX_UNIT_SP, 14f)
        setTypeface(typeface, Typeface.BOLD)
        setPadding(0, 0, 0, dp(8))
    }

    private fun statBox(label: String, initial: String, valueColor: Int): Pair<LinearLayout, TextView> {
        val box = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            background = roundedDrawable(COLOR_BG_CARD, COLOR_BORDER, dp(12), dp(1))
            setPadding(dp(12), dp(10), dp(12), dp(10))
        }
        val valTv = TextView(this).apply {
            text = initial
            setTextColor(valueColor)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 20f)
            setTypeface(typeface, Typeface.BOLD)
        }
        val lblTv = TextView(this).apply {
            text = label
            setTextColor(COLOR_TEXT_SECONDARY)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 11.5f)
        }
        box.addView(valTv)
        box.addView(lblTv)
        return box to valTv
    }

    private fun switchRow(
        title: String,
        subtitle: String,
        checked: Boolean,
        onChanged: (Boolean) -> Unit,
    ): View {
        val row = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(0, dp(8), 0, dp(8))
        }
        val textCol = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply {
                leftMargin = dp(8)
            }
        }
        textCol.addView(TextView(this).apply {
            text = title
            setTextColor(COLOR_TEXT_PRIMARY)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 13f)
            setTypeface(typeface, Typeface.BOLD)
        })
        textCol.addView(TextView(this).apply {
            text = subtitle
            setTextColor(COLOR_TEXT_SECONDARY)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 11.5f)
        })
        val sw = Switch(this).apply {
            isChecked = checked
            setOnCheckedChangeListener { _, isChecked -> onChanged(isChecked) }
        }
        row.addView(textCol)
        row.addView(sw)
        return row
    }

    private fun actionButton(label: String, onClick: () -> Unit): TextView = TextView(this).apply {
        text = label
        gravity = Gravity.CENTER
        setTextColor(COLOR_TEXT_PRIMARY)
        setTextSize(TypedValue.COMPLEX_UNIT_SP, 13f)
        setTypeface(typeface, Typeface.BOLD)
        setPadding(dp(12), dp(10), dp(12), dp(10))
        background = roundedDrawable(COLOR_ACCENT_SOFT, COLOR_ACCENT_BLUE, dp(10), dp(1))
        layoutParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
            topMargin = dp(8)
        }
        setOnClickListener { onClick() }
    }

    private fun smallPillButton(label: String, active: Boolean, onClick: () -> Unit): TextView = TextView(this).apply {
        text = label
        setTextColor(if (active) COLOR_ACCENT_BLUE else COLOR_TEXT_SECONDARY)
        setTextSize(TypedValue.COMPLEX_UNIT_SP, 11.5f)
        setTypeface(null, if (active) Typeface.BOLD else Typeface.NORMAL)
        setPadding(dp(10), dp(6), dp(10), dp(6))
        background = roundedDrawable(
            if (active) COLOR_ACCENT_SOFT else COLOR_BG_SURFACE,
            if (active) COLOR_ACCENT_BLUE else COLOR_BORDER,
            dp(8),
            dp(1)
        )
        layoutParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
            leftMargin = dp(6)
        }
        setOnClickListener { onClick() }
    }

    private fun domainInputRow(hintText: String, btnText: String, onAdd: (String) -> Unit): View {
        val row = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }
        val et = EditText(this).apply {
            hint = hintText
            setHintTextColor(COLOR_TEXT_MUTED)
            setTextColor(COLOR_TEXT_PRIMARY)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 13f)
            setSingleLine(true)
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
        }
        val btn = smallPillButton(btnText, true) {
            val v = et.text.toString().trim()
            if (v.isNotEmpty()) {
                onAdd(v)
                et.setText("")
            }
        }
        row.addView(et)
        row.addView(btn)
        return row
    }

    private fun domainRuleRow(domain: String, isAllow: Boolean, onRemove: () -> Unit): View {
        val row = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            background = roundedDrawable(COLOR_BG_SURFACE, COLOR_BORDER, dp(8), dp(1))
            setPadding(dp(10), dp(6), dp(10), dp(6))
            layoutParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                bottomMargin = dp(6)
            }
        }
        row.addView(TextView(this).apply {
            text = domain
            setTextColor(if (isAllow) COLOR_STATUS_GREEN else COLOR_STATUS_RED)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 12.5f)
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
        })
        row.addView(TextView(this).apply {
            text = "حذف ✕"
            setTextColor(COLOR_TEXT_SECONDARY)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 11.5f)
            setOnClickListener { onRemove() }
        })
        return row
    }

    companion object {
        private val COLOR_BG_PRIMARY = Color.parseColor("#0B1220")
        private val COLOR_BG_SURFACE = Color.parseColor("#121C2E")
        private val COLOR_BG_CARD = Color.parseColor("#172338")
        private val COLOR_BG_CARD_ELEVATED = Color.parseColor("#1E2E48")
        private val COLOR_BORDER = Color.parseColor("#253654")
        private val COLOR_ACCENT_BLUE = Color.parseColor("#38BDF8")
        private val COLOR_ACCENT_SOFT = Color.parseColor("#1E3A5F")
        private val COLOR_STATUS_GREEN = Color.parseColor("#22C55E")
        private val COLOR_STATUS_GREEN_SOFT = Color.parseColor("#143828")
        private val COLOR_STATUS_AMBER = Color.parseColor("#F59E0B")
        private val COLOR_STATUS_AMBER_SOFT = Color.parseColor("#3B2A12")
        private val COLOR_STATUS_RED = Color.parseColor("#EF4444")
        private val COLOR_STATUS_RED_SOFT = Color.parseColor("#3C1820")
        private val COLOR_TEXT_PRIMARY = Color.parseColor("#F1F5F9")
        private val COLOR_TEXT_SECONDARY = Color.parseColor("#94A3B8")
        private val COLOR_TEXT_MUTED = Color.parseColor("#64748B")
    }
}
