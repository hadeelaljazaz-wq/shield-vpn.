package com.smartadshield.vpn.core

import com.smartadshield.vpn.core.dns.DnsMessage
import com.smartadshield.vpn.core.filter.AppMode
import com.smartadshield.vpn.core.filter.CompiledList
import com.smartadshield.vpn.core.filter.DomainHashSet
import com.smartadshield.vpn.core.filter.EngineOptions
import com.smartadshield.vpn.core.filter.FilterEngine
import com.smartadshield.vpn.core.filter.FilterListParser
import com.smartadshield.vpn.core.filter.NamedList
import com.smartadshield.vpn.core.video.VideoCompatibilityMonitor
import com.smartadshield.vpn.data.PrivateDnsStatus
import com.smartadshield.vpn.diagnostics.CheckStatus
import com.smartadshield.vpn.diagnostics.DiagnosticsRunner
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.net.InetAddress

/**
 * Automated verification of the 10 mandatory test categories + VideoCompatibilityMonitor
 * incident detection and instant rule disablement.
 */
class MandatoryTenTestsSuiteTest {

    private val testdataDir = File(System.getProperty("testdata.dir") ?: "testdata")

    private fun loadBundledAsset(name: String): DomainHashSet {
        val f = File(testdataDir.parentFile, "app/src/main/assets/filters/$name")
        return DomainHashSet.Builder().apply {
            FilterListParser.parseDomains(f.readLines().asSequence()).forEach { add(it) }
        }.build()
    }

    @Test
    fun runAllTenMandatoryChecksAndPrintMeasuredReport() {
        val adgFile = File(testdataDir, "adguard_dns.txt")
        val remoteLists = if (adgFile.exists()) {
            val parsed = adgFile.bufferedReader().use { FilterListParser.parse(it) }
            listOf(NamedList("adguard", "AdGuard DNS Filter", CompiledList.from(parsed)))
        } else emptyList()

        val engine = FilterEngine(
            confirmedAds = loadBundledAsset("ads_confirmed.txt"),
            trackers = loadBundledAsset("trackers.txt"),
            dnsBypass = loadBundledAsset("dns_bypass.txt"),
            remote = remoteLists,
            userAllow = emptySet(),
            userBlock = emptySet(),
            options = EngineOptions(),
        )

        val baselineIp = DiagnosticsRunner.fetchPublicIp(4000).getOrNull()
        println("=== Mandatory 10 Tests Execution ===")
        println("Baseline Public IP before engine/pipeline run: $baselineIp")

        val pDns = PrivateDnsStatus(
            mode = "opportunistic",
            specifier = null,
            isActiveConflict = false,
            summaryAr = "متوافق (Opportunistic)",
            detailAr = "يرفض اتصالات TCP/853 عبر RST ليعود النظام تلقائيًا إلى UDP/53 المحلي",
        )

        val report = DiagnosticsRunner.runFullSuite(
            engine = engine,
            upstreamServers = listOf(InetAddress.getByName("8.8.8.8"), InetAddress.getByName("1.1.1.1")),
            privateDnsStatus = pDns,
            baselinePublicIp = baselineIp,
        )

        assertEquals(10, report.items.size)
        for (item in report.items) {
            println("Test #${item.id} [${item.status}] ${item.titleAr}")
            println("   Measured: ${item.measuredValue}")
            println("   Details : ${item.detailsAr}")
            assertTrue("Check #${item.id} must not FAIL", item.status != CheckStatus.FAIL)
        }
    }

    @Test
    fun videoCompatibilityMonitorDetectsRetryStormAndInstantAllowFixesIt() {
        val monitor = VideoCompatibilityMonitor(retryThreshold = 4, retryWindowMs = 10_000)
        val adsSet = DomainHashSet.Builder().apply { add("ad-cdn-stream.example.net") }.build()
        val engine1 = FilterEngine(
            confirmedAds = adsSet,
            trackers = DomainHashSet.EMPTY,
            dnsBypass = DomainHashSet.EMPTY,
            remote = emptyList(),
            userAllow = emptySet(),
            userBlock = emptySet(),
            options = EngineOptions(),
        )

        val host = "video-edge.ad-cdn-stream.example.net"
        val dec1 = engine1.evaluate(host, AppMode.FILTER)
        assertTrue(dec1.blocked)

        val now = System.currentTimeMillis()
        repeat(4) { i ->
            monitor.onEvent(
                QueryEvent(
                    time = now + i * 200L,
                    domain = host,
                    qtype = DnsMessage.TYPE_A,
                    decision = dec1,
                    app = AppInfo(10123, "com.google.android.youtube", "YouTube", AppMode.COMPAT),
                    cached = false,
                    latencyMs = 1,
                    upstreamError = null,
                    intercepted = false,
                )
            )
        }

        val incidents = monitor.snapshot()
        assertEquals(1, incidents.size)
        assertEquals(host, incidents[0].domain)
        assertEquals(4, incidents[0].count)
        println("[video-monitor] Incident captured: domain=${incidents[0].domain}, rule=${incidents[0].rule}, signals=${incidents[0].signals}")

        // User taps "Disable rule immediately" -> adds rule/domain to userAllow
        val engine2 = FilterEngine(
            confirmedAds = adsSet,
            trackers = DomainHashSet.EMPTY,
            dnsBypass = DomainHashSet.EMPTY,
            remote = emptyList(),
            userAllow = setOf("ad-cdn-stream.example.net"),
            userBlock = emptySet(),
            options = EngineOptions(),
        )
        monitor.dismiss(host)
        assertFalse("Rule must be immediately bypassed after user allow", engine2.evaluate(host, AppMode.FILTER).blocked)
        assertTrue(monitor.snapshot().isEmpty())
    }
}
