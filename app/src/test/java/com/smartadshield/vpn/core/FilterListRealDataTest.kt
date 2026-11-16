package com.smartadshield.vpn.core

import com.smartadshield.vpn.core.filter.CompiledList
import com.smartadshield.vpn.core.filter.DomainHashSet
import com.smartadshield.vpn.core.filter.EngineOptions
import com.smartadshield.vpn.core.filter.FilterEngine
import com.smartadshield.vpn.core.filter.FilterListParser
import com.smartadshield.vpn.core.filter.NamedList
import com.smartadshield.vpn.core.filter.ProtectionSets
import com.smartadshield.vpn.core.filter.Reason
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File

/**
 * Runs the parser and policy engine against the real lists downloaded into /testdata
 * (AdGuard DNS filter, EasyList, StevenBlack hosts). Prints measured numbers; skipped if absent.
 */
class FilterListRealDataTest {
    private val dir = File(System.getProperty("testdata.dir") ?: "testdata")

    private fun load(name: String): FilterListParser.Result? {
        val f = File(dir, name)
        if (!f.exists()) return null
        val t0 = System.nanoTime()
        val r = f.bufferedReader().use { FilterListParser.parse(it, 400_000) }
        val ms = (System.nanoTime() - t0) / 1_000_000
        println("[$name] lines=${r.totalLines} ruleLines=${r.ruleLines} accepted=${r.accepted} skipped=${r.skipped} " +
            "block=${r.block.size} allow=${r.allow.size} wildcardBlock=${r.wildcardBlock.size} wildcardAllow=${r.wildcardAllow.size} parseMs=$ms " +
            "approxMemKB=${(r.block.size + r.allow.size) * 8 / 1024}")
        return r
    }

    private fun assets(name: String): DomainHashSet {
        val f = File(dir.parentFile, "app/src/main/assets/filters/$name")
        return DomainHashSet.Builder().apply { FilterListParser.parseDomains(f.readLines().asSequence()).forEach { add(it) } }.build()
    }

    @Test
    fun realListsParseAndEngineBehaves() {
        val adg = load("adguard_dns.txt")
        assumeTrue("testdata missing", adg != null)
        load("easylist.txt")
        load("stevenblack_hosts.txt")
        adg!!
        assertTrue("AdGuard DNS filter should yield >50k rules", adg.block.size > 50_000)

        // Which protected domains would this list have blocked without protection?
        val conflicts = adg.blockedDomainsSample.filter { d ->
            listOf(ProtectionSets.VIDEO_CDN, ProtectionSets.RECOMMENDATION_SIGNALS, ProtectionSets.PLATFORM_SHARED, ProtectionSets.ESSENTIAL)
                .flatten().any { p -> d == p || d.endsWith(".$p") }
        }
        println("[conflicts] AdGuard DNS rules inside protected/shared domains: ${conflicts.size}")
        conflicts.take(60).forEach { println("   conflict: $it") }
        val wildConflicts = adg.wildcardBlock.patterns.filter { p ->
            (ProtectionSets.VIDEO_CDN + ProtectionSets.RECOMMENDATION_SIGNALS + ProtectionSets.PLATFORM_SHARED).any { p.endsWith(".$it") }
        }
        println("[conflicts] wildcard rules inside protected/shared domains: ${wildConflicts.size}")
        wildConflicts.take(40).forEach { println("   wildcard conflict: $it") }

        val engine = FilterEngine(
            assets("ads_confirmed.txt"), assets("trackers.txt"), assets("dns_bypass.txt"),
            listOf(NamedList("adguard", "AdGuard DNS", CompiledList.from(adg))), emptySet(), emptySet(), EngineOptions(),
        )
        val probes = listOf(
            "googleads.g.doubleclick.net", "pagead2.googlesyndication.com", "ads.youtube.com", "adservice.google.com",
            "www.youtube.com", "youtubei.googleapis.com", "rr1---sn-4g5e6nsz.googlevideo.com", "i.ytimg.com", "s.youtube.com",
            "www.tiktok.com", "log.tiktokv.com", "mon.tiktokv.com", "v16-ad.byteoversea.com", "p16-sign-va.tiktokcdn.com",
            "www.instagram.com", "scontent.cdninstagram.com", "graph.facebook.com", "an.facebook.com", "connect.facebook.net",
            "static.xx.fbcdn.net", "xz.fbcdn.net", "www.google-analytics.com", "app-measurement.com",
            "use-application-dns.net", "connectivitycheck.gstatic.com", "en.wikipedia.org", "github.com",
        )
        for (p in probes) {
            val d = engine.evaluate(p)
            println(String.format("[probe] %-38s %-8s %-26s rule=%s src=%s", p, if (d.blocked) "BLOCK" else "allow", d.reason, d.rule, d.source))
        }
        assertTrue(engine.evaluate("googleads.g.doubleclick.net").blocked)
        assertTrue(!engine.evaluate("rr1---sn-4g5e6nsz.googlevideo.com").blocked)
        assertTrue(!engine.evaluate("i.ytimg.com").blocked)
        assertTrue(engine.evaluate("log.tiktokv.com").reason == Reason.RECOMMENDATION_PROTECTED)

        // Lookup speed over a realistic mix (all AdGuard sample domains + probes, with subdomains).
        val names = adg.blockedDomainsSample.take(100_000).map { "x1.$it" } + probes
        val t0 = System.nanoTime()
        var blocked = 0
        for (n in names) if (engine.evaluate(n).blocked) blocked++
        val nsPer = (System.nanoTime() - t0) / names.size
        println("[perf] ${names.size} lookups, blocked=$blocked, avg ${nsPer} ns/lookup")
        assertTrue("lookups should be well under 1 ms", nsPer < 1_000_000)
    }
}
