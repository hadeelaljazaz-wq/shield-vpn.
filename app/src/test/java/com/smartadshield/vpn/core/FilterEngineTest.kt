package com.smartadshield.vpn.core

import com.smartadshield.vpn.core.filter.AppMode
import com.smartadshield.vpn.core.filter.CompiledList
import com.smartadshield.vpn.core.filter.DomainHashSet
import com.smartadshield.vpn.core.filter.EngineOptions
import com.smartadshield.vpn.core.filter.FilterEngine
import com.smartadshield.vpn.core.filter.FilterListParser
import com.smartadshield.vpn.core.filter.NamedList
import com.smartadshield.vpn.core.filter.Reason
import com.smartadshield.vpn.core.filter.WildcardRules
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream

class FilterEngineTest {

    private val sample = """
        ! Title: test
        [Adblock Plus 2.0]
        ||ads.example.com^
        ||tracker.example.net^${'$'}important
        ||thirdparty.example.org^${'$'}third-party
        @@||good.ads.example.com^
        ||mon*.tiktokv.us^
        ||log*-normal-*.tiktokv.com
        example.com##.banner
        /^regex$/
        ||1.2.3.4^
        ||rgfftupf.
        ||example.com/path^
        0.0.0.0 hosts-ad.example.io # comment
        127.0.0.1 localhost
        plain-ad.example.co
        ||ads.youtube.com^
        ||googlevideo.com^
        ||log.tiktokv.com^
        ||xz.fbcdn.net^
        ||pixel.some-tracker.com^
    """.trimIndent()

    private fun parsed() = FilterListParser.parse(sample.reader().buffered(), 100)

    @Test
    fun parserKeepsOnlyDnsCompatibleRules() {
        val r = parsed()
        assertTrue(r.block.contains("ads.example.com"))
        assertTrue(r.block.contains("tracker.example.net"))
        assertFalse(r.block.contains("thirdparty.example.org"))
        assertTrue(r.allow.contains("good.ads.example.com"))
        assertTrue(r.block.contains("hosts-ad.example.io"))
        assertTrue(r.block.contains("plain-ad.example.co"))
        assertFalse(r.block.contains("localhost"))
        assertFalse(r.block.contains("example.com"))
        assertEquals(listOf("mon*.tiktokv.us", "log*-normal-*.tiktokv.com"), r.wildcardBlock.patterns)
        assertFalse(r.looksLikeHtml)
    }

    @Test
    fun wildcardSemantics() {
        val w = WildcardRules(listOf("mon*.tiktokv.us", "log*-normal-*.tiktokv.com"))
        assertEquals("mon*.tiktokv.us", w.match("mon16.tiktokv.us"))
        assertEquals("mon*.tiktokv.us", w.match("a.mon-va.tiktokv.us"))
        assertEquals("log*-normal-*.tiktokv.com", w.match("log22-normal-useast1a.tiktokv.com"))
        assertNull(w.match("api.tiktokv.us"))
        assertNull(w.match("xmon.tiktokv.us"))
    }

    @Test
    fun compiledListSerializationRoundTrip() {
        val c = CompiledList.from(parsed())
        val bos = ByteArrayOutputStream()
        c.write(DataOutputStream(bos))
        val back = CompiledList.read(DataInputStream(ByteArrayInputStream(bos.toByteArray())))
        assertEquals(c.ruleCount, back.ruleCount)
        assertTrue(back.block.contains("ads.example.com"))
        assertEquals(c.wildcardBlock.patterns, back.wildcardBlock.patterns)
    }

    private fun set(vararg d: String) = DomainHashSet.Builder().apply { d.forEach { add(it) } }.build()

    private fun engine(
        opts: EngineOptions = EngineOptions(),
        allow: Set<String> = emptySet(),
        block: Set<String> = emptySet(),
    ) = FilterEngine(
        confirmedAds = set("doubleclick.net", "ads.youtube.com", "an.facebook.com"),
        trackers = set("google-analytics.com", "pixel.facebook.com"),
        dnsBypass = set("use-application-dns.net", "dns.google.com", "chrome.cloudflare-dns.com"),
        remote = listOf(NamedList("t", "Test list", CompiledList.from(parsed()))),
        userAllow = allow, userBlock = block, options = opts,
    )

    @Test
    fun chromeAdBlockingAndDnsBypass() {
        val e = engine()
        // Regional Google AdService domains are blocked as CONFIRMED_AD across all ccTLDs
        assertEquals(Reason.CONFIRMED_AD, e.evaluate("adservice.google.com").reason)
        assertEquals(Reason.CONFIRMED_AD, e.evaluate("adservice.google.com.eg").reason)
        assertEquals(Reason.CONFIRMED_AD, e.evaluate("adservice.google.com.sa").reason)
        assertEquals(Reason.CONFIRMED_AD, e.evaluate("adservice.google.co.uk").reason)
        assertEquals(Reason.CONFIRMED_AD, e.evaluate("pagead.adservice.google.com.eg").reason)

        // Chrome DoH bypass endpoints are blocked with DNS_BYPASS even when videoCompat is ON
        // and cannot be overridden by platformShared "google.com"
        assertEquals(Reason.DNS_BYPASS, e.evaluate("dns.google.com").reason)
        assertEquals(Reason.DNS_BYPASS, e.evaluate("chrome.cloudflare-dns.com").reason)
        assertTrue(e.evaluate("dns.google.com").blocked)
    }

    @Test
    fun decisionPriorities() {
        val e = engine()
        assertEquals(Reason.CONFIRMED_AD, e.evaluate("googleads.g.doubleclick.net").reason)
        assertEquals(Reason.FILTER_LIST, e.evaluate("x.ads.example.com").reason)
        assertEquals(Reason.LIST_EXCEPTION, e.evaluate("good.ads.example.com").reason)
        assertEquals(Reason.NO_MATCH, e.evaluate("wikipedia.org").reason)
        assertEquals(Reason.TRACKER, e.evaluate("www.google-analytics.com").reason)
        assertEquals(Reason.DNS_BYPASS, e.evaluate("use-application-dns.net").reason)
        // Video CDN can never be blocked by a list rule
        assertEquals(Reason.VIDEO_PROTECTED, e.evaluate("rr3---sn-abc.googlevideo.com").reason)
        // Recommendation signals stay reachable even though the list blocks them
        assertEquals(Reason.RECOMMENDATION_PROTECTED, e.evaluate("log.tiktokv.com").reason)
        assertEquals(Reason.RECOMMENDATION_PROTECTED, e.evaluate("mon16.tiktokv.us").reason)
        // List rule inside media CDN is neutralised
        assertEquals(Reason.VIDEO_PROTECTED, e.evaluate("xz.fbcdn.net").reason)
        // More specific curated ad rule beats the shared platform protection
        assertEquals(Reason.CONFIRMED_AD, e.evaluate("an.facebook.com").reason)
        assertEquals(Reason.CONFIRMED_AD, e.evaluate("ads.youtube.com").reason)
        // Tracker inside a shared platform domain: not applied
        assertEquals(Reason.PLATFORM_PROTECTED, e.evaluate("pixel.facebook.com").reason)
        // Essential services are never blocked by lists
        assertEquals(Reason.ESSENTIAL, e.evaluate("connectivitycheck.gstatic.com").reason)
    }

    @Test
    fun compatAppsOnlyGetConfirmedAds() {
        val e = engine()
        assertEquals(Reason.CONFIRMED_AD, e.evaluate("doubleclick.net", AppMode.COMPAT).reason)
        assertEquals(Reason.COMPAT_APP, e.evaluate("ads.example.com", AppMode.COMPAT).reason)
        assertEquals(Reason.COMPAT_APP, e.evaluate("www.google-analytics.com", AppMode.COMPAT).reason)
    }

    @Test
    fun userRulesWin() {
        val e = engine(allow = setOf("doubleclick.net"), block = setOf("wikipedia.org", "googlevideo.com"))
        assertEquals(Reason.USER_ALLOW, e.evaluate("ad.doubleclick.net").reason)
        assertEquals(Reason.USER_BLOCK, e.evaluate("en.wikipedia.org").reason)
        assertEquals(Reason.USER_BLOCK, e.evaluate("r1.googlevideo.com").reason)
    }

    @Test
    fun togglesDisableProtections() {
        val e = engine(EngineOptions(videoCompat = false, recommendationProtection = false, blockTrackers = false, preventDnsBypass = false))
        assertEquals(Reason.FILTER_LIST, e.evaluate("googlevideo.com").reason)
        assertEquals(Reason.FILTER_LIST, e.evaluate("log.tiktokv.com").reason)
        assertEquals(Reason.NO_MATCH, e.evaluate("www.google-analytics.com").reason)
        assertEquals(Reason.NO_MATCH, e.evaluate("use-application-dns.net").reason)
    }
}
