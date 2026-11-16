package com.smartadshield.vpn.core.filter

/** Why a query was allowed or blocked — surfaced in the log and in diagnostics. */
enum class Reason(val blocked: Boolean, val labelAr: String) {
    NO_MATCH(false, "لا توجد قاعدة"),
    USER_ALLOW(false, "قائمة السماح الخاصة"),
    ESSENTIAL(false, "خدمة أساسية محمية"),
    VIDEO_PROTECTED(false, "محمي بوضع توافق الفيديو"),
    PLATFORM_PROTECTED(false, "نطاق منصة مشترك (لا تُطبّق عليه إلا قواعد الإعلانات المؤكدة)"),
    RECOMMENDATION_PROTECTED(false, "محمي بوضع حماية التوصيات"),
    LIST_EXCEPTION(false, "استثناء من قائمة الفلترة"),
    COMPAT_APP(false, "تطبيق في وضع التوافق (قواعد الإعلانات المؤكدة فقط)"),
    USER_BLOCK(true, "قائمة الحجب الخاصة"),
    CONFIRMED_AD(true, "نطاق إعلاني مؤكد"),
    TRACKER(true, "تتبع/تحليلات"),
    DNS_BYPASS(true, "منع تجاوز DNS"),
    FILTER_LIST(true, "قائمة فلترة"),
}

enum class AppMode { FILTER, COMPAT, EXCLUDED }

class Decision(val reason: Reason, val rule: String? = null, val source: String? = null) {
    val blocked: Boolean get() = reason.blocked
}

class EngineOptions(
    val videoCompat: Boolean = true,
    val recommendationProtection: Boolean = true,
    val blockTrackers: Boolean = true,
    val preventDnsBypass: Boolean = true,
)

/** A named remote list after compilation. */
class NamedList(val id: String, val name: String, val list: CompiledList)

/**
 * Immutable rule snapshot. A new instance is swapped in atomically whenever lists or user rules
 * change, so the packet path never takes locks.
 */
class FilterEngine(
    private val confirmedAds: DomainHashSet,
    private val trackers: DomainHashSet,
    private val dnsBypass: DomainHashSet,
    private val remote: List<NamedList>,
    private val userAllow: Set<String>,
    private val userBlock: Set<String>,
    val options: EngineOptions,
    private val protection: ProtectionSets = ProtectionSets.DEFAULT,
) {
    val totalRules: Int = confirmedAds.size + trackers.size + dnsBypass.size + remote.sumOf { it.list.ruleCount } + userAllow.size + userBlock.size

    private fun matchUserSet(set: Set<String>, domain: String): String? {
        if (set.isEmpty()) return null
        var start = 0
        while (true) {
            val s = if (start == 0) domain else domain.substring(start)
            if (s in set) return s
            val dot = domain.indexOf('.', start)
            if (dot < 0) return null
            start = dot + 1
        }
    }

    private fun suffix(set: DomainHashSet, domain: String): String? {
        val i = set.matchSuffix(domain)
        return if (i < 0) null else domain.substring(i)
    }

    private fun isAdServiceGoogle(domain: String): Boolean {
        return domain.startsWith("adservice.google.") || domain.contains(".adservice.google.")
    }

    fun evaluate(domain: String, appMode: AppMode = AppMode.FILTER): Decision {
        matchUserSet(userAllow, domain)?.let { return Decision(Reason.USER_ALLOW, it, "المستخدم") }
        matchUserSet(userBlock, domain)?.let { return Decision(Reason.USER_BLOCK, it, "المستخدم") }
        suffix(protection.essential, domain)?.let { return Decision(Reason.ESSENTIAL, it, "مدمج") }

        // Wildcard match for Google ad-serving domains across all ccTLDs (.com.eg, .com.sa, etc.)
        if (isAdServiceGoogle(domain)) {
            return Decision(Reason.CONFIRMED_AD, "adservice.google.*", "إعلانات مؤكدة (مدمجة)")
        }

        // Index of the most specific curated ad rule (smaller index = longer, more specific suffix).
        val adIdx = confirmedAds.matchSuffix(domain)
        // A protection suffix wins unless a curated ad rule is strictly more specific than it,
        // e.g. protected "facebook.com" vs confirmed ad "an.facebook.com".
        fun protects(set: DomainHashSet): Int {
            val p = set.matchSuffix(domain)
            return if (p >= 0 && (adIdx < 0 || adIdx >= p)) p else -1
        }
        if (options.videoCompat) {
            val p = protects(protection.videoCdn)
            if (p >= 0) return Decision(Reason.VIDEO_PROTECTED, domain.substring(p), "توافق الفيديو")
        }
        if (options.recommendationProtection) {
            val p = protects(protection.recommendationSignals)
            if (p >= 0) return Decision(Reason.RECOMMENDATION_PROTECTED, domain.substring(p), "حماية التوصيات")
        }
        // Confirmed ad-serving domains (curated, high confidence) apply everywhere.
        if (adIdx >= 0) return Decision(Reason.CONFIRMED_AD, domain.substring(adIdx), "إعلانات مؤكدة (مدمجة)")

        // Anti-bypass (DoH / canary): must NEVER be overridden by platformShared or compat mode
        // so that Chrome and other browsers receive NXDOMAIN and fall back to local system DNS.
        if (options.preventDnsBypass) {
            suffix(dnsBypass, domain)?.let { return Decision(Reason.DNS_BYPASS, it, "منع تجاوز DNS") }
        }

        // Lower-confidence categories.
        val candidate: Decision = findListMatch(domain) ?: return Decision(Reason.NO_MATCH)
        if (!candidate.blocked) return candidate // list exception
        if (appMode == AppMode.COMPAT) return Decision(Reason.COMPAT_APP, candidate.rule, candidate.source)
        if (options.videoCompat) {
            suffix(protection.platformShared, domain)?.let {
                return Decision(Reason.PLATFORM_PROTECTED, candidate.rule, candidate.source)
            }
        }
        return candidate
    }

    private fun findListMatch(domain: String): Decision? {
        if (options.blockTrackers) {
            suffix(trackers, domain)?.let { return Decision(Reason.TRACKER, it, "متتبعات (مدمجة)") }
        }
        for (r in remote) {
            val a = r.list.allow.matchSuffix(domain)
            if (a >= 0) return Decision(Reason.LIST_EXCEPTION, "@@||" + domain.substring(a) + "^", r.name)
            r.list.wildcardAllow.match(domain)?.let { return Decision(Reason.LIST_EXCEPTION, "@@||$it^", r.name) }
        }
        for (r in remote) {
            val i = r.list.block.matchSuffix(domain)
            if (i >= 0) return Decision(Reason.FILTER_LIST, domain.substring(i), r.name)
            r.list.wildcardBlock.match(domain)?.let { return Decision(Reason.FILTER_LIST, it, r.name) }
        }
        return null
    }

    companion object {
        val EMPTY = FilterEngine(
            DomainHashSet.EMPTY, DomainHashSet.EMPTY, DomainHashSet.EMPTY, emptyList(),
            emptySet(), emptySet(), EngineOptions(),
        )
    }
}
