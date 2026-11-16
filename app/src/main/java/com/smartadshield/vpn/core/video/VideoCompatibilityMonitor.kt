package com.smartadshield.vpn.core.video

import com.smartadshield.vpn.core.QueryEvent
import com.smartadshield.vpn.core.filter.ProtectionSets

/** A blocked request that may be related to a playback / feature failure. */
class VideoIncident(
    val domain: String,
    val rule: String?,
    val source: String?,
    val firstSeen: Long,
    @Volatile var lastSeen: Long,
    @Volatile var count: Int,
    @Volatile var appLabel: String?,
    val signals: MutableSet<String>,
)

/**
 * Video Compatibility Engine — runtime half.
 *
 * The static half (never blocking video CDNs / shared platform domains) lives in
 * [ProtectionSets] and FilterEngine. This monitor watches *blocked* queries and flags those that
 * plausibly break playback or features, so the user can lift the responsible rule in one tap:
 *
 *  1. the query came from a video/social app (identified by UID on Android 10+);
 *  2. the hostname looks media-related (video/cdn/stream/img/thumb/…);
 *  3. a retry storm: the same blocked host requested ≥ [retryThreshold] times in [retryWindowMs]
 *     — apps retry what they need, which is a strong hint something is broken.
 */
class VideoCompatibilityMonitor(
    private val videoPackages: Set<String> = ProtectionSets.COMPAT_PACKAGES,
    private val retryThreshold: Int = 5,
    private val retryWindowMs: Long = 30_000,
    private val maxIncidents: Int = 100,
) {
    private val incidents = LinkedHashMap<String, VideoIncident>()
    private val recent = HashMap<String, ArrayDeque<Long>>()
    private val mediaHints = listOf("video", "cdn", "stream", "media", "img", "image", "thumb", "static", "play", "vod", "hls", "dash", "audio")

    @Synchronized
    fun onEvent(e: QueryEvent) {
        if (!e.decision.blocked) return
        val signals = HashSet<String>(2)
        val app = e.app
        val pkg = app?.packageName
        if (app != null && pkg != null && pkg in videoPackages) signals += "طُلب من تطبيق فيديو/تواصل: ${app.label}"
        val firstLabel = e.domain.substringBefore('.')
        if (mediaHints.any { firstLabel.contains(it) }) signals += "اسم النطاق يوحي بمحتوى وسائط"

        val q = recent.getOrPut(e.domain) { ArrayDeque() }
        q.addLast(e.time)
        while (q.isNotEmpty() && e.time - q.first() > retryWindowMs) q.removeFirst()
        if (q.size >= retryThreshold) signals += "إعادة محاولة متكررة (${q.size} مرات خلال ${retryWindowMs / 1000} ث)"
        if (recent.size > 2000) recent.clear()

        if (signals.isEmpty() && e.domain !in incidents) return
        val inc = incidents.getOrPut(e.domain) {
            VideoIncident(e.domain, e.decision.rule, e.decision.source, e.time, e.time, 0, e.app?.label, HashSet())
        }
        inc.count++
        inc.lastSeen = e.time
        if (e.app != null) inc.appLabel = e.app.label
        inc.signals += signals
        if (incidents.size > maxIncidents) incidents.remove(incidents.keys.first())
    }

    @Synchronized
    fun snapshot(): List<VideoIncident> = incidents.values.sortedByDescending { it.lastSeen }

    @Synchronized
    fun dismiss(domain: String) { incidents.remove(domain); recent.remove(domain) }

    @Synchronized
    fun clear() { incidents.clear(); recent.clear() }
}
