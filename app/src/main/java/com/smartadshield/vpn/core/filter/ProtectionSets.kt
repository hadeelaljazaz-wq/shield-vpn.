package com.smartadshield.vpn.core.filter

/**
 * Built-in protection sets used by the Video Compatibility Engine and Recommendation Protection.
 *
 * Every entry is a suffix: "googlevideo.com" covers "rr1---sn-xxx.googlevideo.com".
 * Curated confirmed-ad rules that are *more specific* than a protection suffix still win.
 */
class ProtectionSets(
    val essential: DomainHashSet,
    val videoCdn: DomainHashSet,
    val recommendationSignals: DomainHashSet,
    val platformShared: DomainHashSet,
) {
    companion object {
        /** Connectivity checks, push messaging, time, certificate status, app stores, sign-in. */
        val ESSENTIAL = listOf(
            "connectivitycheck.gstatic.com", "connectivitycheck.android.com", "clients3.google.com",
            "clients1.google.com", "clients.l.google.com", "www.google.com", "time.android.com",
            "android.clients.google.com", "android.googleapis.com", "play.googleapis.com",
            "play.google.com", "play-fe.googleapis.com", "play-lh.googleusercontent.com",
            "mtalk.google.com", "fcm.googleapis.com", "firebaseinstallations.googleapis.com",
            "accounts.google.com", "oauth2.googleapis.com", "www.googleapis.com",
            "fonts.googleapis.com", "fonts.gstatic.com", "www.gstatic.com", "ajax.googleapis.com",
            "ocsp.pki.goog", "crl.pki.goog", "pki.goog", "ocsp.digicert.com", "crl3.digicert.com",
            "ocsp.sectigo.com", "r3.o.lencr.org", "o.lencr.org", "x1.c.lencr.org",
            "captive.apple.com", "www.msftconnecttest.com", "detectportal.firefox.com",
            "ntp.org", "time.google.com",
        )

        /** Media/CDN hosts that carry the actual video, thumbnails, avatars and app APIs. */
        val VIDEO_CDN = listOf(
            // YouTube
            "googlevideo.com", "ytimg.com", "ggpht.com", "youtube-nocookie.com",
            "youtubei.googleapis.com", "youtube.googleapis.com", "yt3.googleusercontent.com",
            "yt4.googleusercontent.com", "youtubekids.com",
            // TikTok / ByteDance media
            "tiktokcdn.com", "tiktokcdn-us.com", "tiktokcdn-eu.com", "ttwstatic.com",
            "ibyteimg.com", "ibytedtos.com", "byteimg.com", "muscdn.com", "tiktokcdn-in.com",
            // Meta (Instagram / Facebook) media
            "cdninstagram.com", "fbcdn.net", "fbsbx.com",
            // Other major video platforms
            "nflxvideo.net", "nflximg.net", "nflxext.com", "nflxso.net", "vimeocdn.com",
            "ttvnw.net", "jtvnw.net", "dmcdn.net", "twimg.com", "video.twimg.com",
        )

        /**
         * First-party endpoints that carry watch history, watch-time, likes, follows and
         * engagement events. Some popular lists block several of these (e.g. TikTok's
         * log/mon hosts); blocking them can plausibly alter what the platform recommends,
         * so they stay reachable while Recommendation Protection is on.
         */
        val RECOMMENDATION_SIGNALS = listOf(
            // YouTube watch-time/playback stats & InnerTube API, search suggestions
            "s.youtube.com", "youtubei.googleapis.com", "suggestqueries.google.com",
            "suggestqueries-clients6.youtube.com", "www.youtube.com", "m.youtube.com",
            "music.youtube.com",
            // TikTok API / event logging
            "tiktokv.com", "tiktokv.us", "tiktokv.eu", "byteoversea.com", "musical.ly",
            "tiktok.com",
            // Instagram / Facebook graph & realtime
            "i.instagram.com", "graph.instagram.com", "www.instagram.com", "edge-chat.instagram.com",
            "graph.facebook.com", "b-graph.facebook.com", "edge-mqtt.facebook.com",
            "mqtt-mini.facebook.com", "z-m-graph.facebook.com", "web.facebook.com",
        )

        /**
         * Shared first-party platform domains: remote-list and tracker rules are NOT applied
         * inside these; only curated confirmed-ad rules or the user's own rules can block here.
         */
        val PLATFORM_SHARED = listOf(
            "youtube.com", "google.com", "googleapis.com", "gstatic.com", "googleusercontent.com",
            "tiktok.com", "tiktokv.com", "instagram.com", "facebook.com", "messenger.com",
            "whatsapp.com", "whatsapp.net", "netflix.com", "twitch.tv", "x.com", "twitter.com",
            "snapchat.com", "spotify.com", "scdn.co", "apple.com", "icloud.com", "microsoft.com",
            "live.com", "office.com", "amazon.com", "media-amazon.com",
        )

        private fun set(list: List<String>) = DomainHashSet.Builder(list.size).apply { list.forEach { add(it) } }.build()

        val DEFAULT = ProtectionSets(set(ESSENTIAL), set(VIDEO_CDN), set(RECOMMENDATION_SIGNALS), set(PLATFORM_SHARED))

        /** Default per-app compatibility mode for apps whose ads arrive from first-party hosts. */
        val COMPAT_PACKAGES = setOf(
            "com.google.android.youtube", "com.google.android.apps.youtube.music",
            "com.google.android.apps.youtube.kids", "com.zhiliaoapp.musically",
            "com.ss.android.ugc.trill", "com.zhiliaoapp.musically.go", "com.instagram.android",
            "com.instagram.lite", "com.facebook.katana", "com.facebook.lite", "com.facebook.orca",
            "com.netflix.mediaclient",
        )
    }
}
