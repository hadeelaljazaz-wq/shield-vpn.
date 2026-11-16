package com.smartadshield.vpn.core.engine

enum class VpnProtocol(
    val id: String,
    val displayNameAr: String,
    val displayNameEn: String,
    val descriptionAr: String,
) {
    AUTO(
        "auto",
        "تلقائي (الذكي)",
        "Auto (Smart)",
        "يقيس أداء واستجابة الشبكة ويختار أفضل بروتوكول تلقائيًا"
    ),
    WIREGUARD(
        "wireguard",
        "WireGuard (الأسرع والأخف)",
        "WireGuard (High-Speed)",
        "تشفير حديث فائق السرعة، استهلاك بطارية شبه منعدم وتأخير منخفض"
    ),
    XRAY_VLESS(
        "xray",
        "Xray / REALITY (مقاوم الحجب)",
        "Xray / REALITY (Anti-Censorship)",
        "محاكاة HTTPS TLS لتجاوز الرقابة الشديدة وحظر الـ VPN والـ UDP"
    ),
    LOCAL_DNS_SHIELD(
        "dns_shield",
        "درع DNS الذكي (حجب إعلانات محلي)",
        "Smart DNS Shield",
        "حجب إعلانات محلي عبر DNS مع الحفاظ الكامل على اتصالك الأصلي دون خادم خارجي"
    );

    companion object {
        fun fromId(id: String?): VpnProtocol = entries.find { it.id == id } ?: AUTO
    }
}

enum class SplitTunnelingMode(
    val id: String,
    val titleAr: String,
    val titleEn: String,
    val descriptionAr: String,
) {
    ALL_APPS(
        "all",
        "جميع التطبيقات",
        "All Apps",
        "تمرير 100% من حركة الجهاز وكافة التطبيقات عبر نفق VPN المشفر"
    ),
    SELECTED_APPS(
        "selected",
        "تطبيقات محددة فقط",
        "Selected Apps Only",
        "تمرير تطبيقات معينة فقط (مثل TikTok والمتصفح) عبر VPN وتشغيل باقي التطبيقات مباشرة"
    ),
    EXCLUDED_APPS(
        "excluded",
        "استثناء تطبيقات محددة",
        "All Except Excluded",
        "تمرير كافة التطبيقات عبر VPN باستثناء تطبيقات تختارها (مثل تطبيقات البنوك المحلية)"
    );

    companion object {
        fun fromId(id: String?): SplitTunnelingMode = entries.find { it.id == id } ?: ALL_APPS
    }
}
