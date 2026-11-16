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
        "يجرّب WireGuard أولًا ثم Xray REALITY إذا فشل التحقق"
    ),
    WIREGUARD(
        "wireguard",
        "WireGuard (الأسرع والأخف)",
        "WireGuard (High-Speed)",
        "المكتبة الرسمية wireguard-go — يحتاج UDP غير محجوب"
    ),
    XRAY_VLESS(
        "xray",
        "Xray / REALITY (مقاوم الحجب)",
        "Xray / REALITY (Anti-Censorship)",
        "Xray-core عبر TCP/443 يشبه اتصال HTTPS — لا يضمن تجاوز كل أشكال الحجب"
    ),
    LOCAL_DNS_SHIELD(
        "dns_shield",
        "درع DNS المحلي (ليس VPN)",
        "Smart DNS Shield",
        "فلترة DNS على الجهاز فقط — ليس VPN ولا يغيّر IP"
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
