package com.smartadshield.vpn.core.engine

/**
 * Connection states. CONNECTED is only ever set after the tunnel has been
 * verified end-to-end (handshake + a request that exits through the server).
 * LOCAL_DNS_ONLY is on-device DNS filtering: no remote server, IP unchanged.
 */
enum class VpnState(val labelAr: String, val labelEn: String) {
    DISCONNECTED("غير متصل", "Disconnected"),
    PREPARING("جاري التجهيز...", "Preparing..."),
    CONNECTING("جاري الاتصال بالخادم...", "Connecting..."),
    AUTHENTICATING("جاري المصافحة مع الخادم...", "Handshaking..."),
    ESTABLISHING_TUNNEL("جاري إنشاء النفق...", "Establishing tunnel..."),
    VERIFYING_CONNECTIVITY("جاري التحقق من مرور البيانات عبر الخادم...", "Verifying..."),
    CONNECTED("متصل بخادم VPN (تم التحقق)", "Connected (verified)"),
    RECONNECTING("جاري إعادة الاتصال...", "Reconnecting..."),
    DISCONNECTING("جاري قطع الاتصال...", "Disconnecting..."),
    ERROR("فشل الاتصال", "Connection error"),
    LOCAL_DNS_ONLY("حجب إعلانات محلي فقط (بدون خادم VPN)", "Local DNS filtering only");

    val isRunning: Boolean
        get() = this == CONNECTED || this == VERIFYING_CONNECTIVITY || this == RECONNECTING ||
            this == ESTABLISHING_TUNNEL || this == CONNECTING || this == AUTHENTICATING ||
            this == PREPARING || this == LOCAL_DNS_ONLY

    val isBusy: Boolean
        get() = this == PREPARING || this == CONNECTING || this == AUTHENTICATING ||
            this == ESTABLISHING_TUNNEL || this == VERIFYING_CONNECTIVITY || this == RECONNECTING
}
