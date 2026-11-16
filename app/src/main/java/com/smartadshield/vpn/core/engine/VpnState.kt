package com.smartadshield.vpn.core.engine

/**
 * Exact 10-state finite state machine for production VPN lifecycle.
 */
enum class VpnState(val labelAr: String, val labelEn: String) {
    DISCONNECTED("غير متصل", "Disconnected"),
    PREPARING("جاري التجهيز...", "Preparing..."),
    CONNECTING("جاري الاتصال بالسيرفر...", "Connecting..."),
    AUTHENTICATING("جاري المصادقة وتبادل المفاتيح...", "Authenticating..."),
    ESTABLISHING_TUNNEL("جاري إنشاء نفق التشفير...", "Establishing Tunnel..."),
    VERIFYING_CONNECTIVITY("جاري التحقق من مرور البيانات وIP...", "Verifying Connectivity..."),
    CONNECTED("متصل بنفق VPN حقيقي", "Connected (Real VPN)"),
    RECONNECTING("جاري إعادة الاتصال...", "Reconnecting..."),
    DISCONNECTING("جاري قطع الاتصال...", "Disconnecting..."),
    ERROR("خطأ في الاتصال", "Connection Error");

    val isRunning: Boolean
        get() = this == CONNECTED || this == VERIFYING_CONNECTIVITY || this == RECONNECTING || this == ESTABLISHING_TUNNEL
}
