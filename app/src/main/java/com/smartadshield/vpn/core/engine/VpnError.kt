package com.smartadshield.vpn.core.engine

/**
 * Standardized typed error codes and diagnostics for VPN failures.
 */
enum class VpnError(
    val code: String,
    val messageAr: String,
    val messageEn: String,
    val isRecoverable: Boolean = true,
) {
    NONE(
        "NONE",
        "لا توجد أخطاء",
        "No errors",
        isRecoverable = true
    ),
    VPN_PERMISSION_DENIED(
        "VPN_PERMISSION_DENIED",
        "تم رفض إذن إنشاء الـ VPN من قبل المستخدم أو النظام",
        "VPN permission denied by user or system",
        isRecoverable = false
    ),
    NO_NETWORK(
        "NO_NETWORK",
        "لا يوجد اتصال إنترنت نشط على الجهاز",
        "No active network connection",
        isRecoverable = true
    ),
    SERVER_UNREACHABLE(
        "SERVER_UNREACHABLE",
        "تعذر الوصول إلى عنوان خادم الـ VPN؛ تحقق من اتصالك أو جرب سيرفر آخر",
        "VPN server endpoint is unreachable",
        isRecoverable = true
    ),
    HANDSHAKE_TIMEOUT(
        "HANDSHAKE_TIMEOUT",
        "انتهت مهلة المصافحة المشفرة مع الخادم دون استجابة (قد تكون منافذ UDP محجوبة)",
        "Encrypted handshake timed out (UDP may be blocked)",
        isRecoverable = true
    ),
    AUTHENTICATION_FAILED(
        "AUTHENTICATION_FAILED",
        "فشلت المصادقة التشفيرية؛ تحقق من صحة المفاتيح والتكوين",
        "Cryptographic authentication failed; check keys and config",
        isRecoverable = false
    ),
    DNS_FAILURE(
        "DNS_FAILURE",
        "فشل في حل عناوين النطاقات عبر النفق",
        "DNS resolution failed through tunnel",
        isRecoverable = true
    ),
    TUN_ESTABLISH_FAILED(
        "TUN_ESTABLISH_FAILED",
        "تعذر إنشاء واجهة النفق الافتراضية TUN على نظام أندرويد",
        "Failed to establish Android TUN interface",
        isRecoverable = true
    ),
    ROUTING_FAILURE(
        "ROUTING_FAILURE",
        "فشل في ضبط مسارات التوجيه وحماية المقابس",
        "Routing configuration failure",
        isRecoverable = true
    ),
    UPSTREAM_NOT_AVAILABLE(
        "UPSTREAM_NOT_AVAILABLE",
        "شبكة الإنترنت الأساسية غير متاحة أو انقطعت",
        "Upstream network not available",
        isRecoverable = true
    ),
    CONNECTIVITY_VERIFICATION_FAILED(
        "CONNECTIVITY_VERIFICATION_FAILED",
        "تم إنشاء النفق بنجاح لكن حركة البيانات الخارجية لم تمر عبر الإنترنت",
        "Tunnel established but external data traffic verification failed",
        isRecoverable = true
    ),
    ANDROID_SERVICE_TERMINATED(
        "ANDROID_SERVICE_TERMINATED",
        "أوقف نظام أندرويد خدمة الـ VPN في الخلفية لتوفير الطاقة",
        "VPN service terminated by Android background limitations",
        isRecoverable = true
    ),
    INVALID_SERVER_CONFIG(
        "INVALID_SERVER_CONFIG",
        "ملف تكوين الخادم أو مفاتيح التشفير غير صالحة",
        "Invalid server configuration or cryptographic keys",
        isRecoverable = false
    ),
    PROTOCOL_UNAVAILABLE(
        "PROTOCOL_UNAVAILABLE",
        "البروتوكول المحدد غير مدعوم على هذه الشبكة، سيتم التبديل تلقائيًا",
        "Selected protocol is not available on this network, switching automatically",
        isRecoverable = true
    );
}
