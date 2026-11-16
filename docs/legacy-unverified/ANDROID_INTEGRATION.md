# ANDROID_INTEGRATION.md
## دليل تكامل Android VpnService وإدارة الخدمات في الخلفية

### 1. تكامل VpnService والواجهة الافتراضية TUN
يقوم محرك التطبيق بالتعامل الصارم مع دورة حياة `android.net.VpnService` وفق أفضل الممارسات الموثقة من Google:

#### أ. طلب الإذن والإعداد الأولي:
```kotlin
val intent = VpnService.prepare(context)
if (intent != null) {
    // توجيه المستخدم لشاشة موافقة النظام الرسمية
    activityResultLauncher.launch(intent)
} else {
    // الإذن ممنوح مسبقاً، بدء الخدمة مباشرة
    startVpnService()
}
```

#### ب. بناء واجهة النفق (VpnService.Builder):
```kotlin
val builder = Builder()
    .setSession("Ultimate VPN Secure Tunnel")
    .setMtu(1420)
    .addAddress("10.66.66.2", 24)
    .addDnsServer("1.1.1.1")
    .addDnsServer("8.8.8.8")
    .allowFamily(OsConstants.AF_INET)
    .allowFamily(OsConstants.AF_INET6)

// توجيه كامل حركة الإنترنت للنفق (Real Full VPN)
if (routeAllTraffic) {
    builder.addRoute("0.0.0.0", 0)
    builder.addRoute("::", 0)
}

// تطبيق Split Tunneling
when (splitMode) {
    SplitMode.SELECTED_APPS -> selectedPackages.forEach { builder.addAllowedApplication(it) }
    SplitMode.EXCLUDED_APPS -> excludedPackages.forEach { builder.addDisallowedApplication(it) }
    SplitMode.ALL_APPS -> {}
}

// إنشاء الواجهة واستلام FileDescriptor
val pfd = builder.establish() ?: throw IllegalStateException("تعذر إنشاء واجهة TUN")
```

#### ج. حماية مقبس النقل الخارجي من حلقة التوجيه (Routing Loop Prevention):
لمنع دخول الحزم المشفرة الصادرة في حلقة لا نهائية داخل واجهة TUN، يجب استدعاء `protect()` على كل مقبس اتصال خارجي:
```kotlin
val socket = DatagramSocket()
if (!vpnService.protect(socket)) {
    throw IllegalStateException("فشل حماية المقبس عبر VpnService.protect()")
}
```

---

### 2. التوافق مع Android 12 و 13 و 14 و 15 و 16
* **صلاحيات الإشعارات (Android 13+ / API 33):** التحقق من منح إذن `POST_NOTIFICATIONS` قبل تشغيل الخدمة في الواجهة الأمامية.
* **أنواع الخدمات الأمامية (Android 14+ / API 34):**
  * إدراج `android:foregroundServiceType="specialUse"` أو `systemExempted` مع بيان الاستخدام الخاص بالـ VPN.
  * ربط الخدمة بإشعار دائم غير قابل للإلغاء أثناء الاتصال النشط يعرض اسم الخادم وحجم البيانات المنقولة ومدة الاتصال.
* **إدارة Doze Mode والبطارية:**
  * التخلص التلقائي من أي Coroutines أو خيوط غير مستخدمة عند قطع الاتصال.
  * تفادي استخدام WakeLock المستمر، والاعتماد بدلاً من ذلك على فترات استيقاظ مؤقتة مرتبطة بحزم Keepalive.

---

### 3. مراقبة الشبكة وإعادة الاتصال التلقائي (Network Handover)
يستخدم التطبيق `ConnectivityManager.NetworkCallback` لمراقبة تبديل الاتصال بين Wi-Fi وبيانات الهاتف الخلوية:
```kotlin
val networkCallback = object : ConnectivityManager.NetworkCallback() {
    override fun onAvailable(network: Network) {
        // تحديث الشبكة الأساسية النشطة
        underlyingNetwork = network
        vpnService.setUnderlyingNetworks(arrayOf(network))
        // إعادة تهيئة المقبس وتحديث Endpoint دون قطع الجلسة
        engineManager.onNetworkChanged(network)
    }

    override fun onLost(network: Network) {
        // تحويل الحالة إلى RECONNECTING والبحث عن بديل
        engineManager.onNetworkLost()
    }
}
```
