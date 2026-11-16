# Ultimate Android VPN & Smart Ad Shield

تطبيق Android VPN هندسي متكامل واحترافي متعدد البروتوكولات (WireGuard و Xray و Smart DNS Shield)، يوفر تشفيرًا حقيقيًا لكافة حركة الجهاز، تجاوز الحجب والرقابة، فلترة الإعلانات الذكية، وتقسيم النفق (Split Tunneling).

---

## 🌟 الميزات الرئيسية (Key Features)

1. **نفق VPN مشفر حقيقي (Real Full Tunnel):** توجيه كامل لحركة الإنترنت (`0.0.0.0/0` و `::/0`) عبر خادم خارجي مع تغيير عنوان IP العام وحماية التصفح.
2. **محرك WireGuard فائق السرعة:** مبني بشفرة نقية مدعومة ببروتوكول الضوضاء `Noise_IKpsk2` وتشفير `ChaCha20-Poly1305` و `Curve25519` لتوفير أقصى سرعة وأقل استهلاك للبطارية.
3. **محرك Xray / Anti-Censorship:** للتعامل مع الشبكات المقيدة وتجاوز حجب الـ VPN والـ UDP.
4. **آلة حالات دقيقة (10-State Connection Machine):** لا تدّعي الاتصال الناجح حتى يتم إثبات المصافحة المشفرة وتدفق الحزم واختبار الاتصال الخارجي.
5. **تقسيم النفق المتقدم (Split Tunneling):**
   * **كافة التطبيقات (All Apps):** نفق كامل مشفر 100%.
   * **تطبيقات محددة (Selected Apps):** توجيه تطبيقات معينة فقط عبر VPN (مثل TikTok والمتصفح).
   * **استثناء تطبيقات (Excluded Apps):** استثناء تطبيقات البنوك والتطبيقات المحلية من النفق.
6. **درع الإعلانات الذكي (Smart Ad Shield):** فلترة إعلانات محلية عبر DNS لأكثر من 190,000 قاعدة دون كسر خوادم تدفق الفيديو في YouTube أو TikTok.
7. **إدارة الخوادم والاختيار الذكي:** قائمة خوادم عالمية (ألمانيا، هولندا، بريطانيا، أمريكا) مع إمكانية استيراد أي ملف `.conf` مخصص.
8. **توافق كامل مع أندرويد الحديث:** دعم Android 12 و 13 و 14 و 15 و 16 مع إشعارات الحالة المستمرة وإدارة تبديل الشبكات (Network Handover).

---

## 🏗️ هيكل المشروع (Project Structure)

```
/workspace/vpn/
├── app/
│   ├── src/main/java/com/smartadshield/vpn/
│   │   ├── core/
│   │   │   ├── engine/          # مدير المحركات وآلة الحالات والبروتوكولات
│   │   │   ├── wireguard/       # محرك وتشفير WireGuard (Curve25519, ChaCha, Blake2s)
│   │   │   ├── dns/             # معالجة وتحليل رسائل وكاش الـ DNS
│   │   │   ├── filter/          # محرك وقواعد فلترة الإعلانات عالية الكفاءة
│   │   │   ├── video/           # مراقب توافق منصات الفيديو (YouTube/TikTok)
│   │   │   └── net/             # بناء وتحليل حزم IP و UDP و TCP
│   │   ├── service/             # خدمة VpnService الرئيسية
│   │   ├── data/                # إدارة الإعدادات والخوادم والتخزين
│   │   ├── diagnostics/         # أدوات الفحص والتشخيص الحي
│   │   └── ui/                  # واجهة المستخدم الاحترافية (RTL)
│   └── src/test/java/           # اختبارات الوحدة والتكامل
├── server/                      # سكربتات نشر خوادم WireGuard و Xray على Linux VPS
├── ARCHITECTURE.md              # توثيق المعمارية ومخطط التدفق
├── VPN_PROJECT_FORENSIC_AUDIT.md# تقرير التحقيق الجنائي في النسخة القديمة
├── VPN_PROTOCOLS.md             # دليل البروتوكولات ومعايير التشفير
├── SERVER_DEPLOYMENT.md         # دليل إعداد الخادم الخارجي
├── ANDROID_INTEGRATION.md       # دليل تكامل VpnService وأندرويد الحديث
├── SECURITY_REVIEW.md           # تقرير الأمان والخصوصية والتراخيص
├── TEST_REPORT.md               # تقرير نتائج الاختبارات الآلية
├── PERFORMANCE_REPORT.md        # تقرير قياسات الأداء
└── KNOWN_LIMITATIONS.md         # المشاكل المعروفة والحدود التقنية
```

---

## 🚀 البناء والتشغيل (Build Instructions)

لإنشاء حزمة الـ APK للتطوير:
```bash
timeout 5m gradle -Dorg.gradle.jvmargs= --no-daemon --max-workers=2 --offline --init-script /root/.gradle/init.d/pocketdev-android.gradle -Pandroid.aapt2FromMavenOverride=/root/android-sdk/build-tools/35.0.0/aapt2 assembleDebug --console=plain --stacktrace
```

مسار الحزمة الناتجة:
`app/build/outputs/apk/debug/app-debug.apk`

---

## 🖥️ نشر الخادم الخارجي (Server Setup)

انسخ مجلد `server/` إلى خادمك الخاص (Ubuntu / Debian VPS) ونفّذ:
```bash
cd server
chmod +x deploy.sh
sudo ./deploy.sh
```
سيقوم السكربت تلقائيًا بإعداد WireGuard و Xray و NAT Forwarding وتوليد ملف `client_android.conf` الجاهز للاستيراد المباشر داخل التطبيق.
