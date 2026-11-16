# SERVER_DEPLOYMENT.md
## دليل إعداد ونشر خوادم VPN الخارجية (Remote VPN Gateway)

لكي يعمل تطبيق الـ VPN بصورة حقيقية ويغير عنوان IP للمستخدم، يجب توفير خادم افتراضي خاص (Linux VPS) يعمل بنظام Ubuntu 22.04 LTS أو 24.04 LTS أو Debian 12.

يوفر المشروع سكربتات تشغيل ونشر آلية بالكامل داخل مجلد `server/`.

---

### 1. المتطلبات الأساسية للخادم (VPS Prerequisites)
* **نظام التشغيل الموصى به:** Ubuntu 22.04 / 24.04 LTS (x86_64 أو ARM64).
* **المواصفات الأدنى:** 1 vCPU، 1 GB RAM، 10 GB SSD، منفذ شبكة 100 Mbps أو 1 Gbps.
* **الموقع الجغرافي:** ألمانيا (فرانكفورت)، هولندا (أمستردام)، أو المملكة المتحدة (لندن) لدعم تشغيل كافة الخدمات وتطبيقات الفيديو دون قيود إقليمية.

---

### 2. التثبيت السريع عبر سكربت النشر الآلي (Automated Setup)
انسخ مجلد `server/` إلى الخادم الخاص بك وشغّل سكربت التثبيت كـ `root`:

```bash
# تنزيل أو نسخ ملفات الخادم
cd /opt
sudo git clone <REPO_URL> vpn-server
cd vpn-server/server

# تشغيل سكربت الإعداد الشامل
sudo chmod +x deploy.sh
sudo ./deploy.sh
```

---

### 3. إعداد خادم WireGuard يدويًا (WireGuard Configuration)

#### أ. تثبيت الحزم وتفعيل التوجيه (Kernel Forwarding):
```bash
sudo apt update && sudo apt install -y wireguard iptables iptables-persistent qrencode

# تفعيل توجيه حزم IPv4 و IPv6 في النواة
sudo tee -a /etc/sysctl.d/99-wireguard.conf <<EOF
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
EOF
sudo sysctl -p /etc/sysctl.d/99-wireguard.conf
```

#### ب. توليد المفاتيح (Key Generation):
```bash
umask 077
wg genkey | tee server_private.key | wg pubkey > server_public.key
wg genkey | tee client_private.key | wg pubkey > client_public.key
```

#### ج. ملف تكوين الخادم `/etc/wireguard/wg0.conf`:
```ini
[Interface]
Address = 10.66.66.1/24, fd66:6666::1/64
ListenPort = 51820
PrivateKey = <SERVER_PRIVATE_KEY>

# قواعد جدار الحماية لتوجيه الـ NAT عند بدء وإيقاف الخدمة
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE; ip6tables -A FORWARD -i wg0 -j ACCEPT; ip6tables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE; ip6tables -D FORWARD -i wg0 -j ACCEPT; ip6tables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

# عميل التطبيق (Client Peer)
[Peer]
PublicKey = <CLIENT_PUBLIC_KEY>
AllowedIPs = 10.66.66.2/32, fd66:6666::2/128
```

#### د. تشغيل الخدمة وتفعيلها عند الإقلاع:
```bash
sudo systemctl enable --now wg-quick@wg0
sudo wg show
```

---

### 4. إعداد خادم Xray للشبكات المقيدة (Xray Server with VLESS-REALITY)
يتم توفير ملف `server/xray/config.json` الجاهز للاستخدام:
* المنفذ: 443 (HTTPS)
* البروتوكول: VLESS
* الأمان: REALITY (باستخدام نطاق شرعي مثل `www.microsoft.com` أو `dl.google.com`)
* النقل: TCP / Vision

يضمن هذا الإعداد عدم إمكانية تمييز حركة الـ VPN عن حركة تصفح HTTPS العادية عبر أجهزة فحص الحزم العميقة (DPI).

---

### 5. ملف تكوين العميل الجاهز للاستيراد في التطبيق
يقوم السكربت تلقائياً بتوليد ملف `client.conf` وملف JSON وصورة QR Code يمكن استيرادها مباشرة داخل تطبيق الأندرويد:
```ini
[Interface]
PrivateKey = <CLIENT_PRIVATE_KEY>
Address = 10.66.66.2/32, fd66:6666::2/128
DNS = 1.1.1.1, 8.8.8.8

[Peer]
PublicKey = <SERVER_PUBLIC_KEY>
Endpoint = <YOUR_SERVER_PUBLIC_IP>:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
```
