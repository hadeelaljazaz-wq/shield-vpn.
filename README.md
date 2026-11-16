# Smart Ad Shield VPN

Android VPN with three honest modes:

| Mode | What it really does | Changes IP? |
|---|---|---|
| **WireGuard** | Official `wireguard-go` (GoBackend) tunnel to *your* server | Yes |
| **Xray VLESS‑REALITY** | Xray-core (built from source) over TCP/443, for networks that block WireGuard/UDP | Yes |
| **Local DNS Shield** | On-device DNS ad filtering. **Not a VPN**, no server, no encryption of traffic | No |

`CONNECTED` is shown only after a protocol-level proof (WireGuard handshake / Xray tunnel up) **and** an HTTPS request through the tunnel reports the server's IP as the exit IP. The app ships **no preset servers**: every server in the list is one you enrolled or imported.

## Download
Latest APK: **https://github.com/hadeelaljazaz-wq/shield-vpn./releases/latest/download/SmartAdShieldVPN.apk**

## Your server (Oracle Cloud Always Free)
1. Create an Oracle Cloud Free Tier account (card is used for identity verification).
2. Open **[Deploy to Oracle Cloud](https://cloud.oracle.com/resourcemanager/stacks/create?zipUrl=https://github.com/hadeelaljazaz-wq/shield-vpn./releases/download/oracle-stack/oracle-stack.zip)** → accept terms → *Next* → *Create* (keep **Run apply** ticked).
3. When the job is *Succeeded*, wait ~4 minutes, open **Outputs** and copy `enrollment_code`.
4. In the app tap **Connect**, paste the code. The phone generates its own WireGuard key; only the public key is sent to the server.

If the job fails with *Out of host capacity*, edit the stack, pick `VM.Standard.E2.1.Micro` (or another availability domain) and apply again.

## What is tested and how
* **Server E2E (CI)** — `.github/workflows/server-e2e.yml` installs the real gateway on a GitHub runner and, from a network namespace with no internet route except the VPN, verifies: API auth rejection, provisioning, WireGuard handshake, exit IP, DNS through the tunnel, AdGuard ad-blocking, Xray SOCKS and Xray TUN (TCP + UDP), throughput.
* **Android (CI)** — unit tests + signed release APK.
* **Not covered by CI:** a real phone, a real censored network, TikTok. These need the device test below.

## Repository layout
```
app/                      Android app (Kotlin)
  tunnel/                 TunnelManager, WireGuard/Xray engines, enrollment, pinning, probes
  service/                ConnectionService, XrayVpnService, SmartAdShieldVpnService (DNS-only)
xray/libxray/             gomobile wrapper → app/libs/libxray.aar (built in CI)
server/install.sh         WireGuard + Xray + provisioning API installer (Ubuntu)
server/provision.py       provisioning API (stdlib, pinned TLS)
server/oracle/            Oracle Resource Manager Terraform stack
docs/legacy-unverified/   old reports — contain false claims, kept for history only
```

No secrets are stored in this repository: the enrollment token, TLS key and WireGuard/REALITY keys are generated inside the user's Oracle account and on the phone.
