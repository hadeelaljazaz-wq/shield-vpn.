# Test report — 2026-11-17 (verified evidence only)

| Test | Result | Evidence |
|---|---|---|
| App launches | NOT DEVICE TESTED on a phone; launched on Android 14 emulator by instrumentation | CI `device-e2e` |
| DNS Shield | Code path unchanged except honest `LOCAL_DNS_ONLY` state and DNS-only routes; NOT DEVICE TESTED | — |
| WireGuard connects to a real server | **PASS (emulator)** — official GoBackend, handshake + exit IP = gateway IP | CI `device-e2e`, `server-e2e` |
| Xray VLESS‑REALITY | **PASS (emulator)** — libxray TUN fd, exit IP = gateway IP | CI `device-e2e`, `server-e2e` (SOCKS + TUN, TCP + UDP) |
| Handshake | **PASS** — server `wg show latest-handshakes` > 0, app waits for real handshake timestamp | CI |
| Public IP changes | **PASS** — exit IP through tunnel equals gateway IP (CI runner) | CI |
| Web browsing through tunnel | **PASS** — HTTPS + DNS via tunnel | CI |
| DNS ad blocking in tunnel | **PASS** — AdGuard DNS returns 0.0.0.0 for doubleclick.net via tunnel | CI `server-e2e` |
| Speed | Measured, CI only (not representative of a phone in Jordan) | logs |
| TikTok on censored network | **NOT DEVICE TESTED** | — |
| Reconnection after network switch | Implemented (monitor + backoff, Xray rebuild on network change); NOT DEVICE TESTED | — |
| Disconnect | **PASS (emulator)** — test disconnects WireGuard then connects Xray | CI |
| DNS leak / split tunneling | Implemented via VpnService/GoBackend DNS + include/exclude apps; NOT DEVICE TESTED | — |
| Real Oracle server | **BLOCKED BY SERVER PROVISIONING** — needs the owner's Oracle account | — |
| APK builds and is signed | **PASS** | GitHub release `apk-*` |
