#!/usr/bin/env python3
"""Smart Ad Shield VPN — provisioning API (stdlib only).

Endpoints (HTTPS, self-signed cert pinned by the app):
  GET  /v1/health                         no auth  -> liveness + load (used for latency/health checks)
  POST /v1/register   {wg_public_key, device}   Bearer token -> per-device WireGuard + Xray credentials
  POST /v1/unregister {wg_public_key}            Bearer token

Design rules:
  * The device generates its WireGuard private key locally; only the public key is received here.
  * No logging of client traffic, destinations or DNS. Only peer public keys / assigned IPs are stored.
"""
import base64
import hmac
import ipaddress
import json
import os
import ssl
import subprocess
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ETC = os.environ.get("SHIELD_ETC", "/etc/shieldvpn")
STATE = os.path.join(ETC, "state.json")
XRAY_CONFIG = os.environ.get("SHIELD_XRAY_CONFIG", "/usr/local/etc/xray/config.json")
API_PORT = int(os.environ.get("SHIELD_API_PORT", "8443"))
REALITY_DEST = os.environ.get("SHIELD_REALITY_DEST", "www.microsoft.com")
WG_IF = "wg0"
NET4 = ipaddress.ip_network("10.66.66.0/24")
NET6 = ipaddress.ip_network("fd66:66::/64")
MAX_PEERS = 200
LOCK = threading.Lock()
_fail_times = []


def _read(path):
    with open(path, "r", encoding="utf-8") as f:
        return f.read().strip()


def load_json(path, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return default


def save_json(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=1)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def valid_wg_key(k):
    try:
        return isinstance(k, str) and len(base64.b64decode(k, validate=True)) == 32
    except Exception:
        return False


def run(*cmd):
    return subprocess.run(cmd, check=True, capture_output=True, text=True).stdout


def apply_wg_peer(pub, ip4, ip6):
    run("wg", "set", WG_IF, "peer", pub, "allowed-ips", f"{ip4}/32,{ip6}/128")


def remove_wg_peer(pub):
    run("wg", "set", WG_IF, "peer", pub, "remove")


def xray_enabled(server):
    return bool(server.get("xray"))


def write_xray_config(server, state):
    if not xray_enabled(server):
        return
    reality = load_json(os.path.join(ETC, "reality.json"), {})
    clients = [
        {"id": p["uuid"], "flow": "xtls-rprx-vision", "email": f"peer{n}@shield"}
        for n, p in enumerate(state["peers"].values())
    ]
    cfg = {
        "log": {"loglevel": "warning", "access": "none"},
        "inbounds": [{
            "listen": "0.0.0.0",
            "port": server["xray"]["port"],
            "protocol": "vless",
            "settings": {"clients": clients, "decryption": "none"},
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "show": False,
                    "dest": f"{REALITY_DEST}:443",
                    "xver": 0,
                    "serverNames": [REALITY_DEST],
                    "privateKey": reality["private_key"],
                    "shortIds": [reality["short_id"]],
                },
            },
            "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"], "routeOnly": True},
        }],
        "outbounds": [
            {"protocol": "freedom", "tag": "direct", "settings": {"domainStrategy": "UseIPv4v6"}},
            {"protocol": "blackhole", "tag": "block"},
        ],
        "routing": {"rules": [{"type": "field", "ip": ["geoip:private"], "outboundTag": "block"}]},
    }
    new = json.dumps(cfg, indent=1)
    try:
        old = _read(XRAY_CONFIG)
    except FileNotFoundError:
        old = ""
    if new.strip() != old.strip():
        os.makedirs(os.path.dirname(XRAY_CONFIG), exist_ok=True)
        with open(XRAY_CONFIG, "w", encoding="utf-8") as f:
            f.write(new)
        subprocess.run(["systemctl", "restart", "xray"], check=False)


def allocate(state):
    used4 = {p["ip4"] for p in state["peers"].values()}
    for host in NET4.hosts():
        if int(host) - int(NET4.network_address) < 2:
            continue  # .1 is the gateway
        if str(host) not in used4:
            idx = int(host) - int(NET4.network_address)
            ip6 = NET6.network_address + idx
            return str(host), str(ip6)
    raise RuntimeError("address pool exhausted")


def restore():
    state = load_json(STATE, {"peers": {}})
    server = load_json(os.path.join(ETC, "server.json"), {})
    for pub, p in state["peers"].items():
        try:
            apply_wg_peer(pub, p["ip4"], p["ip6"])
        except Exception as e:  # interface may be restarting
            print("restore peer failed:", e, file=sys.stderr)
    write_xray_config(server, state)


def wg_up():
    try:
        run("wg", "show", WG_IF, "public-key")
        return True
    except Exception:
        return False


def xray_active():
    r = subprocess.run(["systemctl", "is-active", "xray"], capture_output=True, text=True)
    return r.stdout.strip() == "active"


class Handler(BaseHTTPRequestHandler):
    server_version = "shield"
    timeout = 15
    sys_version = ""

    def log_message(self, fmt, *args):  # no access logs (privacy)
        pass

    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _authorized(self):
        token = _read(os.path.join(ETC, "token"))
        got = self.headers.get("Authorization", "")
        ok = got.startswith("Bearer ") and hmac.compare_digest(got[7:].encode(), token.encode())
        if not ok:
            now = time.time()
            _fail_times[:] = [t for t in _fail_times if now - t < 60] + [now]
            time.sleep(min(5, 0.2 * len(_fail_times)))  # slow brute force down
        return ok

    def _body(self):
        n = int(self.headers.get("Content-Length", "0") or 0)
        if n > 4096:
            raise ValueError("body too large")
        return json.loads(self.rfile.read(n) or b"{}")

    def do_GET(self):
        if self.path == "/v1/health":
            server = load_json(os.path.join(ETC, "server.json"), {})
            state = load_json(STATE, {"peers": {}})
            self._send(200, {
                "ok": wg_up(),
                "name": server.get("name"),
                "cc": server.get("cc"),
                "wg": wg_up(),
                "xray": xray_active() if xray_enabled(server) else None,
                "load": os.getloadavg()[0],
                "peers": len(state["peers"]),
                "time": int(time.time()),
            })
        else:
            self._send(404, {"error": "not_found"})

    def do_POST(self):
        if not self._authorized():
            return self._send(401, {"error": "unauthorized"})
        try:
            body = self._body()
        except Exception:
            return self._send(400, {"error": "bad_json"})
        pub = body.get("wg_public_key", "")
        if not valid_wg_key(pub):
            return self._send(400, {"error": "bad_public_key"})
        server = load_json(os.path.join(ETC, "server.json"), {})
        with LOCK:
            state = load_json(STATE, {"peers": {}})
            if self.path == "/v1/register":
                p = state["peers"].get(pub)
                if p is None:
                    if len(state["peers"]) >= MAX_PEERS:
                        return self._send(409, {"error": "server_full"})
                    ip4, ip6 = allocate(state)
                    p = {"ip4": ip4, "ip6": ip6, "uuid": str(uuid.uuid4()),
                         "device": str(body.get("device", ""))[:64], "created": int(time.time())}
                    state["peers"][pub] = p
                    save_json(STATE, state)
                apply_wg_peer(pub, p["ip4"], p["ip6"])
                write_xray_config(server, state)
                resp = {
                    "name": server.get("name"),
                    "cc": server.get("cc"),
                    "public_ip": server.get("public_ip"),
                    "wg": {
                        "server_public_key": server["wg"]["public_key"],
                        "endpoint_host": server.get("public_ip"),
                        "endpoint_port": server["wg"]["port"],
                        "address4": p["ip4"] + "/32",
                        "address6": p["ip6"] + "/128",
                        "mtu": server["wg"].get("mtu", 1280),
                        "keepalive": 25,
                    },
                    "xray": None,
                }
                if xray_enabled(server):
                    x = server["xray"]
                    resp["xray"] = {
                        "address": server.get("public_ip"), "port": x["port"], "uuid": p["uuid"],
                        "flow": x["flow"], "sni": x["sni"], "public_key": x["public_key"],
                        "short_id": x["short_id"], "fingerprint": "chrome",
                    }
                return self._send(200, resp)
            if self.path == "/v1/unregister":
                p = state["peers"].pop(pub, None)
                if p:
                    save_json(STATE, state)
                    remove_wg_peer(pub)
                    write_xray_config(server, state)
                return self._send(200, {"removed": bool(p)})
        return self._send(404, {"error": "not_found"})


def main():
    restore()
    httpd = ThreadingHTTPServer(("0.0.0.0", API_PORT), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(os.path.join(ETC, "api.crt"), os.path.join(ETC, "api.key"))
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True, do_handshake_on_connect=False)
    print(f"provisioning API on :{API_PORT}", flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
