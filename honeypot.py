#!/usr/bin/env python3
# local honeypot - v5: fixed canary spam, dashboard with block controls, better logs

import socket, threading, logging, subprocess
import json, sys, signal, urllib.request, urllib.parse, time
from datetime import datetime
from pathlib import Path
from logging.handlers import RotatingFileHandler
from http.server import BaseHTTPRequestHandler, HTTPServer

try:
    from threat_intel import get_reputation, score_badge
    HAS_THREAT_INTEL = True
except ImportError:
    HAS_THREAT_INTEL = False

try:
    from ssh_trap import start_ssh_trap
    HAS_SSH_TRAP = True
except ImportError:
    HAS_SSH_TRAP = False

BASE_DIR     = Path(__file__).resolve().parent
CONFIG_FILE  = BASE_DIR / "config.json"
LOG_DIR      = BASE_DIR / "logs"
DATA_DIR     = BASE_DIR / "data"
BLOCKED_FILE = DATA_DIR / "blocked_ips.json"
RATE_FILE    = DATA_DIR / "rate_limits.json"
STATS_FILE   = DATA_DIR / "stats.json"
LOG_FILE     = LOG_DIR  / "honeypot.log"
PCAP_DIR     = LOG_DIR  / "pcap"
CANARY_DIR   = BASE_DIR / "canary_files"

LOG_DIR.mkdir(exist_ok=True)
DATA_DIR.mkdir(exist_ok=True)
PCAP_DIR.mkdir(exist_ok=True)

DEFAULT_CONFIG = {
    "ports": {
        "21":"FTP","22":"SSH","23":"Telnet","80":"HTTP",
        "3306":"MySQL","5432":"PostgreSQL","6379":"Redis","8080":"HTTP-Alt"
    },
    "auto_block_enabled":   False,
    "auto_block_threshold": 5,
    "alert_method":         "all",
    "log_level":            "INFO",
    "max_recv_bytes":       1024,
    "geoip_enabled":        True,
    "daily_summary":        True,
    "dashboard_port":       5000,
    "pcap_enabled":         False,
    "ssh_trap_enabled":     True,
    "canary_enabled":       True,
    "abuseipdb_key":        "",
    "telegram":             {"token": "", "chat_id": ""}
}

BANNERS = {
    "SSH":        b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n",
    "FTP":        b"220 (vsFTPd 3.0.5)\r\n",
    "Telnet":     b"Ubuntu 22.04 LTS\r\n\r\nlogin: ",
    "HTTP":       b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.52\r\nContent-Length: 0\r\n\r\n",
    "MySQL":      b"\x4a\x00\x00\x00\x0a8.0.36\x00",
    "PostgreSQL": b"R\x00\x00\x00\x08\x00\x00\x00\x00",
    "Redis":      b"-ERR Protocol error\r\n",
    "HTTP-Alt":   b"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Length: 0\r\n\r\n",
}

CANARY_PATHS = {
    "/admin", "/admin/", "/.env", "/config.php",
    "/wp-admin", "/phpinfo.php", "/backup",
    "/.git/config", "/api/keys"
}


def setup_logging(level):
    logger = logging.getLogger("honeypot")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    fmt = logging.Formatter("%(asctime)s | %(levelname)-8s | %(message)s",
                            datefmt="%Y-%m-%d %H:%M:%S")
    ch = logging.StreamHandler()
    ch.setFormatter(fmt)
    logger.addHandler(ch)
    fh = RotatingFileHandler(LOG_FILE, maxBytes=10*1024*1024, backupCount=5, encoding="utf-8")
    fh.setFormatter(fmt)
    logger.addHandler(fh)
    return logger


def load_config():
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE) as f:
            cfg = json.load(f)
        for k, v in DEFAULT_CONFIG.items():
            cfg.setdefault(k, v)
        cfg.setdefault("telegram", DEFAULT_CONFIG["telegram"])
        return cfg
    with open(CONFIG_FILE, "w") as f:
        json.dump(DEFAULT_CONFIG, f, indent=2)
    return DEFAULT_CONFIG.copy()


def _j(path, default=None):
    try:
        with open(path) as f: return json.load(f)
    except:
        return default if default is not None else {}

def _save(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


_stats_lock = threading.Lock()

def record_hit(ip, port, service):
    with _stats_lock:
        s = _j(STATS_FILE) or {"total": 0, "by_port": {}, "by_ip": {}, "date": ""}
        today = str(datetime.now().date())
        if s.get("date") != today:
            s = {"total": 0, "by_port": {}, "by_ip": {}, "date": today}
        s["total"] += 1
        k = f"{port}/{service}"
        s["by_port"][k] = s["by_port"].get(k, 0) + 1
        s["by_ip"][ip]  = s["by_ip"].get(ip, 0) + 1
        _save(STATS_FILE, s)


_geo_cache = {}

def geoip(ip):
    if ip in _geo_cache:
        return _geo_cache[ip]
    # show local IPs clearly instead of skipping them
    if ip in ("127.0.0.1", "::1"):
        _geo_cache[ip] = "localhost"
        return "localhost"
    if any(ip.startswith(p) for p in ("10.", "192.168.", "172.")):
        _geo_cache[ip] = "local network"
        return "local network"
    try:
        with urllib.request.urlopen(
            f"http://ip-api.com/json/{ip}?fields=status,country,city,isp", timeout=3
        ) as r:
            d = json.loads(r.read())
        if d.get("status") == "success":
            loc = f"{d.get('city','?')}, {d.get('country','?')} — {d.get('isp','?')}"
            _geo_cache[ip] = loc
            return loc
    except:
        pass
    _geo_cache[ip] = ""
    return ""


def tg_send(token, chat_id, text):
    if not token or not chat_id:
        return
    try:
        payload = json.dumps({
            "chat_id": chat_id, "text": text, "parse_mode": "HTML"
        }).encode()
        req = urllib.request.Request(
            f"https://api.telegram.org/bot{token}/sendMessage",
            data=payload, headers={"Content-Type": "application/json"}, method="POST"
        )
        urllib.request.urlopen(req, timeout=8)
    except:
        pass

def tg_get(token, method, params=None):
    url = f"https://api.telegram.org/bot{token}/{method}"
    if params:
        url += "?" + urllib.parse.urlencode(params)
    try:
        with urllib.request.urlopen(url, timeout=20) as r:
            return json.loads(r.read())
    except:
        return {}


def load_blocked():
    return _j(BLOCKED_FILE) or {}

def _ipt(args):
    subprocess.run(["sudo", "iptables"] + args, capture_output=True)

def block_ip(ip, reason, logger, config):
    blocked = load_blocked()
    if ip in blocked:
        return
    blocked[ip] = {"blocked_at": datetime.now().isoformat(), "reason": reason}
    _save(BLOCKED_FILE, blocked)
    _ipt(["-I", "INPUT", "-s", ip, "-j", "DROP"])
    logger.warning(f"blocked {ip} ({reason})")
    tg = config.get("telegram", {})
    threading.Thread(
        target=tg_send,
        args=(tg.get("token",""), tg.get("chat_id",""),
              f"🚫 <b>IP Blocked</b>\n<code>{ip}</code>\n{reason}"),
        daemon=True
    ).start()

def unblock_ip(ip):
    blocked = load_blocked()
    if ip not in blocked:
        return False
    del blocked[ip]
    _save(BLOCKED_FILE, blocked)
    _ipt(["-D", "INPUT", "-s", ip, "-j", "DROP"])
    return True

def load_rate_limits():
    return _j(RATE_FILE) or {}


def alert(msg, method, logger):
    logger.warning(f"hit: {msg}")
    if method in ("desktop", "all"):
        subprocess.Popen(
            ["notify-send", "--urgency=critical", "honeypot", msg],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )


def start_pcap(config, logger):
    if not config.get("pcap_enabled", False):
        return None
    ports = list(config.get("ports", {}).keys())
    port_filter = " or ".join(f"port {p}" for p in ports)
    fname = PCAP_DIR / f"capture_{datetime.now().strftime('%Y%m%d')}.pcap"
    try:
        proc = subprocess.Popen(
            ["sudo", "tcpdump", "-i", "any", "-w", str(fname), port_filter],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        logger.info(f"  pcap → logs/pcap/{fname.name}")
        return proc
    except FileNotFoundError:
        logger.warning("  tcpdump not found — sudo apt install tcpdump")
        return None


# canary: only alert on real file opens, ignore directory scans and system noise
_canary_debounce = {}
_canary_lock = threading.Lock()

def watch_canary_files(config, logger):
    if not config.get("canary_enabled", True) or not CANARY_DIR.exists():
        return

    r = subprocess.run(["which", "inotifywait"], capture_output=True)
    if r.returncode != 0:
        logger.warning("  inotifywait not found — sudo apt install inotify-tools")
        return

    logger.info(f"  canary files watching {CANARY_DIR}")
    tg = config.get("telegram", {})

    def _watch():
        cmd = [
            "inotifywait", "-m", "-r",
            "-e", "open",           # only actual opens, not ACCESS or ISDIR
            "--format", "%f %e",
            str(CANARY_DIR)
        ]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue

            parts = line.split()
            filename  = parts[0] if parts else ""
            event     = parts[1] if len(parts) > 1 else ""

            # skip directory events and system noise
            if "ISDIR" in event:
                continue
            if not filename or filename.startswith("."):
                continue

            # debounce: same file max once per 10 seconds
            with _canary_lock:
                last = _canary_debounce.get(filename, 0)
                now  = time.time()
                if now - last < 10:
                    continue
                _canary_debounce[filename] = now

            logger.warning(f"canary file opened: {filename}")
            threading.Thread(
                target=tg_send,
                args=(tg.get("token",""), tg.get("chat_id",""),
                      f"🪤 <b>Canary File Accessed!</b>\n"
                      f"📄 File: <code>{filename}</code>\n"
                      f"🕐 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"),
                daemon=True
            ).start()

    threading.Thread(target=_watch, daemon=True, name="canary-watch").start()


def handle_connection(conn, addr, port, service, config, logger, counters, lock):
    ip = addr[0]

    if ip in load_blocked():
        conn.close()
        return

    rl = load_rate_limits()
    if ip in rl:
        mkey = f"{ip}:{datetime.now().strftime('%Y%m%d%H%M')}"
        with lock:
            counters[mkey] = counters.get(mkey, 0) + 1
            if counters[mkey] > rl[ip].get("max_per_minute", 999):
                conn.close()
                return

    raw = b""
    try:
        conn.sendall(BANNERS.get(service, b""))
        conn.settimeout(2)
        try:
            raw = conn.recv(config.get("max_recv_bytes", 1024))
        except socket.timeout:
            pass
    except:
        pass
    finally:
        conn.close()

    decoded = raw.decode("utf-8", errors="replace").strip() if raw else ""
    geo     = geoip(ip) if config.get("geoip_enabled", True) else ""
    record_hit(ip, port, service)

    rep = None
    if HAS_THREAT_INTEL:
        try: rep = get_reputation(ip)
        except: pass

    rep_str = f" [{score_badge(rep['level'])} {rep['score']}/100]" if rep else ""
    msg = f"{port}/{service} <- {ip}{rep_str}" \
          + (f" [{geo}]" if geo else "") \
          + (f" | {repr(decoded[:80])}" if decoded else "")
    alert(msg, config.get("alert_method", "terminal"), logger)

    if config.get("alert_method", "terminal") in ("telegram", "all"):
        tg = config.get("telegram", {})
        geo_line = f"\n🌍 {geo}" if geo else ""
        rep_line = ""
        if rep:
            ext = rep.get("external") or {}
            abuse = f" | AbuseIPDB: {ext.get('abuse_score','?')}%" if ext else ""
            rep_line = f"\n{score_badge(rep['level'])} Reputation: {rep['score']}/100{abuse}"
        payload_line = f"\n📦 <code>{decoded[:300]}</code>" if decoded else ""
        threading.Thread(
            target=tg_send,
            args=(tg.get("token",""), tg.get("chat_id",""),
                  f"🍯 <b>Hit!</b>\n"
                  f"🕐 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
                  f"🎯 Port {port} ({service})\n"
                  f"🔴 <code>{ip}</code>{geo_line}{rep_line}{payload_line}"),
            daemon=True
        ).start()

    if config.get("auto_block_enabled", False):
        thr = config.get("auto_block_threshold", 5)
        with lock:
            counters[ip] = counters.get(ip, 0) + 1
            if counters[ip] >= thr:
                block_ip(ip, f"auto — {counters[ip]} hits", logger, config)
                counters.pop(ip, None)


def start_listener(port, service, config, logger, counters, lock, stop_event):
    try:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", port))
        srv.listen(20)
        srv.settimeout(1.0)
        logger.info(f"  listening on {port} ({service})")
    except OSError as e:
        logger.error(f"  can't bind {port}: {e}")
        return

    while not stop_event.is_set():
        try:
            conn, addr = srv.accept()
            threading.Thread(
                target=handle_connection,
                args=(conn, addr, port, service, config, logger, counters, lock),
                daemon=True
            ).start()
        except socket.timeout:
            continue
        except Exception as e:
            if not stop_event.is_set():
                logger.error(f"listener {port}: {e}")
    srv.close()


# ---- dashboard with block/unblock controls -----------------------------------

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta http-equiv="refresh" content="20">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Honeypot</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:#0f1117;color:#e2e8f0;font-family:'Segoe UI',sans-serif;font-size:14px}}
.header{{background:linear-gradient(135deg,#1a1f2e,#252b3b);padding:16px 24px;
         border-bottom:2px solid #f6ad55;display:flex;align-items:center;gap:12px}}
.header h1{{font-size:1.4rem;color:#f6ad55;font-weight:700}}
.ts{{margin-left:auto;font-size:.78rem;color:#718096}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;padding:20px}}
.card{{background:#1a1f2e;border:1px solid #2d3748;border-radius:10px;padding:18px 12px;text-align:center}}
.num{{font-size:2.2rem;font-weight:800;margin:6px 0}}
.lbl{{font-size:.68rem;color:#718096;text-transform:uppercase;letter-spacing:.06em}}
.y .num{{color:#f6ad55}} .r .num{{color:#fc8181}}
.b .num{{color:#63b3ed}} .g .num{{color:#68d391}} .p .num{{color:#b794f4}}
.sec{{padding:0 20px 24px}}
.sec h2{{font-size:.78rem;color:#a0aec0;margin-bottom:8px;text-transform:uppercase;
          letter-spacing:.08em;border-bottom:1px solid #2d3748;padding-bottom:6px}}
table{{width:100%;border-collapse:collapse;font-size:.8rem}}
th{{background:#252b3b;color:#a0aec0;padding:8px 10px;text-align:left;font-weight:500}}
td{{padding:7px 10px;border-bottom:1px solid #1a1f2e;color:#cbd5e0;vertical-align:middle}}
tr:hover td{{background:#1e2433}}
code{{background:#252b3b;padding:1px 5px;border-radius:3px;font-size:.78rem;font-family:monospace}}
.br{{display:inline-block;padding:1px 7px;border-radius:12px;font-size:.68rem;font-weight:600}}
.br-r{{background:#2d1515;color:#fc8181;border:1px solid #fc8181}}
.br-o{{background:#2d1f00;color:#f6ad55;border:1px solid #f6ad55}}
.br-g{{background:#1a2e1a;color:#68d391;border:1px solid #68d391}}
.bar-w{{background:#2d3748;border-radius:3px;height:6px;min-width:40px}}
.bar{{background:#f6ad55;height:6px;border-radius:3px}}
.log-box{{background:#111418;border:1px solid #2d3748;border-radius:8px;
           padding:12px;max-height:340px;overflow-y:auto;font-family:monospace;font-size:.72rem}}
.log-line{{padding:3px 0;border-bottom:1px solid #1a1f2e;color:#a0aec0;word-break:break-all}}
.log-line.warn{{color:#fc8181}}
.log-line.canary{{color:#f6ad55}}
.log-line.ssh{{color:#b794f4}}
.log-line.block{{color:#fc8181;font-weight:600}}
.btn{{display:inline-block;padding:3px 10px;border-radius:4px;font-size:.72rem;
       font-weight:600;cursor:pointer;border:none;text-decoration:none}}
.btn-block{{background:#2d1515;color:#fc8181;border:1px solid #fc8181}}
.btn-unblock{{background:#1a2e1a;color:#68d391;border:1px solid #68d391}}
.btn-block:hover{{background:#3d1515}}
.btn-unblock:hover{{background:#1a3e1a}}
.inp{{background:#252b3b;border:1px solid #4a5568;color:#e2e8f0;padding:5px 8px;
       border-radius:4px;font-size:.8rem;width:150px}}
.ctrl-row{{display:flex;gap:8px;align-items:center;padding:12px 20px 0;flex-wrap:wrap}}
.tick{{position:fixed;bottom:12px;right:12px;background:#1a1f2e;border:1px solid #2d3748;
        border-radius:6px;padding:5px 10px;font-size:.68rem;color:#4a5568}}
</style>
</head>
<body>
<div class="header">
  <span style="font-size:1.8rem">🍯</span>
  <h1>Honeypot</h1>
  <div class="ts">updated: {now}</div>
</div>

<div class="grid">
  <div class="card y"><div class="lbl">hits today</div><div class="num">{total}</div></div>
  <div class="card r"><div class="lbl">blocked</div><div class="num">{n_blocked}</div></div>
  <div class="card b"><div class="lbl">ports</div><div class="num">{n_ports}</div></div>
  <div class="card g"><div class="lbl">rate limits</div><div class="num">{n_rates}</div></div>
  <div class="card p"><div class="lbl">canary files</div><div class="num">{n_canary}</div></div>
</div>

<div class="ctrl-row">
  <form method="POST" action="/block" style="display:flex;gap:6px;align-items:center">
    <input class="inp" name="ip" placeholder="IP to block" required>
    <input class="inp" name="reason" placeholder="reason (optional)" style="width:130px">
    <button class="btn btn-block" type="submit">🚫 Block</button>
  </form>
  <form method="POST" action="/unblock" style="display:flex;gap:6px;align-items:center">
    <input class="inp" name="ip" placeholder="IP to unblock" required>
    <button class="btn btn-unblock" type="submit">✅ Unblock</button>
  </form>
</div>

<div style="padding:20px 20px 0">
<div class="sec" style="padding:0 0 24px">
  <h2>top targeted ports</h2>
  <table>
    <tr><th>port</th><th>hits</th><th style="width:40%"></th></tr>
    {port_rows}
  </table>
</div>
</div>

<div class="sec">
  <h2>top attackers</h2>
  <table>
    <tr><th>IP</th><th>hits</th><th>location</th><th>reputation</th><th>status</th><th>action</th></tr>
    {ip_rows}
  </table>
</div>

<div class="sec">
  <h2>blocked IPs</h2>
  <table>
    <tr><th>IP</th><th>reason</th><th>when</th><th>action</th></tr>
    {blocked_rows}
  </table>
</div>

<div class="sec">
  <h2>recent alerts <span style="color:#4a5568;font-size:.7rem;font-weight:400">({log_count} total in log)</span></h2>
  <div class="log-box" id="logbox">
    {log_lines}
  </div>
</div>

<div class="tick">🔄 auto-refresh 20s</div>

<script>
// scroll log to bottom on load
document.getElementById('logbox').scrollTop = 9999;
</script>
</body></html>"""


def _get_all_alerts(n=150):
    if not LOG_FILE.exists():
        return []
    lines = LOG_FILE.read_text(errors="replace").splitlines()
    return [l for l in lines if any(t in l for t in ["hit:", "blocked", "WARNING", "canary", "ssh"])][-n:]


def _rep_badge(ip):
    if not HAS_THREAT_INTEL:
        return ""
    try:
        rep = get_reputation(ip)
        level = rep.get("level", "low")
        score = rep.get("score", 0)
        cls   = {"critical":"br-r","high":"br-o","medium":"br-o","low":"br-g"}.get(level,"br-g")
        return f'<span class="br {cls}">{score}/100</span>'
    except:
        return ""


def build_dashboard(config):
    stats   = _j(STATS_FILE) or {}
    blocked = load_blocked()
    rates   = load_rate_limits()
    total   = stats.get("total", 0)
    n_canary = sum(1 for _ in CANARY_DIR.rglob("*") if _.is_file()) if CANARY_DIR.exists() else 0

    ports = sorted(stats.get("by_port", {}).items(), key=lambda x: -x[1])
    port_rows = "".join(
        f"<tr><td><code>{p}</code></td><td>{c}</td>"
        f"<td><div class='bar-w'><div class='bar' style='width:{int(c/max(total,1)*100)}%'></div></div></td></tr>"
        for p, c in ports[:8]
    ) or "<tr><td colspan='3' style='color:#4a5568'>no data yet — run a test: nc -w2 localhost 22</td></tr>"

    ips = sorted(stats.get("by_ip", {}).items(), key=lambda x: -x[1])
    ip_rows = ""
    for ip, c in ips[:15]:
        geo  = geoip(ip) if config.get("geoip_enabled", True) else ""
        rep  = _rep_badge(ip)
        is_blocked = ip in blocked
        status = '<span class="br br-r">blocked</span>' if is_blocked else '<span class="br br-g">active</span>'
        if is_blocked:
            action = f'<form method="POST" action="/unblock" style="display:inline"><input type="hidden" name="ip" value="{ip}"><button class="btn btn-unblock" type="submit">unblock</button></form>'
        else:
            action = f'<form method="POST" action="/block" style="display:inline"><input type="hidden" name="ip" value="{ip}"><input type="hidden" name="reason" value="dashboard"><button class="btn btn-block" type="submit">block</button></form>'
        ip_rows += f"<tr><td><code>{ip}</code></td><td>{c}</td><td style='color:#718096;font-size:.75rem'>{geo}</td><td>{rep}</td><td>{status}</td><td>{action}</td></tr>"
    if not ip_rows:
        ip_rows = "<tr><td colspan='6' style='color:#4a5568'>no data yet</td></tr>"

    blocked_rows = ""
    for ip, i in list(blocked.items()):
        action = f'<form method="POST" action="/unblock" style="display:inline"><input type="hidden" name="ip" value="{ip}"><button class="btn btn-unblock" type="submit">unblock</button></form>'
        blocked_rows += f"<tr><td><code>{ip}</code></td><td>{i.get('reason','?')}</td><td style='color:#718096'>{i.get('blocked_at','?')[:19]}</td><td>{action}</td></tr>"
    if not blocked_rows:
        blocked_rows = "<tr><td colspan='4' style='color:#4a5568'>none</td></tr>"

    alerts = _get_all_alerts(150)
    log_lines = ""
    for a in reversed(alerts[-100:]):
        if "canary" in a:
            cls = "canary"
        elif "ssh cmd" in a or "ssh login" in a:
            cls = "ssh"
        elif "blocked" in a:
            cls = "block"
        elif "WARNING" in a or "hit:" in a:
            cls = "warn"
        else:
            cls = ""
        log_lines += f'<div class="log-line {cls}">{a}</div>'

    return DASHBOARD_HTML.format(
        now=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        total=total, n_blocked=len(blocked),
        n_ports=len(config.get("ports", {})), n_rates=len(rates),
        n_canary=n_canary, port_rows=port_rows, ip_rows=ip_rows,
        blocked_rows=blocked_rows, log_lines=log_lines,
        log_count=len(alerts)
    )


def make_handler(config, logger):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass

        def do_GET(self):
            ip = self.client_address[0]
            if self.path in CANARY_PATHS or any(self.path.startswith(p) for p in CANARY_PATHS):
                logger.warning(f"canary HTTP hit: {ip} → {self.path}")
                tg = config.get("telegram", {})
                threading.Thread(target=tg_send, args=(
                    tg.get("token",""), tg.get("chat_id",""),
                    f"🪤 <b>Canary URL!</b>\n🔴 <code>{ip}</code>\n🔗 <code>{self.path}</code>"
                ), daemon=True).start()
                self.send_response(403); self.end_headers()
                self.wfile.write(b"Forbidden"); return

            body = build_dashboard(config).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers(); self.wfile.write(body)

        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            body   = self.rfile.read(length).decode()
            params = dict(p.split("=", 1) for p in body.split("&") if "=" in p)
            ip     = urllib.parse.unquote_plus(params.get("ip", "").strip())
            reason = urllib.parse.unquote_plus(params.get("reason", "dashboard").strip())

            if ip:
                if self.path == "/block":
                    block_ip(ip, reason or "dashboard", logger, config)
                elif self.path == "/unblock":
                    unblock_ip(ip)

            # redirect back to dashboard
            self.send_response(303)
            self.send_header("Location", "/")
            self.end_headers()

    return H


def start_dashboard(config, logger):
    port = config.get("dashboard_port", 5000)
    srv  = HTTPServer(("0.0.0.0", port), make_handler(config, logger))
    logger.info(f"  dashboard at http://localhost:{port}")
    threading.Thread(target=srv.serve_forever, daemon=True).start()


# ---- telegram bot ------------------------------------------------------------

def _bot_status():
    blocked = load_blocked()
    stats   = _j(STATS_FILE) or {}
    cfg     = _j(CONFIG_FILE) or {}
    r = subprocess.run(["pgrep", "-fa", "honeypot.py"], capture_output=True, text=True)
    up = any("honeypot.py" in l for l in r.stdout.splitlines())
    n_canary = sum(1 for _ in CANARY_DIR.rglob("*") if _.is_file()) if CANARY_DIR.exists() else 0
    return (
        f"{'🟢 running' if up else '🔴 stopped'}\n"
        f"ports: {len(cfg.get('ports', {}))}\n"
        f"hits today: {stats.get('total', 0)}\n"
        f"blocked: {len(blocked)}\n"
        f"canary files: {n_canary}\n"
        f"{datetime.now().strftime('%H:%M:%S')}"
    )

def _bot_stats():
    s  = _j(STATS_FILE) or {}
    tp = sorted(s.get("by_port", {}).items(), key=lambda x: -x[1])[:5]
    ti = sorted(s.get("by_ip",   {}).items(), key=lambda x: -x[1])[:5]
    lines = [f"📊 <b>{s.get('date','today')}</b>\ntotal: {s.get('total', 0)}\n\ntop ports:"]
    for p, c in tp: lines.append(f"  {p}: {c}")
    lines.append("\ntop IPs:")
    for ip, c in ti:
        rep = ""
        if HAS_THREAT_INTEL:
            try:
                r = get_reputation(ip)
                rep = f" {score_badge(r['level'])}{r['score']}"
            except: pass
        lines.append(f"  <code>{ip}</code>: {c}{rep}")
    return "\n".join(lines)

def _bot_list():
    blocked = load_blocked()
    if not blocked: return "nothing blocked"
    return "blocked:\n" + "\n".join(
        f"<code>{ip}</code> — {i.get('reason','?')}"
        for ip, i in list(blocked.items())[:15]
    )

def _bot_logs():
    alerts = _get_all_alerts(15)
    if not alerts: return "no recent alerts"
    return "<code>" + "\n".join(l[-90:] for l in reversed(alerts)) + "</code>"

def _bot_block(ip, logger, config):
    if not ip: return "usage: /block &lt;ip&gt;"
    blocked = load_blocked()
    if ip in blocked: return f"{ip} already blocked"
    blocked[ip] = {"blocked_at": datetime.now().isoformat(), "reason": "telegram"}
    _save(BLOCKED_FILE, blocked)
    _ipt(["-I", "INPUT", "-s", ip, "-j", "DROP"])
    logger.warning(f"[tg] blocked {ip}")
    return f"blocked <code>{ip}</code>"

def _bot_unblock(ip, logger):
    if not ip: return "usage: /unblock &lt;ip&gt;"
    if unblock_ip(ip):
        logger.info(f"[tg] unblocked {ip}")
        return f"unblocked <code>{ip}</code>"
    return f"{ip} not in list"

def _bot_limits():
    rates = load_rate_limits()
    if not rates: return "no rate limits"
    return "\n".join(f"<code>{ip}</code> — {i.get('max_per_minute','?')}/min" for ip, i in rates.items())

def _bot_rep(ip):
    if not ip: return "usage: /rep &lt;ip&gt;"
    if not HAS_THREAT_INTEL: return "threat_intel not loaded"
    try:
        rep = get_reputation(ip)
        ext = rep.get("external") or {}
        lines = [f"{score_badge(rep['level'])} <b>{rep['score']}/100</b> ({rep['level']})", f"<code>{ip}</code>"]
        if ext:
            lines.append(f"AbuseIPDB: {ext.get('abuse_score','?')}%")
            lines.append(f"Reports: {ext.get('reports','?')}")
            if ext.get("is_tor"): lines.append("⚠️ TOR exit node")
        return "\n".join(lines)
    except Exception as e:
        return f"error: {e}"

HELP_TEXT = (
    "/status\n/stats\n/list\n"
    "/block &lt;ip&gt;\n/unblock &lt;ip&gt;\n"
    "/rep &lt;ip&gt;\n/limits\n/logs\n/help"
)

def run_bot(token, chat_id, logger, stop_event):
    offset  = 0
    allowed = str(chat_id)
    logger.info("  telegram bot ready")

    while not stop_event.is_set():
        try:
            data = tg_get(token, "getUpdates", {"offset": offset, "timeout": 20})
            for upd in data.get("result", []):
                offset = upd["update_id"] + 1
                msg    = upd.get("message", {})
                sender = str(msg.get("chat", {}).get("id", ""))
                text   = msg.get("text", "").strip()

                if not text or not text.startswith("/"): continue

                # log every sender so you can debug chat_id issues
                logger.info(f"bot msg from chat_id={sender}: {text}")

                if sender != allowed:
                    tg_send(token, sender, f"not authorized\nyour chat_id: <code>{sender}</code>")
                    continue

                parts = text.split()
                cmd   = parts[0].lower().split("@")[0]
                arg   = parts[1] if len(parts) > 1 else ""
                cfg   = load_config()

                if   cmd == "/help":    reply = HELP_TEXT
                elif cmd == "/status":  reply = _bot_status()
                elif cmd == "/stats":   reply = _bot_stats()
                elif cmd == "/list":    reply = _bot_list()
                elif cmd == "/logs":    reply = _bot_logs()
                elif cmd == "/block":   reply = _bot_block(arg, logger, cfg)
                elif cmd == "/unblock": reply = _bot_unblock(arg, logger)
                elif cmd == "/limits":  reply = _bot_limits()
                elif cmd == "/rep":     reply = _bot_rep(arg)
                else:                   reply = "unknown — try /help"

                tg_send(token, chat_id, reply)
        except Exception as e:
            if not stop_event.is_set():
                logger.error(f"bot error: {e}")
            time.sleep(5)


def daily_scheduler(config, logger, stop_event):
    sent_today = None
    while not stop_event.is_set():
        now = datetime.now()
        if now.hour == 8 and now.minute == 0 and sent_today != now.date():
            tg  = config.get("telegram", {})
            s   = _j(STATS_FILE) or {}
            b   = load_blocked()
            tp  = sorted(s.get("by_port", {}).items(), key=lambda x: -x[1])[:5]
            ti  = sorted(s.get("by_ip",   {}).items(), key=lambda x: -x[1])[:5]
            tg_send(tg.get("token",""), tg.get("chat_id",""),
                f"📊 daily — {s.get('date','?')}\n"
                f"hits: {s.get('total',0)} | blocked: {len(b)}\n\n"
                f"ports:\n" + "\n".join(f"  {p}: {c}" for p,c in tp) +
                f"\n\nIPs:\n"  + "\n".join(f"  <code>{i}</code>: {c}" for i,c in ti)
            )
            logger.info("daily summary sent")
            sent_today = now.date()
        time.sleep(30)


def main():
    config     = load_config()
    logger     = setup_logging(config.get("log_level", "INFO"))
    stop_event = threading.Event()
    counters   = {}
    lock       = threading.Lock()
    tg         = config.get("telegram", {})

    logger.info("starting honeypot v5...")

    for port_str, service in config["ports"].items():
        threading.Thread(
            target=start_listener,
            args=(int(port_str), service, config, logger, counters, lock, stop_event),
            daemon=True
        ).start()

    start_dashboard(config, logger)

    if config.get("ssh_trap_enabled", True) and HAS_SSH_TRAP:
        threading.Thread(target=start_ssh_trap, args=(config, logger, stop_event), daemon=True).start()

    pcap_proc = start_pcap(config, logger)
    watch_canary_files(config, logger)

    if tg.get("token"):
        threading.Thread(target=run_bot,
            args=(tg["token"], tg["chat_id"], logger, stop_event), daemon=True).start()

    if config.get("daily_summary", True):
        threading.Thread(target=daily_scheduler,
            args=(config, logger, stop_event), daemon=True).start()

    dash = config.get("dashboard_port", 5000)
    threading.Thread(target=tg_send, args=(
        tg.get("token",""), tg.get("chat_id",""),
        f"✅ honeypot v5 started\n{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"ports: {len(config['ports'])} | dashboard: http://localhost:{dash}"
    ), daemon=True).start()

    def _shutdown(sig, frame):
        logger.info("shutting down...")
        if pcap_proc: pcap_proc.terminate()
        tg_send(tg.get("token",""), tg.get("chat_id",""), "🛑 honeypot stopped")
        stop_event.set()
        sys.exit(0)

    signal.signal(signal.SIGINT,  _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)
    logger.info(f"running — dashboard at http://localhost:{dash}")
    signal.pause()


if __name__ == "__main__":
    main()
