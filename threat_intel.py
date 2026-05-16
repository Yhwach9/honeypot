#!/usr/bin/env python3
# IP reputation scoring - internal behavior analysis + optional AbuseIPDB check
# score 0-100: higher = more dangerous

import json, urllib.request, urllib.error
from datetime import datetime
from pathlib import Path

BASE_DIR   = Path(__file__).resolve().parent
STATS_FILE = BASE_DIR / "data" / "stats.json"
REP_FILE   = BASE_DIR / "data" / "reputation.json"
CONFIG_FILE= BASE_DIR / "config.json"

def _j(path):
    try:
        with open(path) as f: return json.load(f)
    except: return {}


def internal_score(ip):
    """score based on local behavior — no external calls needed"""
    stats = _j(STATS_FILE)
    hits  = stats.get("by_ip", {}).get(ip, 0)

    score = 0

    # more hits = more suspicious
    if hits >= 20:  score += 40
    elif hits >= 10: score += 25
    elif hits >= 5:  score += 15
    elif hits >= 2:  score += 5

    # if they hit many different ports, they're scanning
    port_hits = sum(
        1 for k, v in stats.get("by_port", {}).items()
        if ip in _j(BASE_DIR / "data" / "stats.json").get("by_ip", {})
    )
    if port_hits >= 5: score += 30
    elif port_hits >= 3: score += 15
    elif port_hits >= 2: score += 5

    return min(score, 70)  # max from internal is 70, rest from external


def abuseipdb_score(ip, api_key):
    """check AbuseIPDB - free tier: 1000 checks/day, get key at abuseipdb.com"""
    if not api_key:
        return 0, None
    # skip private IPs
    if any(ip.startswith(p) for p in ("127.", "10.", "192.168.", "172.")):
        return 0, None
    try:
        req = urllib.request.Request(
            f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90",
            headers={"Key": api_key, "Accept": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=5) as r:
            data = json.loads(r.read())
        d = data.get("data", {})
        abuse_score = d.get("abuseConfidenceScore", 0)
        reports     = d.get("totalReports", 0)
        country     = d.get("countryCode", "")
        return int(abuse_score * 0.3), {  # scale to max 30 pts
            "abuse_score": abuse_score,
            "reports":     reports,
            "country":     country,
            "is_tor":      d.get("isTor", False),
        }
    except Exception:
        return 0, None


def get_reputation(ip):
    """combined score + cache results"""
    cache = _j(REP_FILE)
    today = str(datetime.now().date())

    if ip in cache and cache[ip].get("date") == today:
        return cache[ip]

    cfg     = _j(CONFIG_FILE)
    api_key = cfg.get("abuseipdb_key", "")

    score   = internal_score(ip)
    ext_pts, ext_data = abuseipdb_score(ip, api_key)
    score   = min(score + ext_pts, 100)

    if   score >= 80: level = "critical"
    elif score >= 60: level = "high"
    elif score >= 35: level = "medium"
    else:             level = "low"

    result = {
        "ip":       ip,
        "score":    score,
        "level":    level,
        "date":     today,
        "external": ext_data
    }

    # cache it
    cache[ip] = result
    try:
        with open(REP_FILE, "w") as f: json.dump(cache, f, indent=2)
    except: pass

    return result


def score_badge(level):
    return {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(level, "⚪")
