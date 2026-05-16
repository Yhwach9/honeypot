#!/usr/bin/env python3
# CLI tool to manage the honeypot - block/unblock IPs, check logs, etc.

import argparse, json, subprocess
from datetime import datetime
from pathlib import Path

BASE_DIR     = Path(__file__).resolve().parent
BLOCKED_FILE = BASE_DIR / "data" / "blocked_ips.json"
RATE_FILE    = BASE_DIR / "data" / "rate_limits.json"
STATS_FILE   = BASE_DIR / "data" / "stats.json"
LOG_FILE     = BASE_DIR / "logs" / "honeypot.log"

(BASE_DIR / "data").mkdir(exist_ok=True)

R="\033[91m"; G="\033[92m"; Y="\033[93m"; C="\033[96m"; BD="\033[1m"; NC="\033[0m"
def red(t):   return f"{R}{t}{NC}"
def green(t): return f"{G}{t}{NC}"
def cyan(t):  return f"{C}{t}{NC}"
def yellow(t):return f"{Y}{t}{NC}"
def bold(t):  return f"{BD}{t}{NC}"

def _j(path):
    try:
        with open(path) as f: return json.load(f)
    except: return {}

def _save(path, data):
    with open(path, "w") as f: json.dump(data, f, indent=2)

def _ipt(args):
    return subprocess.run(["sudo", "iptables"] + args, capture_output=True).returncode == 0


def cmd_status(args):
    blocked = _j(BLOCKED_FILE)
    rates   = _j(RATE_FILE)
    stats   = _j(STATS_FILE)
    r = subprocess.run(["pgrep", "-fa", "honeypot.py"], capture_output=True, text=True)
    running = any("honeypot.py" in l for l in r.stdout.splitlines())
    log_size = f"{LOG_FILE.stat().st_size/1024:.1f} KB" if LOG_FILE.exists() else "—"
    cfg = _j(BASE_DIR / "config.json")

    print(bold("\n  honeypot status\n") + "  " + "─"*35)
    print(f"  process   : {green('running') if running else red('stopped')}")
    print(f"  hits today: {yellow(str(stats.get('total', 0)))}")
    print(f"  blocked   : {red(str(len(blocked))) if blocked else green('0')}")
    print(f"  rate limits: {cyan(str(len(rates)))}")
    print(f"  log size  : {log_size}")
    print(f"  dashboard : http://localhost:{cfg.get('dashboard_port', 5000)}")
    if blocked:
        print(bold("\n  recently blocked:"))
        for ip, i in list(blocked.items())[:5]:
            print(f"    {red(ip)} — {i.get('reason','?')} @ {i.get('blocked_at','?')[:16]}")
    print()


def cmd_block(args):
    blocked = _j(BLOCKED_FILE)
    if args.ip in blocked:
        print(yellow(f"  {args.ip} is already blocked"))
        return
    blocked[args.ip] = {"blocked_at": datetime.now().isoformat(), "reason": args.reason}
    _save(BLOCKED_FILE, blocked)
    ok = _ipt(["-I", "INPUT", "-s", args.ip, "-j", "DROP"])
    print(red(f"  blocked {args.ip}") + f"  (iptables: {'ok' if ok else 'failed — try sudo'})")


def cmd_unblock(args):
    blocked = _j(BLOCKED_FILE)
    if args.ip not in blocked:
        print(yellow(f"  {args.ip} not in block list"))
        return
    del blocked[args.ip]
    _save(BLOCKED_FILE, blocked)
    _ipt(["-D", "INPUT", "-s", args.ip, "-j", "DROP"])
    print(green(f"  unblocked {args.ip}"))


def cmd_list(args):
    blocked = _j(BLOCKED_FILE)
    if not blocked:
        print(green("  no IPs blocked"))
        return
    print(bold(f"\n  {'IP':<20} {'blocked at':<22} reason"))
    print("  " + "─"*58)
    for ip, i in sorted(blocked.items()):
        print(f"  {red(ip):<29} {i.get('blocked_at','?')[:19]:<22} {i.get('reason','?')}")
    print(f"\n  total: {len(blocked)}\n")


def cmd_limit(args):
    rates = _j(RATE_FILE)
    if args.rate == 0:
        if args.ip in rates:
            del rates[args.ip]
            _save(RATE_FILE, rates)
            print(green(f"  removed rate limit for {args.ip}"))
        else:
            print(yellow(f"  no limit found for {args.ip}"))
        return
    rates[args.ip] = {"max_per_minute": args.rate, "set_at": datetime.now().isoformat()}
    _save(RATE_FILE, rates)
    print(cyan(f"  {args.ip} → max {args.rate} connections/min"))


def cmd_limits(args):
    rates = _j(RATE_FILE)
    if not rates:
        print(green("  no rate limits"))
        return
    print(bold(f"\n  {'IP':<20} max/min   set at"))
    print("  " + "─"*50)
    for ip, i in rates.items():
        print(f"  {cyan(ip):<29} {i.get('max_per_minute','?'):<10} {i.get('set_at','?')[:16]}")
    print()


def cmd_logs(args):
    if not LOG_FILE.exists():
        print(yellow("  no log file yet"))
        return
    n = args.last or 30
    lines = LOG_FILE.read_text(errors="replace").splitlines()[-n:]
    print(bold(f"\n  last {n} entries\n"))
    for l in lines:
        if any(t in l for t in ["WARNING", "hit:", "blocked"]):
            print(f"  {red(l)}")
        elif "ERROR" in l:
            print(f"  {yellow(l)}")
        else:
            print(f"  {cyan(l)}")
    print()


def cmd_stats(args):
    s = _j(STATS_FILE)
    if not s:
        print(yellow("  no stats yet"))
        return
    tp = sorted(s.get("by_port", {}).items(), key=lambda x: -x[1])[:8]
    ti = sorted(s.get("by_ip",   {}).items(), key=lambda x: -x[1])[:8]
    print(bold(f"\n  stats — {s.get('date','?')}\n") + "  " + "─"*35)
    print(f"  total hits: {yellow(str(s.get('total', 0)))}\n")
    print(bold("  top ports:"))
    for p, c in tp: print(f"    {cyan(p):<22} {c}")
    print(bold("\n  top attackers:"))
    for ip, c in ti: print(f"    {red(ip):<24} {c}")
    print()


def main():
    p = argparse.ArgumentParser(
        description="honeypot manager",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = p.add_subparsers(dest="cmd", metavar="command")

    sub.add_parser("status").set_defaults(func=cmd_status)

    b = sub.add_parser("block")
    b.add_argument("ip")
    b.add_argument("--reason", default="manual")
    b.set_defaults(func=cmd_block)

    u = sub.add_parser("unblock")
    u.add_argument("ip")
    u.set_defaults(func=cmd_unblock)

    sub.add_parser("list").set_defaults(func=cmd_list)

    lm = sub.add_parser("limit")
    lm.add_argument("ip")
    lm.add_argument("--rate", type=int, required=True)
    lm.set_defaults(func=cmd_limit)

    sub.add_parser("limits").set_defaults(func=cmd_limits)

    lg = sub.add_parser("logs")
    lg.add_argument("--last", type=int, default=30)
    lg.set_defaults(func=cmd_logs)

    sub.add_parser("stats").set_defaults(func=cmd_stats)

    args = p.parse_args()
    if not args.cmd:
        p.print_help()
        return
    args.func(args)


if __name__ == "__main__":
    main()
