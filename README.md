# Honeypot

A personal project I built to learn how attackers behave when they find open ports. It runs on my local Ubuntu machine, traps connections on common service ports, and gives me real-time visibility into what's hitting my network.

No external libraries except paramiko for the SSH emulator.

---

## What it does

- Listens on ports like SSH (22), FTP (21), MySQL (3306), Redis (6379), etc.
- Sends realistic service banners so scanners think the service is real
- Logs every connection with IP, port, timestamp, and captured data
- Looks up attacker location and ISP via ip-api.com
- Scores each IP with a reputation system (internal + AbuseIPDB if configured)
- Interactive fake SSH shell on port 2222 — logs every command typed
- PCAP capture of all honeypot traffic (open in Wireshark)
- Canary files — fake credentials/keys that alert when accessed
- Canary HTTP endpoints — alert when someone hits /admin, /.env, etc.
- Web dashboard at localhost:5000 with live stats
- Telegram alerts for every hit, plus bot commands to manage IPs remotely
- Daily summary report at 8am

---

## Project layout

```
honeypot/
├── honeypot.py        main daemon
├── ssh_trap.py        interactive fake SSH shell
├── threat_intel.py    IP reputation scoring + AbuseIPDB
├── manager.py         CLI tool
├── config.json        settings
├── install.sh         setup script
├── honeypot.service   systemd
├── canary_files/      fake sensitive files (trigger alerts when accessed)
│   ├── credentials.txt
│   ├── .env
│   ├── api_keys.md
│   ├── .ssh/id_rsa
│   └── backups/prod_backup_2024.sql
├── logs/
│   ├── honeypot.log
│   ├── pcap/          traffic captures (Wireshark)
│   └── ssh_sessions/  full logs of SSH attacker sessions
└── data/
    ├── blocked_ips.json
    ├── rate_limits.json
    ├── stats.json
    └── reputation.json
```

---

## Setup

```bash
git clone https://github.com/your-username/honeypot
cd honeypot
bash install.sh
```

Edit `config.json` — add Telegram token and chat_id, then:

```bash
./venv/bin/python3 honeypot.py
```

Dashboard at `http://localhost:5000`

---

## Configuration

```json
{
  "auto_block_enabled":   false,
  "auto_block_threshold": 5,
  "alert_method":         "all",
  "pcap_enabled":         true,
  "ssh_trap_enabled":     true,
  "canary_enabled":       true,
  "abuseipdb_key":        ""
}
```

| Key | Description |
|---|---|
| `auto_block_enabled` | Block IPs automatically after N hits |
| `alert_method` | terminal / desktop / telegram / all |
| `pcap_enabled` | Capture traffic with tcpdump |
| `ssh_trap_enabled` | Run interactive fake SSH on port 2222 |
| `canary_enabled` | Monitor canary files with inotifywait |
| `abuseipdb_key` | Optional — free at abuseipdb.com (1000 checks/day) |

---

## Telegram bot commands

```
/status    is it running
/stats     today's hit count + top attackers with reputation scores
/list      blocked IPs
/block     <ip>
/unblock   <ip>
/rep       <ip>  — full reputation report
/limits    rate limits
/logs      recent alerts
/help
```

---

## CLI

```bash
python manager.py status
python manager.py block   10.0.0.5 --reason "port scan"
python manager.py unblock 10.0.0.5
python manager.py list
python manager.py limit   10.0.0.5 --rate 5
python manager.py logs    --last 50
python manager.py stats
```

---

## Run on startup

```bash
sudo cp -r . /opt/honeypot
sudo cp honeypot.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now honeypot
```

---

## How the SSH trap works

Port 2222 runs a fake SSH server (using paramiko). It accepts any username and password, logs the credentials, then drops the attacker into a fake bash shell. Every command they type is logged. The responses are pre-defined — nothing actually executes on the real system.

Session logs are saved as JSON in `logs/ssh_sessions/`.

---

## How canary tokens work

**Files:** `canary_files/` contains fake credentials, API keys, SSH keys, and database backups. If inotify-tools is installed, any file access triggers an immediate Telegram alert.

**HTTP:** The dashboard also listens for requests to paths like `/.env`, `/admin`, `/backup`. If someone finds the dashboard URL and probes for common vulnerable paths, it fires an alert.

---

## Stack

Python · socket · threading · paramiko · iptables · tcpdump · inotify-tools · Telegram Bot API · systemd
