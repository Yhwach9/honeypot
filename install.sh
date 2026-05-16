#!/usr/bin/env bash
# install.sh — honeypot setup
set -e
RED='\033[91m'; GREEN='\033[92m'; YELLOW='\033[93m'; CYAN='\033[96m'; BOLD='\033[1m'; NC='\033[0m'
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
step(){ echo -e "${YELLOW}[$1]${NC} $2"; }
ok()  { echo -e "  ${GREEN}✓${NC} $1"; }
warn(){ echo -e "  ${YELLOW}⚠${NC}  $1"; }

echo -e "${CYAN}${BOLD}\n  🍯  Honeypot Installer\n${NC}"

step "1/5" "Checking Python 3..."
command -v python3 &>/dev/null || { echo "install python3 first"; exit 1; }
ok "$(python3 --version)"

step "2/5" "Installing system packages..."
sudo apt-get update -qq
sudo apt-get install -y -qq python3-venv python3-pip libnotify-bin iptables tcpdump inotify-tools
ok "system packages ready"

step "3/5" "Creating virtual environment..."
python3 -m venv "$DIR/venv"
mkdir -p "$DIR/logs/pcap" "$DIR/logs/ssh_sessions" "$DIR/data"
ok "venv + directories created"

step "4/5" "Installing Python packages..."
"$DIR/venv/bin/pip" install --quiet paramiko
ok "paramiko installed (SSH trap)"

step "5/5" "Setting port capabilities..."
PY="$DIR/venv/bin/python3"
if sudo setcap 'cap_net_bind_service=+ep' "$PY" 2>/dev/null; then
  ok "can bind ports < 1024 without sudo"
else
  warn "may need sudo for ports < 1024"
fi

echo -e "\n${GREEN}${BOLD}✅  Done!${NC}"
echo ""
echo -e "  1. Edit ${CYAN}config.json${NC} — add your Telegram token + chat_id"
echo "     (optional) add your AbuseIPDB key for threat intel"
echo ""
echo -e "  2. Run: ${CYAN}./venv/bin/python3 honeypot.py${NC}"
echo -e "  3. Dashboard: ${CYAN}http://localhost:5000${NC}"
echo ""
echo -e "  ${YELLOW}Telegram setup:${NC}"
echo "    BotFather → /newbot → copy token"
echo "    Visit: https://api.telegram.org/bot<TOKEN>/getUpdates"
echo "    Copy chat_id → paste in config.json"
echo ""
echo -e "  ${YELLOW}AbuseIPDB (optional, free):${NC}"
echo "    abuseipdb.com → register → API key → paste in config.json"
echo ""
