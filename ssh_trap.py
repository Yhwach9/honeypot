#!/usr/bin/env python3
# fake SSH server - accepts any login and logs everything the attacker types
# they think they got a real shell, we're just recording them

import socket, threading, logging, json, time
from datetime import datetime
from pathlib import Path

try:
    import paramiko
except ImportError:
    paramiko = None

BASE_DIR  = Path(__file__).resolve().parent
LOG_DIR   = BASE_DIR / "logs" / "ssh_sessions"
KEY_FILE  = BASE_DIR / "data" / "ssh_host.key"
LOG_DIR.mkdir(parents=True, exist_ok=True)

# fake outputs for common commands attackers run
FAKE_RESPONSES = {
    "whoami":        "root",
    "id":            "uid=0(root) gid=0(root) groups=0(root)",
    "pwd":           "/root",
    "hostname":      "ubuntu-prod-01",
    "uname -a":      "Linux ubuntu-prod-01 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux",
    "ls":            "snap  .bashrc  .bash_history  .ssh  backups  scripts",
    "ls -la":        "total 52\ndrwx------ 6 root root 4096 Jan 15 09:23 .\ndrwxr-xr-x 19 root root 4096 Jan 10 14:31 ..\n-rw------- 1 root root  892 Jan 15 09:21 .bash_history\n-rw-r--r-- 1 root root 3526 Jan 10 14:31 .bashrc\ndrwx------ 2 root root 4096 Jan 15 09:22 .ssh\ndrwxr-xr-x 3 root root 4096 Jan 12 11:05 backups\ndrwxr-xr-x 2 root root 4096 Jan 13 08:44 scripts",
    "cat .bash_history": "ls -la\ncd /etc\ncat /etc/shadow\ncd /root\nls\ncat .ssh/id_rsa",
    "cat /etc/passwd":   "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nubuntu:x:1000:1000:ubuntu:/home/ubuntu:/bin/bash",
    "ifconfig":      "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n        inet 10.0.0.50  netmask 255.255.255.0  broadcast 10.0.0.255\n        ether 02:42:ac:11:00:02  txqueuelen 0",
    "ip a":          "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP>\n    inet 10.0.0.50/24 brd 10.0.0.255 scope global eth0",
    "ps aux":        "USER  PID %CPU %MEM COMMAND\nroot    1  0.0  0.1 /sbin/init\nroot  423  0.0  0.1 /usr/sbin/sshd -D\nroot 1337  0.0  0.0 -bash",
    "netstat -an":   "Proto Local Address    Foreign Address  State\ntcp   0.0.0.0:22      0.0.0.0:*        LISTEN\ntcp   0.0.0.0:80      0.0.0.0:*        LISTEN\ntcp   0.0.0.0:3306    0.0.0.0:*        LISTEN",
    "df -h":         "Filesystem      Size  Used Avail Use% Mounted on\n/dev/sda1        50G   12G   36G  25% /\ntmpfs           2.0G     0  2.0G   0% /dev/shm",
    "history":       "    1  ls -la\n    2  cat /etc/passwd\n    3  cd .ssh\n    4  cat id_rsa",
    "env":           "HOME=/root\nSHELL=/bin/bash\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\nLANG=en_US.UTF-8",
    "crontab -l":    "# m h dom mon dow command\n*/5 * * * * /root/scripts/backup.sh\n0 2 * * * /usr/bin/apt-get update -qq",
}


def log_session(ip, username, password, commands):
    ts    = datetime.now().strftime("%Y%m%d_%H%M%S")
    fname = LOG_DIR / f"session_{ip}_{ts}.json"
    data  = {
        "ip":       ip,
        "time":     datetime.now().isoformat(),
        "username": username,
        "password": password,
        "commands": commands
    }
    with open(fname, "w") as f:
        json.dump(data, f, indent=2)


def get_response(cmd):
    cmd = cmd.strip()
    if cmd in FAKE_RESPONSES:
        return FAKE_RESPONSES[cmd]
    # handle some patterns
    if cmd.startswith("cd "):
        return ""
    if cmd.startswith("cat "):
        return f"cat: {cmd[4:]}: No such file or directory"
    if cmd.startswith("wget ") or cmd.startswith("curl "):
        return "curl: (6) Could not resolve host"
    if cmd == "" or cmd == "clear":
        return ""
    return f"{cmd.split()[0]}: command not found"


class FakeSSHServer(paramiko.ServerInterface):
    def __init__(self):
        self.username = ""
        self.password = ""

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED

    def check_auth_password(self, username, password):
        self.username = username
        self.password = password
        return paramiko.AUTH_SUCCESSFUL  # accept everything, we're a trap

    def check_auth_publickey(self, username, key):
        self.username = username
        return paramiko.AUTH_SUCCESSFUL

    def get_allowed_auths(self, username):
        return "password,publickey"

    def check_channel_shell_request(self, channel):
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True


def handle_ssh_client(conn, addr, config, logger):
    if paramiko is None:
        conn.close()
        return

    ip = addr[0]

    try:
        # load or generate host key
        if KEY_FILE.exists():
            host_key = paramiko.RSAKey(filename=str(KEY_FILE))
        else:
            host_key = paramiko.RSAKey.generate(2048)
            host_key.write_private_key_file(str(KEY_FILE))

        transport = paramiko.Transport(conn)
        transport.add_server_key(host_key)

        fake_server = FakeSSHServer()
        transport.start_server(server=fake_server)

        chan = transport.accept(20)
        if chan is None:
            return

        logger.warning(f"ssh login: {ip} user={fake_server.username} pass={fake_server.password}")

        tg = config.get("telegram", {})
        from honeypot import tg_send
        tg_send(tg.get("token",""), tg.get("chat_id",""),
            f"🔐 <b>SSH Login Attempt!</b>\n"
            f"🔴 IP: <code>{ip}</code>\n"
            f"👤 User: <code>{fake_server.username}</code>\n"
            f"🔑 Pass: <code>{fake_server.password}</code>"
        )

        # fake shell interaction
        chan.send(f"Welcome to Ubuntu 22.04.3 LTS\r\nLast login: Mon Jan 15 08:12:11 2024 from 192.168.1.1\r\n")
        commands = []

        while True:
            chan.send("root@ubuntu-prod-01:~# ")
            cmd = ""
            while True:
                try:
                    data = chan.recv(1)
                    if not data:
                        break
                    ch = data.decode("utf-8", errors="replace")
                    if ch in ("\r", "\n"):
                        chan.send("\r\n")
                        break
                    elif ch == "\x7f":  # backspace
                        if cmd:
                            cmd = cmd[:-1]
                            chan.send("\b \b")
                    elif ch == "\x03":  # ctrl+c
                        cmd = ""
                        chan.send("^C\r\n")
                        break
                    else:
                        cmd += ch
                        chan.send(ch)
                except Exception:
                    break

            if not cmd and not data:
                break

            cmd = cmd.strip()
            if cmd in ("exit", "logout", "quit"):
                chan.send("logout\r\n")
                break

            commands.append({"cmd": cmd, "time": datetime.now().isoformat()})
            logger.warning(f"ssh cmd [{ip}]: {cmd}")

            response = get_response(cmd)
            if response:
                chan.send(response.replace("\n", "\r\n") + "\r\n")

        log_session(ip, fake_server.username, fake_server.password, commands)

    except Exception as e:
        logger.debug(f"ssh session {ip}: {e}")
    finally:
        try: conn.close()
        except: pass


def start_ssh_trap(config, logger, stop_event):
    if paramiko is None:
        logger.warning("paramiko not installed - SSH trap disabled. run: pip install paramiko")
        return

    try:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", 2222))  # use 2222 to avoid conflict if real SSH is on 22
        srv.listen(10)
        srv.settimeout(1.0)
        logger.info("  ssh trap on port 2222 (interactive fake shell)")
    except OSError as e:
        logger.error(f"  ssh trap failed: {e}")
        return

    while not stop_event.is_set():
        try:
            conn, addr = srv.accept()
            threading.Thread(
                target=handle_ssh_client,
                args=(conn, addr, config, logger),
                daemon=True
            ).start()
        except socket.timeout:
            continue
        except Exception as e:
            if not stop_event.is_set():
                logger.error(f"ssh trap: {e}")
    srv.close()
