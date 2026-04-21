#!/usr/bin/env python3
"""
Fake SSH Server v2.0
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Forward firewall ports to this server.
It logs every connection attempt and streams them live to the web dashboard.

Features:
- Generic TCP blackhole listeners with protocol fingerprinting
- Fake SSH honeypot on 22/2222/2223/2224/2225
- Accepts root / 12345
- Counts password attempts and records which one succeeded
- Provides fake shell after login
- Logs every command typed by the bot
- Returns "command not found" for every command
- Web dashboard with live SSH sessions and command stats

Usage:
python3 blackhole_server.py

Dashboard opens at: http://localhost:8181
"""

import asyncio
import json
import os
import socket
import sys
import threading
import http.server
import time
from datetime import datetime
from collections import defaultdict, deque
from typing import Set

# Auto-install dependencies
try:
    import websockets
    from websockets.server import serve as ws_serve
except ImportError:
    print("[*] Installing websockets...")
    os.system(f"{sys.executable} -m pip install websockets")
    import websockets
    from websockets.server import serve as ws_serve

try:
    import paramiko
except ImportError:
    print("[*] Installing paramiko...")
    os.system(f"{sys.executable} -m pip install paramiko")
    import paramiko

# Suppress paramiko internal "Error reading SSH protocol banner" noise.
# This is triggered by port scanners that connect and immediately disconnect.
# Our code handles it correctly — paramiko just logs it redundantly.
import logging
logging.getLogger("paramiko.transport").setLevel(logging.CRITICAL)

# ── CONFIGURATION ─────────────────────────────────────────────────────────────
SSH_PORTS = [22, 2222, 2223, 2224, 2225]
GENERIC_PORTS = [1723, 3389, 445, 8080, 23]
HONEYPOT_PORTS = SSH_PORTS + GENERIC_PORTS

SSH_USER = "root"
SSH_PASSWORD = "*" #any password will be accepted, but this is the one that "succeeds" and triggers the fake shell.
SSH_BANNER = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
SSH_HOSTNAME = "ubuntu"
SSH_SHELL_PROMPT = f"{SSH_USER}@{SSH_HOSTNAME}:~# "

WEB_PORT = 8181
WS_PORT = 8182
MAX_RECV_BYTES = 512
MAX_LOG_ENTRIES = 2000
MAX_SSH_SESSIONS = 300
MAX_COMMANDS_PER_SESSION = 500
MAX_AUTH_ATTEMPTS_PER_SESSION = 100
# ──────────────────────────────────────────────────────────────────────────────

log_entries: deque = deque(maxlen=MAX_LOG_ENTRIES)
ws_clients: Set = set()
_counter = 0
_ssh_counter = 0
async_loop = None

stats = {
    "total": 0,
    "by_port": defaultdict(int),
    "by_ip": defaultdict(int),
    "by_proto": defaultdict(int),
}

ssh_state = {
    "sessions": deque(maxlen=MAX_SSH_SESSIONS),
    "by_session": {},
    "command_freq": defaultdict(int),
    "total_auth_attempts": 0,
    "successful_logins": 0,
    "failed_logins": 0,
}

SIGS = [
    (b"SSH-", "SSH"),
    (b"\x16\x03", "TLS/SSL"),
    (b"\x03\x00", "RDP"),
    (b"GET ", "HTTP"),
    (b"POST ", "HTTP"),
    (b"HEAD ", "HTTP"),
    (b"PUT ", "HTTP"),
    (b"DELETE ", "HTTP"),
    (b"CONNECT ", "HTTP CONNECT"),
    (b"\xff\xfb", "Telnet"),
    (b"\xff\xfd", "Telnet"),
    (b"\xff\xfa", "Telnet"),
    (b"\xffSMB", "SMB"),
    (b"\xfeSMB", "SMBv2"),
    (b"USER ", "FTP"),
    (b"EHLO", "SMTP"),
    (b"HELO", "SMTP"),
    (b"NTLMSSP", "NTLM"),
    (b"RFB ", "VNC"),
    (b"*1\r\n", "Redis"),
    (b"*2\r\n", "Redis"),
    (b"*3\r\n", "Redis"),
    (b"\x4d\x5a", "Windows PE/Binary"),
]

PORT_HINTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 1723: "PPTP", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB",
    2222: "SSH", 2223: "SSH", 2224: "SSH", 2225: "SSH",
}

HOST_KEY_PATH = os.path.expanduser("~/.blackhole_ssh_host_rsa")


def ensure_host_key():
    if os.path.exists(HOST_KEY_PATH):
        return paramiko.RSAKey(filename=HOST_KEY_PATH)
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(HOST_KEY_PATH)
    try:
        os.chmod(HOST_KEY_PATH, 0o600)
    except Exception:
        pass
    return key


HOST_KEY = ensure_host_key()


def fingerprint(data: bytes, port: int):
    if not data:
        hint = PORT_HINTS.get(port, f"Port {port}")
        return hint, "TCP handshake only — no payload data sent"

    for sig, name in SIGS:
        if data.startswith(sig):
            try:
                snip = data[:300].decode("utf-8", "replace").strip()
            except Exception:
                snip = data[:32].hex(" ")
            return name, snip[:500]

    try:
        t = data[:300].decode("utf-8", "strict").strip()
        if len(t) > 2:
            return "Text", t[:500]
    except Exception:
        pass

    return "Binary", data[:32].hex(" ")


def compact_ssh_stats():
    top_ip = max(stats["by_ip"], key=stats["by_ip"].get) if stats["by_ip"] else "-"
    top_port = max(stats["by_port"], key=stats["by_port"].get) if stats["by_port"] else "-"
    top_cmds = sorted(ssh_state["command_freq"].items(), key=lambda x: (-x[1], x[0]))[:20]
    session_list = list(ssh_state["sessions"])
    return {
        "total_auth_attempts": ssh_state["total_auth_attempts"],
        "successful_logins": ssh_state["successful_logins"],
        "failed_logins": ssh_state["failed_logins"],
        "active_sessions": sum(1 for s in session_list if s.get("connected")),
        "top_cmds": [{"cmd": cmd, "count": cnt} for cmd, cnt in top_cmds],
        "recent_sessions": session_list[:50],
        "top_ip": top_ip,
        "top_ip_count": stats["by_ip"].get(top_ip, 0) if top_ip != "-" else 0,
        "top_port": top_port,
        "top_port_count": stats["by_port"].get(top_port, 0) if top_port != "-" else 0,
    }


async def broadcast(msg: dict):
    if not ws_clients:
        return
    payload = json.dumps(msg, ensure_ascii=False)
    dead = set()
    for c in list(ws_clients):
        try:
            await c.send(payload)
        except Exception:
            dead.add(c)
    ws_clients.difference_update(dead)


def broadcast_from_thread(msg: dict):
    if async_loop is None:
        return
    try:
        asyncio.run_coroutine_threadsafe(broadcast(msg), async_loop)
    except Exception:
        pass


def append_log_entry(ip, sport, port, proto, snip, data=b"", extra=None):
    global _counter
    _counter += 1
    stats["total"] += 1
    stats["by_port"][port] += 1
    stats["by_ip"][ip] += 1
    stats["by_proto"][proto] += 1

    now = datetime.now()
    entry = {
        "id": _counter,
        "ts": now.strftime("%H:%M:%S"),
        "date": now.strftime("%Y-%m-%d"),
        "ip": ip,
        "sport": sport,
        "dport": port,
        "proto": proto,
        "len": len(data) if isinstance(data, (bytes, bytearray)) else 0,
        "snip": snip,
        "hex": data[:48].hex(" ") if isinstance(data, (bytes, bytearray)) and data else "",
        "cnt": stats["by_ip"][ip],
    }
    if extra:
        entry.update(extra)
    log_entries.appendleft(entry)

    tp = max(stats["by_port"], key=stats["by_port"].get) if stats["by_port"] else "-"
    ti = max(stats["by_ip"], key=stats["by_ip"].get) if stats["by_ip"] else "-"

    print(f" [{entry['ts']}] {ip}:{sport} → :{port} [{proto}] {snip[:90]}")

    broadcast_from_thread({
        "type": "entry",
        "entry": entry,
        "stats": {
            "total": stats["total"],
            "uniq": len(stats["by_ip"]),
            "tp": tp,
            "tpc": stats["by_port"].get(tp, 0),
            "ti": ti,
            "tic": stats["by_ip"].get(ti, 0),
        },
        "ssh": compact_ssh_stats(),
    })
    return entry


def new_ssh_session(ip, sport, port):
    global _ssh_counter
    _ssh_counter += 1
    now = datetime.now()
    session = {
        "id": _ssh_counter,
        "ip": ip,
        "sport": sport,
        "port": port,
        "ts": now.strftime("%H:%M:%S"),
        "date": now.strftime("%Y-%m-%d"),
        "connected": True,
        "authenticated": False,
        "username": None,
        "success_attempt": None,
        "attempt_count": 0,
        "auth_attempts": [],
        "commands": [],
        "closed_ts": None,
    }
    ssh_state["sessions"].appendleft(session)
    ssh_state["by_session"][session["id"]] = session
    return session


class FakeSSHServer(paramiko.ServerInterface):
    def __init__(self, session):
        self.session = session
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def get_allowed_auths(self, username):
        return "password"

    def check_auth_publickey(self, username, key):
        return paramiko.AUTH_FAILED

    def check_auth_none(self, username):
        return paramiko.AUTH_FAILED

    def check_auth_password(self, username, password):
        self.session["attempt_count"] += 1
        ssh_state["total_auth_attempts"] += 1

        attempt = {
            "n": self.session["attempt_count"],
            "username": username,
            "password": password,
            "ts": datetime.now().strftime("%H:%M:%S"),
            "ok": username == SSH_USER,
        }

        if len(self.session["auth_attempts"]) < MAX_AUTH_ATTEMPTS_PER_SESSION:
            self.session["auth_attempts"].append(attempt)

        append_log_entry(
            self.session["ip"],
            self.session["sport"],
            self.session["port"],
            "SSH auth",
            f"user={username} pass={password} attempt={attempt['n']} ok={attempt['ok']}",
            b"",
            {"ssh_session_id": self.session["id"], "ssh_auth": attempt},
        )

        broadcast_from_thread({
            "type": "ssh_auth",
            "session": self.session,
            "attempt": attempt,
            "ssh": compact_ssh_stats(),
        })

        if attempt["ok"]:
            self.session["authenticated"] = True
            self.session["username"] = username
            self.session["success_attempt"] = attempt["n"]
            ssh_state["successful_logins"] += 1
            append_log_entry(
                    self.session["ip"],
                    self.session["sport"],
                    self.session["port"],
                    "SSH login",
                    f"login accepted user={username} on attempt #{attempt['n']}",
                    b"",
                    {"ssh_session_id": self.session["id"]},
            )
            broadcast_from_thread({
                    "type": "ssh_login",
                    "session": self.session,
                    "ssh": compact_ssh_stats(),
            })
            return paramiko.AUTH_SUCCESSFUL

        return paramiko.AUTH_FAILED

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_exec_request(self, channel, command):
        self.event.set()
        try:
            cmd = command.decode("utf-8", "replace") if isinstance(command, (bytes, bytearray)) else str(command)
        except Exception:
            cmd = str(command)
        log_ssh_command(self.session, cmd, exec_mode=True)
        try:
            channel.send(f"-bash: {cmd.split()[0] if cmd.strip() else '':s}: command not found\n")
        except Exception:
            pass
        return True


async def handle_conn(reader, writer, port: int):
    peer = writer.get_extra_info("peername") or ("unknown", 0)
    ip, sport = peer[0], peer[1]

    data = b""
    try:
        data = await asyncio.wait_for(reader.read(MAX_RECV_BYTES), timeout=4.0)
    except Exception:
        pass

    proto, snip = fingerprint(data, port)
    append_log_entry(ip, sport, port, proto, snip, data)

    try:
        writer.close()
        await writer.wait_closed()
    except Exception:
        pass


def log_ssh_command(session, cmd, exec_mode=False):
    cmd = (cmd or "").strip()
    if not cmd:
        return

    if len(session["commands"]) < MAX_COMMANDS_PER_SESSION:
        session["commands"].append({
            "ts": datetime.now().strftime("%H:%M:%S"),
            "cmd": cmd,
            "exec": exec_mode,
        })

    ssh_state["command_freq"][cmd] += 1

    append_log_entry(
        session["ip"],
        session["sport"],
        session["port"],
        "SSH cmd",
        f"{cmd}",
        b"",
        {"ssh_session_id": session["id"], "ssh_command": cmd, "exec_mode": exec_mode},
    )

    broadcast_from_thread({
        "type": "ssh_command",
        "session": session,
        "command": cmd,
        "exec_mode": exec_mode,
        "ssh": compact_ssh_stats(),
    })

# ── Fake command responses ─────────────────────────────────────────────────────
_UNAME = {
    "s": "Linux",
    "n": SSH_HOSTNAME,
    "r": "5.15.0-89-generic",
    "v": "#99-Ubuntu SMP PREEMPT_DYNAMIC Mon Apr  7 15:06:41 UTC 2025",
    "m": "x86_64",
    "p": "x86_64",
    "i": "x86_64",
    "o": "GNU/Linux",
}

# uname always prints fields in this fixed order regardless of flag order
_UNAME_ORDER = ["s", "n", "r", "v", "m", "p", "i", "o"]

def fake_command_response(cmd: str) -> str | None:
    """Return fake stdout for known commands, or None to fall through to 'not found'."""
    parts = cmd.split()
    if not parts:
        return None
    base = parts[0]

    if base == "uname":
        flags = set()
        for arg in parts[1:]:
            if arg.startswith("-") and arg != "--":
                for ch in arg[1:]:
                    flags.add(ch)
        if not flags or "a" in flags:
            # uname / uname -a → all fields
            return " ".join(_UNAME[k] for k in _UNAME_ORDER)
        # specific flags in canonical order
        return " ".join(_UNAME[k] for k in _UNAME_ORDER if k in flags and k in _UNAME)

    return None  # unknown command → caller prints "command not found"


def run_fake_shell(channel, session):
    motd = (
        "\r\n"
        "Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-89-generic x86_64)\r\n"
        "\r\n"
        f"Password guessed successfully on attempt #{session['success_attempt']}\r\n"
        f"Total password attempts in this session: {session['attempt_count']}\r\n"
        "\r\n"
        f"Last login: {datetime.now().strftime('%a %b %d %H:%M:%S %Y')} from {session['ip']}\r\n"
        "\r\n"
    )

    try:
        channel.send(motd.encode("utf-8", "replace"))
        channel.send(SSH_SHELL_PROMPT.encode())
    except Exception:
        return

    buf = ""
    while True:
        try:
            data = channel.recv(1024)
            if not data:
                break
        except Exception:
            break

        for b in data:
            if b in (10, 13):
                try:
                    channel.send(b"\r\n")
                except Exception:
                    return
                cmd = buf.strip()
                buf = ""
                if cmd:
                    log_ssh_command(session, cmd)
                    if cmd in ("exit", "quit", "logout"):
                        try:
                            channel.send(b"logout\r\n")
                        except Exception:
                            pass
                        return
                    response = fake_command_response(cmd)
                    if response is None:
                        base = cmd.split()[0]
                        response = f"-bash: {base}: command not found"
                    try:
                        channel.send((response + "\r\n").encode("utf-8", "replace"))
                    except Exception:
                        return
                try:
                    channel.send(SSH_SHELL_PROMPT.encode())
                except Exception:
                    return
            elif b in (8, 127):
                if buf:
                    buf = buf[:-1]
                    try:
                        channel.send(b"\b \b")
                    except Exception:
                        return
            elif b == 3:
                buf = ""
                try:
                    channel.send(b"^C\r\n")
                    channel.send(SSH_SHELL_PROMPT.encode())
                except Exception:
                    return
            elif 32 <= b <= 126:
                ch = chr(b)
                buf += ch
                try:
                    channel.send(ch.encode())
                except Exception:
                    return


def handle_ssh_client(client, addr, port):
    ip, sport = addr[0], addr[1]
    session = new_ssh_session(ip, sport, port)

    append_log_entry(
        ip, sport, port, "SSH conn",
        f"SSH session #{session['id']} started",
        b"",
        {"ssh_session_id": session["id"]},
    )

    transport = None
    chan = None

    try:
        client.settimeout(30)
        transport = paramiko.Transport(client)
        transport.local_version = SSH_BANNER
        transport.add_server_key(HOST_KEY)
        transport.set_subsystem_handler('sftp', paramiko.SFTPServer)

        server = FakeSSHServer(session)
        transport.start_server(server=server)
        chan = transport.accept(20)
        if chan is None:
            if not session["authenticated"]:
                ssh_state["failed_logins"] += 1
            return

        server.event.wait(20)
        if not session["authenticated"]:
            ssh_state["failed_logins"] += 1
            return

        run_fake_shell(chan, session)
    except Exception:
        if not session["authenticated"] and session["attempt_count"] > 0:
            ssh_state["failed_logins"] += 1
    finally:
        session["connected"] = False
        session["closed_ts"] = datetime.now().strftime("%H:%M:%S")
        broadcast_from_thread({
            "type": "ssh_session_end",
            "session": session,
            "ssh": compact_ssh_stats(),
        })
        try:
            if chan is not None:
                chan.close()
        except Exception:
            pass
        try:
            if transport is not None:
                transport.close()
        except Exception:
            pass
        try:
            client.close()
        except Exception:
            pass


def ssh_listener(port):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind(("0.0.0.0", port))
        srv.listen(100)
        print(f" [+] SSH Honeypot :{port:>5} (SSH)")
        while True:
            client, addr = srv.accept()
            t = threading.Thread(target=handle_ssh_client, args=(client, addr, port), daemon=True)
            t.start()
    except OSError as e:
        print(f" [!] SSH Port {port}: {e.strerror} (try sudo or setcap)")
    finally:
        try:
            srv.close()
        except Exception:
            pass


async def ws_handler(ws):
    ws_clients.add(ws)
    try:
        tp = max(stats["by_port"], key=stats["by_port"].get) if stats["by_port"] else "-"
        ti = max(stats["by_ip"], key=stats["by_ip"].get) if stats["by_ip"] else "-"
        await ws.send(json.dumps({
            "type": "init",
            "entries": list(log_entries)[:300],
            "stats": {
                "total": stats["total"],
                "uniq": len(stats["by_ip"]),
                "tp": tp,
                "tpc": stats["by_port"].get(tp, 0),
                "ti": ti,
                "tic": stats["by_ip"].get(ti, 0),
                "by_port": {str(k): v for k, v in stats["by_port"].items()},
                "by_proto": dict(stats["by_proto"]),
                "top_ips": dict(sorted(stats["by_ip"].items(), key=lambda x: -x[1])[:15]),
            },
            "ssh": compact_ssh_stats(),
            "ports": HONEYPOT_PORTS,
        }, ensure_ascii=False))
        await ws.wait_closed()
    finally:
        ws_clients.discard(ws)


class DashboardHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path in ("/", "/index.html"):
            body = DASHBOARD_HTML.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/api/export.json":
            body = json.dumps({
                "connections": list(log_entries),
                "ssh_sessions": list(ssh_state["sessions"]),
                "ssh_command_freq": dict(ssh_state["command_freq"]),
            }, indent=2, ensure_ascii=False).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Disposition", 'attachment; filename="blackhole_logs.json"')
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/api/export.csv":
            rows = ["id,timestamp,date,src_ip,src_port,dst_port,protocol,data_len,snippet"]
            for e in log_entries:
                s = e["snip"][:120].replace('"', "'").replace("\n", " ").replace("\r", "")
                rows.append(f'{e["id"]},{e["ts"]},{e["date"]},{e["ip"]},{e["sport"]},{e["dport"]},{e["proto"]},{e["len"]},"{s}"')
            body = "\n".join(rows).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/csv")
            self.send_header("Content-Disposition", 'attachment; filename="blackhole_logs.csv"')
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_error(404)

    def log_message(self, *args):
        pass


DASHBOARD_HTML = r'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>BlackHole — Honeypot Dashboard</title>
<style>
:root{
  --bg:#0a0d14;
  --panel:#111826;
  --panel2:#0e1522;
  --line:#24324a;
  --muted:#8da2c0;
  --text:#e8eef9;
  --green:#35d07f;
  --red:#ff5f7a;
  --amber:#f6be4f;
  --blue:#53a7ff;
  --cyan:#46d9e7;
  --violet:#8f7dff;
}
*{box-sizing:border-box}
body{
  margin:0;
  font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,Cantarell,Noto Sans,sans-serif;
  background:linear-gradient(180deg,#0a0d14 0%,#0d1320 100%);
  color:var(--text)
}
.header{
  padding:18px 22px;
  border-bottom:1px solid var(--line);
  display:flex;gap:16px;justify-content:space-between;align-items:center;flex-wrap:wrap;
  position:sticky;top:0;background:rgba(10,13,20,.92);backdrop-filter:blur(10px);z-index:10
}
.title{font-size:22px;font-weight:800;letter-spacing:.2px}
.sub{color:var(--muted);font-size:13px}
.wrap{padding:18px;display:grid;gap:18px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:14px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:16px;box-shadow:0 8px 30px rgba(0,0,0,.18)}
.card h3{margin:0 0 10px 0;color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.12em}
.big{font-size:30px;font-weight:800;line-height:1.1}
.small{font-size:12px;color:var(--muted);margin-top:8px}
.toolbar{display:flex;flex-wrap:wrap;gap:10px;align-items:center}
.input,.select,.btn{
  background:var(--panel2);color:var(--text);border:1px solid var(--line);border-radius:10px;padding:10px 12px;font-size:14px
}
.btn{cursor:pointer;text-decoration:none;display:inline-flex;align-items:center;gap:8px}
.btn:hover{border-color:#35517f;background:#132038}
.tabs{display:flex;gap:8px;flex-wrap:wrap}
.tab{cursor:pointer;padding:10px 14px;border:1px solid var(--line);background:var(--panel2);border-radius:10px;color:var(--muted);font-weight:700}
.tab.active{background:#12203a;color:#fff;border-color:#35517f}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:14px;overflow:hidden}
.tablewrap{overflow:auto;max-height:65vh}
table{width:100%;border-collapse:collapse}
th,td{padding:10px 12px;border-bottom:1px solid rgba(255,255,255,.05);vertical-align:top;text-align:left;font-size:13px}
th{position:sticky;top:0;background:#121c2d;color:#aac0df;z-index:1}
tr:hover td{background:rgba(255,255,255,.02)}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,Liberation Mono,monospace}
.badge{display:inline-block;padding:3px 8px;border-radius:999px;font-size:11px;font-weight:800;letter-spacing:.05em;border:1px solid transparent}
.p-SSH,.p-SSH\ auth,.p-SSH\ login,.p-SSH\ cmd,.p-SSH\ conn{background:rgba(83,167,255,.12);color:#8fc4ff;border-color:rgba(83,167,255,.35)}
.p-PPTP,.p-Binary{background:rgba(246,190,79,.12);color:#ffd782;border-color:rgba(246,190,79,.35)}
.p-HTTP,.p-HTTP\ CONNECT{background:rgba(70,217,231,.12);color:#92f0f8;border-color:rgba(70,217,231,.35)}
.p-TLS\/SSL,.p-RDP,.p-SMB,.p-SMBv2{background:rgba(143,125,255,.12);color:#bcb2ff;border-color:rgba(143,125,255,.35)}
.p-Text,.p-Telnet{background:rgba(53,208,127,.12);color:#8ff0b9;border-color:rgba(53,208,127,.35)}
.ok{color:var(--green);font-weight:700}
.bad{color:var(--red);font-weight:700}
.warn{color:var(--amber);font-weight:700}
.grid2{display:grid;grid-template-columns:1.2fr .8fr;gap:18px}
.list{display:grid;gap:10px;padding:14px}
.item{background:var(--panel2);border:1px solid var(--line);border-radius:12px;padding:12px}
.kv{display:grid;grid-template-columns:120px 1fr;gap:8px;font-size:13px}
.muted{color:var(--muted)}
.hidden{display:none}
.footer{padding:0 18px 18px;color:var(--muted);font-size:12px}
@media (max-width:1100px){.grid2{grid-template-columns:1fr}.tablewrap{max-height:none}}
</style>
</head>
<body>
<div class="header">
  <div>
    <div class="title">🕳 BlackHole — Honeypot Dashboard</div>
    <div class="sub">Live view of generic blackhole traffic and fake SSH bot sessions</div>
  </div>
  <div class="toolbar">
    <input id="filter" class="input" placeholder="Filter IP / proto / snippet / command">
    <select id="mode" class="select">
      <option value="all">All events</option>
      <option value="ssh">Only SSH</option>
      <option value="generic">No SSH</option>
    </select>
    <label class="sub"><input id="autoscroll" type="checkbox" checked> Auto-scroll</label>
    <a class="btn" href="/api/export.json">Export JSON</a>
    <a class="btn" href="/api/export.csv">Export CSV</a>
  </div>
</div>

<div class="wrap">
  <div class="cards">
    <div class="card"><h3>Total Attempts</h3><div id="s-total" class="big">0</div><div class="small" id="s-total-sub">waiting…</div></div>
    <div class="card"><h3>Unique IPs</h3><div id="s-uniq" class="big">0</div><div class="small">observed sources</div></div>
    <div class="card"><h3>Top Port</h3><div id="s-port" class="big">—</div><div id="s-port-sub" class="small"></div></div>
    <div class="card"><h3>Top IP</h3><div id="s-ip" class="big" style="font-size:22px">—</div><div id="s-ip-sub" class="small"></div></div>
    <div class="card"><h3>SSH Auth Attempts</h3><div id="ssh-auth-total" class="big">0</div><div class="small">all password checks</div></div>
    <div class="card"><h3>SSH Success</h3><div id="ssh-success" class="big">0</div><div id="ssh-success-sub" class="small">successful logins</div></div>
  </div>

  <div class="tabs">
    <button class="tab active" data-tab="events">Events</button>
    <button class="tab" data-tab="ssh">SSH Sessions</button>
    <button class="tab" data-tab="commands">Commands</button>
  </div>

  <div id="tab-events" class="panel tabpanel">
    <div class="tablewrap" id="events-wrap">
      <table>
        <thead>
          <tr>
            <th>Time</th>
            <th>Source IP</th>
            <th>S.Port</th>
            <th>→ Port</th>
            <th>Protocol</th>
            <th>Bytes</th>
            <th>Payload / Info</th>
          </tr>
        </thead>
        <tbody id="events-body"></tbody>
      </table>
    </div>
  </div>

  <div id="tab-ssh" class="tabpanel hidden">
    <div class="grid2">
      <div class="panel">
        <div class="tablewrap">
          <table>
            <thead>
              <tr>
                <th>ID</th>
                <th>Time</th>
                <th>IP</th>
                <th>Port</th>
                <th>Attempts</th>
                <th>Success</th>
                <th>Commands</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody id="ssh-body"></tbody>
          </table>
        </div>
      </div>
      <div class="panel">
        <div class="list" id="ssh-detail">
          <div class="item muted">Select an SSH session to inspect attempts and commands.</div>
        </div>
      </div>
    </div>
  </div>

  <div id="tab-commands" class="tabpanel hidden">
    <div class="grid2">
      <div class="panel">
        <div class="tablewrap">
          <table>
            <thead>
              <tr><th>Command</th><th>Count</th></tr>
            </thead>
            <tbody id="cmd-body"></tbody>
          </table>
        </div>
      </div>
      <div class="panel">
        <div class="list">
          <div class="item">
            <div style="font-weight:800;margin-bottom:8px">SSH honeypot behavior</div>
            <div class="muted">Accepted credentials: <span class="mono">root / 12345</span></div>
            <div class="muted">After success, the bot receives a fake shell prompt.</div>
            <div class="muted">Any command returns <span class="mono">command not found</span>.</div>
            <div class="muted">All attempted commands are recorded live.</div>
          </div>
        </div>
      </div>
    </div>
  </div>
</div>

<div class="footer">
  <span id="footer-status">Server: ws pending</span>
  <span style="margin-left:18px" id="footer-buffer">Buffer: 0 / 2000</span>
</div>

<script>
const events = [];
let sshSessions = [];
let sshCommandFreq = [];
let selectedSshId = null;

const $ = s => document.querySelector(s);
const esc = s => String(s ?? '').replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));

function badge(proto){
  return `<span class="badge p-${esc(proto).replace(/[^a-zA-Z0-9 _/:-]/g,'')}">${esc(proto)}</span>`;
}

function renderStats(stats, ssh){
  $('#s-total').textContent = stats?.total ?? 0;
  $('#s-total-sub').textContent = `${events.length} buffered entries`;
  $('#s-uniq').textContent = stats?.uniq ?? 0;
  $('#s-port').textContent = stats?.tp ?? '—';
  $('#s-port-sub').textContent = stats?.tp && stats?.tp !== '-' ? `${stats.tpc} hits` : 'no data yet';
  $('#s-ip').textContent = ssh?.top_ip ?? stats?.ti ?? '—';
  $('#s-ip-sub').textContent = (ssh?.top_ip && ssh.top_ip !== '-') ? `${ssh.top_ip_count} hits` : ((stats?.ti && stats?.ti !== '-') ? `${stats.tic} hits` : 'no data yet');
  $('#ssh-auth-total').textContent = ssh?.total_auth_attempts ?? 0;
  $('#ssh-success').textContent = ssh?.successful_logins ?? 0;
  $('#ssh-success-sub').textContent = `${ssh?.active_sessions ?? 0} active session(s)`;
  $('#footer-buffer').textContent = `Buffer: ${events.length} / 2000`;
}

function filteredEvents(){
  const q = $('#filter').value.trim().toLowerCase();
  const mode = $('#mode').value;
  return events.filter(e => {
    const isSsh = String(e.proto || '').startsWith('SSH');
    if (mode === 'ssh' && !isSsh) return false;
    if (mode === 'generic' && isSsh) return false;
    if (!q) return true;
    const blob = [e.ts, e.ip, e.sport, e.dport, e.proto, e.snip, e.hex].join(' ').toLowerCase();
    return blob.includes(q);
  });
}

function renderEvents(){
  const body = $('#events-body');
  const rows = filteredEvents().slice(0, 500).map(e => `
    <tr>
      <td class="mono">${esc(e.ts)}</td>
      <td class="mono">${esc(e.ip)}</td>
      <td class="mono">${esc(e.sport)}</td>
      <td class="mono">${esc(e.dport)}</td>
      <td>${badge(e.proto)}</td>
      <td class="mono">${esc(e.len)}</td>
      <td class="mono">${esc(e.snip)}</td>
    </tr>`).join('');
  body.innerHTML = rows || `<tr><td colspan="7" class="muted">Waiting for connections. Forward ports to this server to start capturing.</td></tr>`;
  if ($('#autoscroll').checked) $('#events-wrap').scrollTop = 0;
}

function renderSshSessions(){
  const body = $('#ssh-body');
  const q = $('#filter').value.trim().toLowerCase();
  const rows = sshSessions.filter(s => {
    if (!q) return true;
    return JSON.stringify(s).toLowerCase().includes(q);
  }).map(s => {
    const status = s.connected ? '<span class="ok">active</span>' : '<span class="muted">closed</span>';
    const success = s.success_attempt ? `<span class="ok">#${s.success_attempt}</span>` : '<span class="bad">no</span>';
    return `
      <tr data-ssh-id="${s.id}" style="cursor:pointer">
        <td class="mono">${s.id}</td>
        <td class="mono">${esc(s.ts)}</td>
        <td class="mono">${esc(s.ip)}</td>
        <td class="mono">${esc(s.port)}</td>
        <td class="mono">${esc(s.attempt_count || 0)}</td>
        <td>${success}</td>
        <td class="mono">${esc((s.commands || []).length)}</td>
        <td>${status}</td>
      </tr>`;
  }).join('');
  body.innerHTML = rows || `<tr><td colspan="8" class="muted">No SSH sessions yet.</td></tr>`;
  body.querySelectorAll('tr[data-ssh-id]').forEach(tr => {
    tr.onclick = () => {
      selectedSshId = Number(tr.dataset.sshId);
      renderSshDetail();
    };
  });
}

function renderSshDetail(){
  const box = $('#ssh-detail');
  const s = sshSessions.find(x => x.id === selectedSshId);
  if (!s){
    box.innerHTML = `<div class="item muted">Select an SSH session to inspect attempts and commands.</div>`;
    return;
  }
  const attempts = (s.auth_attempts || []).map(a => `
    <div class="item">
      <div class="kv">
        <div class="muted">Attempt</div><div class="mono">#${a.n}</div>
        <div class="muted">Username</div><div class="mono">${esc(a.username)}</div>
        <div class="muted">Password</div><div class="mono">${esc(a.password)}</div>
        <div class="muted">Time</div><div class="mono">${esc(a.ts)}</div>
        <div class="muted">Result</div><div>${a.ok ? '<span class="ok">accepted</span>' : '<span class="bad">rejected</span>'}</div>
      </div>
    </div>`).join('') || `<div class="item muted">No password attempts recorded.</div>`;
  const commands = (s.commands || []).map(c => `
    <div class="item">
      <div class="kv">
        <div class="muted">Time</div><div class="mono">${esc(c.ts)}</div>
        <div class="muted">Mode</div><div class="mono">${c.exec ? 'exec' : 'shell'}</div>
        <div class="muted">Command</div><div class="mono">${esc(c.cmd)}</div>
      </div>
    </div>`).join('') || `<div class="item muted">No commands recorded.</div>`;
  box.innerHTML = `
    <div class="item">
      <div style="font-weight:800;margin-bottom:8px">SSH session #${s.id}</div>
      <div class="kv">
        <div class="muted">IP</div><div class="mono">${esc(s.ip)}</div>
        <div class="muted">Port</div><div class="mono">${esc(s.port)}</div>
        <div class="muted">Attempts</div><div class="mono">${esc(s.attempt_count || 0)}</div>
        <div class="muted">Success on</div><div>${s.success_attempt ? `<span class="ok">attempt #${s.success_attempt}</span>` : '<span class="bad">none</span>'}</div>
        <div class="muted">Status</div><div>${s.connected ? '<span class="ok">active</span>' : '<span class="muted">closed</span>'}</div>
      </div>
    </div>
    <div class="item"><div style="font-weight:800;margin-bottom:8px">Password attempts</div></div>
    ${attempts}
    <div class="item"><div style="font-weight:800;margin-bottom:8px">Commands used by bot</div></div>
    ${commands}
  `;
}

function renderCommands(ssh){
  const body = $('#cmd-body');
  const q = $('#filter').value.trim().toLowerCase();
  const list = (ssh?.top_cmds || []).filter(x => !q || x.cmd.toLowerCase().includes(q));
  body.innerHTML = list.map(x => `<tr><td class="mono">${esc(x.cmd)}</td><td class="mono">${esc(x.count)}</td></tr>`).join('') || `<tr><td colspan="2" class="muted">No commands recorded yet.</td></tr>`;
}

function renderAll(stats, ssh){
  renderStats(stats, ssh);
  renderEvents();
  renderSshSessions();
  renderSshDetail();
  renderCommands(ssh);
}

function mergeSession(session){
  const idx = sshSessions.findIndex(s => s.id === session.id);
  if (idx >= 0) sshSessions[idx] = JSON.parse(JSON.stringify(session));
  else sshSessions.unshift(JSON.parse(JSON.stringify(session)));
}

document.querySelectorAll('.tab').forEach(btn => {
  btn.onclick = () => {
    document.querySelectorAll('.tab').forEach(x => x.classList.remove('active'));
    document.querySelectorAll('.tabpanel').forEach(x => x.classList.add('hidden'));
    btn.classList.add('active');
    $('#tab-' + btn.dataset.tab).classList.remove('hidden');
  };
});

['input','change'].forEach(ev => {
  $('#filter').addEventListener(ev, () => renderAll(window.__stats || {}, window.__ssh || {}));
  $('#mode').addEventListener(ev, () => renderAll(window.__stats || {}, window.__ssh || {}));
});

(function connect(){
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  const ws = new WebSocket(`${proto}://${location.hostname}:8182`);
  $('#footer-status').textContent = `Server: connecting to ${location.hostname}:8182`;

  ws.onopen = () => { $('#footer-status').textContent = `Server: ${location.hostname}:8182 connected`; };
  ws.onclose = () => {
    $('#footer-status').textContent = 'Server: disconnected, retrying…';
    setTimeout(connect, 1500);
  };
  ws.onerror = () => { $('#footer-status').textContent = 'Server: websocket error'; };

  ws.onmessage = ev => {
    const msg = JSON.parse(ev.data);
    if (msg.type === 'init') {
      events.length = 0;
      (msg.entries || []).forEach(e => events.push(e));
      sshSessions = (msg.ssh?.recent_sessions || []).map(x => JSON.parse(JSON.stringify(x)));
      window.__stats = msg.stats || {};
      window.__ssh = msg.ssh || {};
      renderAll(window.__stats, window.__ssh);
      return;
    }
    if (msg.entry) {
      events.unshift(msg.entry);
      if (events.length > 2000) events.length = 2000;
    }
    if (msg.session) mergeSession(msg.session);
    if (msg.stats) window.__stats = msg.stats;
    if (msg.ssh) window.__ssh = msg.ssh;
    renderAll(window.__stats || {}, window.__ssh || {});
  };
})();
</script>
</body>
</html>
'''


async def main():
    global async_loop
    async_loop = asyncio.get_running_loop()

    print("\n" + "═" * 68)
    print(" 🕳 BlackHole Honeypot Server v2.0")
    print("═" * 68)

    servers = []
    for port in GENERIC_PORTS:
        try:
            srv = await asyncio.start_server(
                lambda r, w, p=port: handle_conn(r, w, p),
                "0.0.0.0", port
            )
            servers.append(srv)
            print(f" [+] Honeypot     :{port:>5} ({PORT_HINTS.get(port, 'custom')})")
        except OSError as e:
            print(f" [!] Port {port}: {e.strerror} (try sudo or setcap)")

    for port in SSH_PORTS:
        t = threading.Thread(target=ssh_listener, args=(port,), daemon=True)
        t.start()

    ws_server = await ws_serve(ws_handler, "0.0.0.0", WS_PORT)
    print(f"\n [+] WebSocket    :{WS_PORT}")

    httpd = http.server.ThreadingHTTPServer(("0.0.0.0", WEB_PORT), DashboardHandler)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    print(f" [+] Dashboard    http://0.0.0.0:{WEB_PORT}")
    print("═" * 68)
    print(f" Monitoring {len(GENERIC_PORTS) + len(SSH_PORTS)} port(s). Waiting for connections...\n")

    try:
        await asyncio.Future()
    except KeyboardInterrupt:
        print("\n[*] Shutting down...")
    finally:
        ws_server.close()
        for s in servers:
            s.close()
        httpd.shutdown()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except PermissionError:
        print("[!] Need root privileges for low ports. Try: sudo python3 blackhole_server.py")