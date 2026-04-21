# 🕳 BlackHole — Fake SSH Honeypot Server

A Python honeypot that combines a generic TCP blackhole on common attack ports with a fully functional **fake SSH server** — it accepts connections, engages bots in real authentication, lets them log in, serves a fake shell, and records every command they try to execute.

No database. No config files. Single Python script.

 

***

## What it does

### Generic blackhole (non-SSH ports)
- Listens on ports `23`, `445`, `1723`, `3389`, `8080`
- Fingerprints each connection by protocol signature and logs it
- Detects SSH, HTTP, TLS/SSL, RDP, SMB/SMBv2, PPTP, Telnet, FTP, SMTP, NTLM, VNC, Redis, Binary, and more
- Handles TCP-only port scans (no payload) separately

### Fake SSH server (ports 22, 2222–2225)
- Implements a real SSH handshake via `paramiko` — bots connect using genuine SSH clients
- Presents itself as `OpenSSH_8.9p1 Ubuntu-3ubuntu0.6`
- Accepts every password attempt for user `root`, logging each one with username, password, attempt number and timestamp
- Records which attempt number triggered successful login
- After authentication, drops the bot into a fake Ubuntu shell:
  ```
  Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-89-generic x86_64)
  Password guessed successfully on attempt #3
  Total password attempts in this session: 3
  root@ubuntu:~#
  ```
- Returns `-bash: <cmd>: command not found` for every command
- Handles `exit` / `quit` / `logout` gracefully
- Partially emulates `uname` (`-s`, `-n`, `-r`, `-v`, `-m`, `-a`, etc.) as most common bot's command
- Supports both interactive shell and SSH exec mode
- Logs every command typed by the bot in real time
- RSA host key is auto-generated on first run and saved to `~/.blackhole_ssh_host_rsa`

### Live web dashboard
- Streams all events via WebSocket in real time
- Three tabs: **Events** (all connections), **SSH Sessions** (per-session detail), **Commands** (frequency table)
- Click any SSH session to inspect its full auth attempt log and command history
- Filter by IP, protocol, keyword
- Counters: total attempts, unique IPs, SSH auth attempts, successful logins, active sessions
- Export full logs as JSON or CSV

***

## Requirements

- Python 3.8+
- `websockets` — auto-installed on first run
- `paramiko` — auto-installed on first run

***

## Quick start

```bash
git clone https://github.com/MikhailBelkin/FakeSSHServer.git
cd FakeSSHServer


# Ports below 1024 require root
sudo python3 fakesshserver.py
```

Open the dashboard: **http://localhost:8181**

Forward the monitored ports from your router or firewall to this machine.

> **Run without root** — grant low-port binding to Python instead:
> ```bash
> sudo setcap 'cap_net_bind_service=+ep' $(which python3)
> python3 fakesshserver.py
> ```

***

## Ports monitored by default

| Port | Service |
|------|---------|
| 22 | SSH (fake shell) |
| 23 | Telnet |
| 445 | SMB |
| 1723 | PPTP VPN |
| 2222–2225 | SSH alt (fake shell) |
| 3389 | RDP |
| 8080 | HTTP-Alt |

Edit `SSH_PORTS` and `GENERIC_PORTS` at the top of the script to add or remove ports.

***

## Configuration

All options are at the top of the file:

| Variable | Default | Description |
|----------|---------|-------------|
| `SSH_USER` | `root` | Username that triggers login |
| `SSH_PASSWORD` | `*` | Any password accepted for `SSH_USER` |
| `SSH_BANNER` | `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6` | SSH version string shown to clients |
| `SSH_HOSTNAME` | `ubuntu` | Hostname shown in shell prompt |
| `WEB_PORT` | `8181` | Dashboard HTTP port |
| `WS_PORT` | `8182` | WebSocket port (internal) |
| `MAX_LOG_ENTRIES` | `2000` | Max entries kept in memory |
| `MAX_SSH_SESSIONS` | `300` | Max SSH sessions kept in memory |
| `MAX_COMMANDS_PER_SESSION` | `500` | Max commands recorded per session |

***

## Dashboard

| | |
|---|---|
| URL | `http://<host>:8181` |
| WebSocket (internal) | port `8182` |
| Export JSON | `http://<host>:8181/api/export.json` |
| Export CSV | `http://<host>:8181/api/export.csv` |

The JSON export includes the full connection log, all SSH sessions with auth attempts and commands, and the global command frequency table.

> Do **not** expose port `8181` to the public internet — the dashboard has no authentication.

***

## Adding fake command responses

The `fake_command_response(cmd)` function handles known commands before falling through to "command not found". Add any command there:

```python
if base == "id":
    return "uid=0(root) gid=0(root) groups=0(root)"

if base == "whoami":
    return "root"

if base in ("cat",) and "/etc/passwd" in cmd:
    return "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"
```

***

## Install as a systemd service (Ubuntu)

**1. Copy the script**

```bash
sudo cp fakesshserver.py /opt/fakesshserver.py
```

**2. Create the unit file**

```bash
sudo nano /etc/systemd/system/blackhole.service
```

```ini
[Unit]
Description=BlackHole Fake SSH Honeypot Server
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 /opt/fakesshserver.py
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

**3. Enable and start**

```bash
sudo systemctl daemon-reload
sudo systemctl enable blackhole
sudo systemctl start blackhole
```

**4. View live logs**

```bash
sudo journalctl -u blackhole -f
```

**5. Stop / disable**

```bash
sudo systemctl stop blackhole
sudo systemctl disable blackhole
```

***

## Protocol detection (generic ports)

| Signature bytes | Detected as |
|-----------------|-------------|
| `SSH-` | SSH |
| `\x16\x03` | TLS/SSL |
| `\x03\x00` | RDP |
| `GET/POST/HEAD/PUT/DELETE` | HTTP |
| `CONNECT` | HTTP CONNECT |
| `\xff\xfb/\xfd/\xfa` | Telnet |
| `\xffSMB` | SMB |
| `\xfeSMB` | SMBv2 |
| `USER ` | FTP |
| `EHLO/HELO` | SMTP |
| `NTLMSSP` | NTLM |
| `RFB ` | VNC |
| `*1/*2/*3\r\n` | Redis |
| `MZ` | Windows PE / Binary |
| no payload | TCP handshake only |

***

## Security note

This tool runs on your own infrastructure and only accepts inbound connections initiated by remote hosts. It does not scan, probe, or interact with any external systems.

***

## License

MIT
