# sgcClaudeCodeRemote

> Access **Claude Code** (or any console application) from any device's web browser.

`sgcClaudeCodeRemote` is a single-binary Windows server, written in Delphi, that wraps Claude Code in a Windows **ConPTY** (Pseudo Console) and exposes it as a real terminal in your browser via **WebSockets** and **xterm.js**. Phones, tablets, laptops — anything with a browser can drive Claude Code on your host machine, from your LAN or across the internet.

```
┌──────────────────────────────────────────────────────────────┐
│  Host (Windows 10 1809+ / 11)                                │
│                                                              │
│   ┌──────────────┐         ┌──────────────────────────────┐  │
│   │  claude.exe  │◄───────►│  sgcClaudeCodeRemote.exe     │  │
│   │  (child)     │ ConPTY  │   - ConPTY wrapper           │  │
│   └──────────────┘ stdin/  │   - WebSocket + HTTP server  │  │
│                    stdout  │   - Auth + firewall + TLS    │  │
│                    + VT    └──────────────┬───────────────┘  │
└──────────────────────────────────────────┬┘                  │
                                           │ ws/wss :8765      │
┌──────────────────────────────────────────▼───────────────────┐
│  Any device — browser                                        │
│   - xterm.js terminal renderer                               │
│   - WebSocket client, fit/resize, login screen               │
└──────────────────────────────────────────────────────────────┘
```

---

## Features

- **Real terminal in the browser** — full ANSI/VT support, colors, cursor moves, TUI apps. Renders Claude Code's interactive UI exactly as it appears locally.
- **Multi-session** — run several named Claude sessions concurrently and switch between them from the UI.
- **Scheduled sessions** — queue up sessions to start at a specific time, or chain a session to start when another finishes.
- **Authentication** — password-protected with SHA-256 session tokens, configurable timeout, and brute-force protection (5 fails per IP → 5-minute block).
- **TLS 1.3 (WSS)** — bring your own certificate, or terminate TLS upstream.
- **IP firewall** — whitelist or blacklist individual IPs and CIDR ranges (`192.168.1.0/24`, `10.0.0.0/8`, …). Localhost is always allowed.
- **Connection limits & heartbeat** — cap concurrent clients, evict idle/dead connections.
- **Configurable from INI, CLI, or both** — CLI flags override the INI file.
- **Static asset bundling** — `index.html` and JS assets are embedded in the `.exe` (`html.RES`); the binary is self-contained.
- **Works with anything, not just Claude** — `cmd.exe`, `powershell.exe`, `bash.exe`, `wsl`, …

---

## Requirements

| | |
|---|---|
| OS | Windows 10 1809+ or Windows 11 (ConPTY API) |
| Build | Delphi 10.3+ with [sgcWebSockets](https://www.esegece.com/websockets) installed |
| Runtime | Claude Code on `PATH` (run `where claude` to verify), Git for Windows |
| TLS (optional) | `libssl-3.dll` and `libcrypto-3.dll` (shipped alongside the binary) |

---

## Quick start

### 1. Run

```cmd
sgcClaudeCodeRemote.exe --password mySecret
```

### 2. Open the browser

```
http://localhost:8765/
```

Log in with the password you set, and you have Claude Code in the browser.

To reach the host from another device on your LAN, use `http://<host-ip>:8765/`.

---

## Configuration

Settings are read from `sgcClaudeCodeRemote.ini` next to the executable, then overridden by command-line flags. Use `--config <file>` to point at a different INI file.

### INI file

```ini
[Server]
Port=8765
Command=claude
Password=changeme
Cols=120
Rows=40
MaxConnections=10
AuthTimeout=15
NoAuth=0

[TLS]
Enabled=0
CertFile=cert.pem
KeyFile=key.pem
Password=
Port=0

[Firewall]
; If any Allow= lines are present, only those IPs/ranges are allowed.
; Localhost (127.0.0.1) is always allowed.
Allow=192.168.1.0/24
Allow=10.0.0.0/8
Deny=203.0.113.0/24
```

### Command-line flags

```
sgcClaudeCodeRemote.exe [options]

  --port <port>          WebSocket port (default: 8765)
  --cols <cols>          Terminal columns (default: 120)
  --rows <rows>          Terminal rows (default: 40)
  --command <cmd>        Command to run (default: claude)
  --password <pwd>       Auth password
  --no-auth              Disable authentication
  --timeout <sec>        Auth timeout in seconds (default: 15)
  --max-conn <n>         Max concurrent connections (default: 10)
  --allow-ip <cidr>      Allow IP or range (repeatable)
  --deny-ip <cidr>       Deny IP or range (repeatable)

  --tls                  Enable TLS 1.3
  --tls-cert <file>      Certificate (.pem)
  --tls-key <file>       Private key (.pem)
  --tls-password <pwd>   Private key password
  --tls-port <port>      TLS port (default: same as --port)

  --config <file>        Path to INI file
  --help                 Show this help
```

---

## How it works

1. **ConPTY wrapper** (`uConPTY.pas`) calls `CreatePseudoConsole` and spawns `claude` (or any command) as a child process. A read thread pumps the ConPTY output pipe; a watch thread waits for the child to exit.
2. **Server** (`uServer.pas`) is a `TsgcWebSocketHTTPServer` that:
   - Serves the embedded `index.html` (xterm.js client) over HTTP.
   - Streams raw terminal bytes to authenticated clients as **binary** WebSocket frames.
   - Receives JSON **text** frames from the client (`auth`, `input`, `resize`, session management).
3. **Browser** runs xterm.js with the `fit` and `web-links` addons, renders the VT stream, and sends keystrokes back over the same WebSocket.

### Authentication handshake

```
Client                            Server
  │                                 │
  ├── WebSocket connect ────────────►
  │◄── {"type":"auth_required"} ────┤
  ├── {"type":"auth",
  │    "user":"admin",
  │    "password":"…"} ─────────────►
  │                                 │  validate + brute-force check
  │◄── {"type":"auth_result",       │
  │    "success":true,
  │    "token":"sha256…"} ──────────┤
  │◄── {"type":"init",              │
  │    "cols":120,"rows":40} ───────┤
  │◄── [binary terminal bytes] ─────┤
  ├── {"type":"input",…} ───────────►
```

### WebSocket protocol

**Server → Client**

| Frame | Payload |
|---|---|
| Binary | Raw UTF-8 + VT escape sequences from the ConPTY |
| Text | JSON: `auth_required`, `auth_result`, `init`, session/schedule events |

**Client → Server**

```json
{"type":"auth","user":"admin","password":"…"}
{"type":"input","data":"keystrokes"}
{"type":"resize","cols":150,"rows":50}
```

---

## Remote access (over the internet)

Pick whichever fits your threat model:

- **SSH tunnel** — simplest and safest for personal use:
  ```bash
  ssh -L 8765:localhost:8765 user@your-host
  # then open http://localhost:8765 locally
  ```
- **TLS / WSS** — enable `--tls` with a cert (Let's Encrypt, mkcert, …) and expose the port directly. Combine with the IP firewall.
- **Mesh VPN** — Tailscale, ZeroTier, WireGuard. Bind to the mesh interface IP and skip public exposure entirely.

> **Don't expose the service to the public internet without a password and TLS.** It's a remote shell to your machine.

---

## Project layout

```
sgcClaudeCodeRemote/
├── sgcClaudeCodeRemote.dpr     Program entry point, CLI/INI parsing
├── uServer.pas                 WebSocket + HTTP server, auth, sessions, schedules
├── uConPTY.pas                 ConPTY wrapper (CreatePseudoConsole + threads)
├── www/index.html              xterm.js client (also embedded in html.RES)
├── html.rc / html.RES          Resource bundling for the embedded UI
├── sgcClaudeCodeRemote.ini     Default config
├── libssl-3.dll, libcrypto-3.dll   OpenSSL 3 (for WSS)
└── sgcClaudeCodeRemote.exe     Compiled binary
```

---

## Building

1. Open `sgcClaudeCodeRemote.dproj` in Delphi 10.3 or newer.
2. Make sure [sgcWebSockets](https://www.esegece.com/websockets) is installed and visible to the IDE.
3. Build the **Release** configuration. The output is a single `sgcClaudeCodeRemote.exe`; the UI is compiled in via `html.RES`.

---

## Troubleshooting

| Problem | Fix |
|---|---|
| `claude` not found | Ensure it's on `PATH`. Run `where claude` in CMD. |
| ConPTY fails to start | Check Windows version with `winver` (need 1809+). |
| Browser shows nothing | If you removed `html.RES`, make sure `www/` sits next to the `.exe`. |
| WebSocket won't connect | Firewall, port already in use, or the IP firewall denied your address. |
| Garbled characters | Use a recent xterm.js (5.x+); default UI is fine. |
| Locked out by brute-force protection | Wait 5 minutes, or restart the server. |

---

## License & credits

Built with [sgcWebSockets](https://www.esegece.com/websockets) by [eSeGeCe](https://www.esegece.com). Terminal rendering by [xterm.js](https://xtermjs.org/).

Copyright © 2026 eSeGeCe — info@esegece.com
