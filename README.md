<p align="center">
  <img src="https://raw.githubusercontent.com/raullenchai/claw/main/.github/logo.svg" width="120" alt="Claw Logo">
</p>

<h1 align="center">Claw (CLaude AnyWhere) </h1>

<p align="center">
  <strong>CL</strong>aude <strong>A</strong>ny<strong>W</strong>here — Control Claude Code from anywhere
  <br>
  <sub>📱 Phone · 💻 Laptop · 📟 Tablet · ⌚ Watch — if it has a browser, you're in control</sub>
</p>

<p align="center">
  <a href="https://github.com/raullenchai/claw/actions"><img src="https://github.com/raullenchai/claw/workflows/CI/badge.svg" alt="CI"></a>
  <a href="https://github.com/raullenchai/claw/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License"></a>
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.8+-blue.svg" alt="Python"></a>
  <a href="https://github.com/raullenchai/claw/stargazers"><img src="https://img.shields.io/github/stars/raullenchai/claw?style=social" alt="Stars"></a>
</p>

<p align="center">
  <img src="https://github.com/user-attachments/assets/814ec57a-e637-4a33-b2d6-f3bf0d5ac389" width="700" alt="Claw Screenshot">
</p>

---

## Why Claw?

Running a long Claude Code session? Need to step away from your desk? **Claw** lets you monitor and control Claude Code from any device with a browser.

- 👀 **See what Claude is doing** in real-time from any screen
- ⚡ **Send quick responses** (yes/no/continue) with one tap
- 🛑 **Interrupt with Ctrl+C** when things go sideways
- 🖥️ **Monitor everything** — sessions, windows, panes, git status, system stats

## Quick Start

```bash
python3 claw.py --share
```

Open the URL on your phone. That's it.

> No dependencies beyond Python 3 standard library.

## Features

| Feature | Description |
|---------|-------------|
| **Live Terminal** | Real-time tmux pane content with auto-scroll |
| **Quick Actions** | One-tap buttons: `yes` `no` `continue` `/compact` `Ctrl+C` |
| **Session Switching** | Switch between tmux sessions, windows, and panes |
| **Git Status** | Current branch, changed files, recent commits |
| **System Stats** | CPU, memory, load averages |
| **Process Monitor** | Claude-related processes with CPU/memory usage |
| **Mobile-First** | Designed for phones with pull-to-refresh |
| **Auto-Refresh** | Configurable refresh interval (default: 5s) |

## Installation

### Option 1: Direct Download

```bash
curl -O https://raw.githubusercontent.com/raullenchai/claw/main/claw.py
python3 claw.py
```

### Option 2: Clone Repository

```bash
git clone https://github.com/raullenchai/claw.git
cd claw
python3 claw.py
```

### Option 3: Add to PATH (recommended)

```bash
# Download
curl -o ~/.local/bin/claw https://raw.githubusercontent.com/raullenchai/claw/main/claw.py
chmod +x ~/.local/bin/claw

# Now run from anywhere
claw
```

## Usage

```
usage: claw.py [-h] [-p PORT] [-b BIND] [-r REFRESH] [-d DIR] [-s]

Claw - Remote control for Claude Code sessions

options:
  -h, --help            show this help message and exit
  -p PORT, --port PORT  Port to run on (default: 8080)
  -b BIND, --bind BIND  Address to bind to (default: 127.0.0.1)
  -r REFRESH, --refresh REFRESH
                        Refresh interval in seconds (default: 5)
  -d DIR, --dir DIR     Add a work directory to monitor
  -s, --share           Share via public URL (uses Cloudflare Tunnel)
```

### Examples

```bash
# Default (localhost only, port 8080, 5s refresh)
claw

# 🌐 Access from ANYWHERE (phone while away from home!)
claw --share

# Allow local network access (for phone/tablet on same WiFi)
claw -b 0.0.0.0

# Custom port with network access
claw -p 3000 -b 0.0.0.0

# Faster refresh
claw -r 2

# Monitor specific directory
claw -d ~/projects/myapp
```

## Accessing Claw from Your Phone

Choose the method that fits your situation:

### Method 1: Same WiFi Network (Simplest)

If your phone and computer are on the same WiFi:

```bash
claw -b 0.0.0.0
```

Then open `http://<your-computer-ip>:8080` on your phone.

**Find your computer's IP:**
```bash
# macOS
ipconfig getifaddr en0

# Linux
hostname -I | awk '{print $1}'
```

Example: `http://192.168.1.42:8080` or `http://10.0.0.15:8080`

---

### Method 2: Access from Anywhere (No Account Needed)

Perfect for checking Claude from a coffee shop, car, or anywhere outside your home:

```bash
claw --share
```

```
    ╱╱╱   Claw - CLaude AnyWhere

  ✓  Tunnel ready!
  →  Public: https://random-words.trycloudflare.com  ← Use this!

  🔐 Authentication Required
  →  Username: any (or leave blank)
  →  Password: xK7mN2pQ9rT4
```

- ✅ Works through any firewall/NAT
- ✅ No signup required
- ✅ Completely free
- ✅ Password-protected (auto-generated)
- ⚠️ URL and password change each time you restart

**First run downloads `cloudflared` (~25MB) automatically.**

---

### Method 3: Permanent URL (Cloudflare Account)

Want the same URL every time? Set up a free Cloudflare account:

**One-time setup:**

```bash
# 1. Install cloudflared (if not auto-installed)
brew install cloudflared   # macOS
# or download from https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/

# 2. Login to Cloudflare (opens browser)
cloudflared tunnel login

# 3. Create your tunnel
cloudflared tunnel create claw

# 4. Connect your domain (you need a domain on Cloudflare)
cloudflared tunnel route dns claw claw.yourdomain.com
```

**Daily use:**

```bash
# Start Claw
claw &

# Start tunnel (in another terminal or add to your startup)
cloudflared tunnel run --url http://localhost:8080 claw
```

Now `https://claw.yourdomain.com` always works!

**Requirements:**
- Free Cloudflare account ([sign up](https://dash.cloudflare.com/sign-up))
- A domain name (~$10/year, or use one you already have)

---

### Method 4: Tailscale (Best for Teams)

If you use [Tailscale](https://tailscale.com), just run:

```bash
claw -b 0.0.0.0
```

Access via your Tailscale IP: `http://100.x.x.x:8080`

---

### Quick Comparison

| Method | Setup | URL | Best For |
|--------|-------|-----|----------|
| Same WiFi | None | `192.168.x.x:8080` | Home use |
| `--share` | None | Random URL | Quick remote access |
| Cloudflare | 5 min | `claw.yourdomain.com` | Daily remote use |
| Tailscale | Install app | `100.x.x.x:8080` | Teams/multiple devices |

## API Reference

### GET Endpoints

| Endpoint | Description |
|----------|-------------|
| `/` | Main dashboard (HTML) |
| `/api/data` | All dashboard data (JSON) |
| `/api/pane?session=NAME&window=IDX&pane=IDX` | Tmux pane content |
| `/api/git?dir=NAME` | Git info for directory |

### POST Endpoints

| Endpoint | Body | Description |
|----------|------|-------------|
| `/api/send` | `{"session": "name", "window": "1", "pane": "0", "text": "yes", "enter": true}` | Send text to pane |
| `/api/control` | `{"session": "name", "window": "1", "pane": "0", "key": "C-c"}` | Send control key |

## Security

**Safe by default:**
- Binds to `localhost` only — your computer only
- `--share` requires password authentication (auto-generated)
- `--share` uses HTTPS (encrypted via Cloudflare)
- Input validation prevents command injection
- Control keys are whitelisted
- Content Security Policy headers prevent XSS

**When using `--share`:**
- A random password is generated and displayed at startup
- You must enter this password when accessing from your phone
- The password changes each time you restart Claw

**When using `-b 0.0.0.0` (local network access):**
- No authentication required (trusted network)
- Anyone on your WiFi can access Claw
- Fine for home networks, be careful on public WiFi

**For extra security on local network:**
```bash
# SSH tunnel (if you have a server)
ssh -L 8080:localhost:8080 your-server
# Then access http://localhost:8080 on your phone via SSH app
```

## Requirements

- **Python 3.8+** (standard library only, no pip install needed)
- **tmux** (for session management)
- **git** (optional, for repository info)

## Platform Support

| Platform | Basic Usage | `--share` | System Stats |
|----------|-------------|-----------|--------------|
| **macOS** (Intel/Apple Silicon) | ✅ | ✅ | ✅ |
| **Linux** (x64/ARM) | ✅ | ✅ | ✅ |
| **Windows** (x64/x86) | ✅ | ✅ | ✅ |
| **WSL** | ✅ | ✅ | ✅ |

> **Note:** Windows requires tmux via WSL or similar. Native Windows terminal monitoring is not supported.

## Troubleshooting

<details>
<summary><strong>Port already in use</strong></summary>

```bash
# Find process using port
lsof -i :8080

# Use different port
claw -p 8081
```
</details>

<details>
<summary><strong>No tmux sessions showing</strong></summary>

```bash
# Verify tmux is running
tmux list-sessions

# Start a new session
tmux new -s dev
```
</details>

<details>
<summary><strong>Can't access from phone</strong></summary>

1. Check firewall settings
2. Verify both devices are on same network
3. Try using your computer's IP directly (not `localhost`)
4. Check if VPN is interfering
</details>

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Mobile Browser                        │
│  ┌─────────────────────────────────────────────────┐    │
│  │  Stats │ Input Panel │ Terminal │ Sessions │ Git │   │
│  └─────────────────────────────────────────────────┘    │
└─────────────────────┬───────────────────────────────────┘
                      │ HTTP/JSON
┌─────────────────────▼───────────────────────────────────┐
│                    claw.py                               │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐     │
│  │ DataCollector│ │CommandSender │ │ HTTPHandler  │     │
│  └──────┬───────┘ └──────┬───────┘ └──────────────┘     │
└─────────┼────────────────┼──────────────────────────────┘
          │                │
    ┌─────▼─────┐    ┌─────▼─────┐
    │   tmux    │    │   tmux    │
    │ capture   │    │ send-keys │
    └───────────┘    └───────────┘
```

## Contributing

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md) and [Code of Conduct](CODE_OF_CONDUCT.md).

```bash
# Fork the repo, then:
git clone https://github.com/YOUR_USERNAME/claw.git
cd claw
python3 claw.py  # Test your changes
```

## License

MIT License - see [LICENSE](LICENSE) for details.

## Acknowledgments

Built for use with [Claude Code](https://claude.ai/claude-code) by Anthropic.

---

<p align="center">
  <sub>Made with 🦞 by developers who got tired of walking back to their desks</sub>
</p>
