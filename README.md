<p align="center">
  <img src="https://raw.githubusercontent.com/raullenchai/claw/main/.github/logo.svg" width="120" alt="Claw Logo">
</p>

<h1 align="center">Claw</h1>

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
# Run Claw
python3 claw.py

# Access from your phone
# http://<your-computer-ip>:8080
```

That's it. No dependencies beyond Python 3 standard library.

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
usage: claw.py [-h] [-p PORT] [-r REFRESH] [-d DIR]

Claw - Remote control for Claude Code sessions

options:
  -h, --help            show this help message and exit
  -p PORT, --port PORT  Port to run on (default: 8080)
  -r REFRESH, --refresh REFRESH
                        Refresh interval in seconds (default: 5)
  -d DIR, --dir DIR     Add a work directory to monitor
```

### Examples

```bash
# Default (port 8080, 5s refresh)
claw

# Custom port
claw -p 3000

# Faster refresh
claw -r 2

# Monitor specific directory
claw -d ~/projects/myapp
```

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

## Network Access

Claw binds to `0.0.0.0` so it's accessible from any device on your network.

**Finding your IP:**

```bash
# macOS
ipconfig getifaddr en0

# Linux
hostname -I | awk '{print $1}'
```

**Tailscale users:** Access via your Tailscale IP (e.g., `http://100.x.x.x:8080/`)

## Security

> ⚠️ **Warning:** Claw has no authentication. Only use on trusted networks.

- Commands sent via `/api/send` execute directly in tmux
- Consider firewall rules if exposing beyond local network
- For remote access, use Tailscale or SSH tunneling

```bash
# SSH tunnel example
ssh -L 8080:localhost:8080 your-server
```

## Requirements

- **Python 3.8+** (standard library only, no pip install needed)
- **tmux** (for session management)
- **git** (optional, for repository info)

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
