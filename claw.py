#!/usr/bin/env python3
"""
Claw - CLaude AnyWhere
Remote control for Claude Code sessions from your phone.
https://github.com/raullenchai/claw
"""

import http.server
import subprocess
import socketserver
import os
import json
import html
import re
import argparse
from datetime import datetime
from urllib.parse import urlparse, parse_qs
from pathlib import Path


class DashboardConfig:
    """Configuration for the dashboard."""
    def __init__(self):
        self.port = 8080
        self.refresh_interval = 5  # seconds
        self.work_dirs = self._detect_work_dirs()
        self.tmux_pane_lines = 50  # lines to capture from tmux
        self.show_system_stats = True

    def _detect_work_dirs(self):
        """Auto-detect work directories with git repos."""
        home = Path.home()
        candidates = [
            home / 'work' / 'src',
            home / 'projects',
            home / 'code',
            Path.cwd(),
        ]
        dirs = {}
        for path in candidates:
            if path.exists() and path.is_dir():
                # Check for subdirectories with .git
                for subdir in path.iterdir():
                    if subdir.is_dir() and (subdir / '.git').exists():
                        dirs[subdir.name] = str(subdir)
                # Also check if the path itself is a git repo
                if (path / '.git').exists():
                    dirs[path.name] = str(path)
        return dirs if dirs else {'default': str(home / 'work' / 'src')}


class CommandSender:
    """Sends commands to tmux sessions."""

    @staticmethod
    def _build_target(session_name, window=None, pane=None):
        """Build tmux target string (session:window.pane)."""
        target = session_name
        if window is not None:
            target = f"{session_name}:{window}"
            if pane is not None:
                target = f"{session_name}:{window}.{pane}"
        return target

    @staticmethod
    def send_to_tmux(session_name, text, press_enter=True, window=None, pane=None):
        """Send text to a tmux pane. Optionally specify window and pane index."""
        try:
            target = CommandSender._build_target(session_name, window, pane)
            # Send the text
            cmd = ['tmux', 'send-keys', '-t', target, text]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)

            if result.returncode != 0:
                return {'success': False, 'error': result.stderr}

            # Optionally press Enter
            if press_enter:
                subprocess.run(['tmux', 'send-keys', '-t', target, 'Enter'],
                             capture_output=True, timeout=5)

            return {'success': True}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    @staticmethod
    def send_control_key(session_name, key, window=None, pane=None):
        """Send a control key (like Ctrl+C) to a tmux pane."""
        try:
            target = CommandSender._build_target(session_name, window, pane)
            subprocess.run(['tmux', 'send-keys', '-t', target, key],
                         capture_output=True, text=True, timeout=5)
            return {'success': True}
        except Exception as e:
            return {'success': False, 'error': str(e)}


class DataCollector:
    """Collects system and project data."""

    @staticmethod
    def run_cmd(cmd, cwd=None, timeout=5):
        """Run a command and return output safely."""
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=cwd,
                timeout=timeout,
                env={**os.environ, 'LANG': 'en_US.UTF-8'}
            )
            return result.stdout.strip() if result.returncode == 0 else result.stderr.strip()
        except subprocess.TimeoutExpired:
            return '[timeout]'
        except Exception as e:
            return f'[error: {e}]'

    @staticmethod
    def get_tmux_sessions():
        """Get detailed tmux session info including windows."""
        sessions = []
        raw = DataCollector.run_cmd(['tmux', 'list-sessions', '-F',
            '#{session_name}|#{session_windows}|#{session_attached}|#{session_created}'])

        if not raw or raw.startswith('['):
            return sessions

        for line in raw.split('\n'):
            if '|' in line:
                parts = line.split('|')
                if len(parts) >= 4:
                    session_name = parts[0]
                    windows = DataCollector.get_tmux_windows(session_name)
                    sessions.append({
                        'name': session_name,
                        'windows': windows,
                        'window_count': len(windows),
                        'attached': parts[2] == '1',
                        'created': datetime.fromtimestamp(int(parts[3])).strftime('%H:%M') if parts[3].isdigit() else 'N/A'
                    })
        return sessions

    @staticmethod
    def get_tmux_windows(session_name):
        """Get windows for a tmux session, including panes."""
        windows = []
        raw = DataCollector.run_cmd(['tmux', 'list-windows', '-t', session_name, '-F',
            '#{window_index}|#{window_name}|#{window_active}|#{window_panes}'])

        if not raw or raw.startswith('['):
            return windows

        for line in raw.split('\n'):
            if '|' in line:
                parts = line.split('|')
                if len(parts) >= 4:
                    window_index = parts[0]
                    panes = DataCollector.get_tmux_panes(session_name, window_index)
                    windows.append({
                        'index': window_index,
                        'name': parts[1],
                        'active': parts[2] == '1',
                        'pane_count': int(parts[3]) if parts[3].isdigit() else 1,
                        'panes': panes
                    })
        return windows

    @staticmethod
    def get_tmux_panes(session_name, window_index):
        """Get panes for a tmux window."""
        panes = []
        raw = DataCollector.run_cmd(['tmux', 'list-panes', '-t', f'{session_name}:{window_index}', '-F',
            '#{pane_index}|#{pane_current_command}|#{pane_active}'])

        if not raw or raw.startswith('['):
            return panes

        for line in raw.split('\n'):
            if '|' in line:
                parts = line.split('|')
                if len(parts) >= 3:
                    panes.append({
                        'index': parts[0],
                        'command': parts[1],
                        'active': parts[2] == '1'
                    })
        return panes

    @staticmethod
    def get_tmux_pane_content(session_name, lines=50, window=None, pane=None):
        """Capture content from a tmux pane. Optionally specify window and pane index."""
        target = session_name
        if window is not None:
            target = f"{session_name}:{window}"
            if pane is not None:
                target = f"{session_name}:{window}.{pane}"
        content = DataCollector.run_cmd([
            'tmux', 'capture-pane', '-t', target, '-p', '-S', f'-{lines}'
        ], timeout=3)
        return content if content and not content.startswith('[') else ''

    @staticmethod
    def get_git_info(work_dir):
        """Get comprehensive git information."""
        if not work_dir or not Path(work_dir).exists():
            return {'status': 'N/A', 'branch': 'N/A', 'log': [], 'changes': 0}

        branch = DataCollector.run_cmd(['git', 'branch', '--show-current'], cwd=work_dir)
        status = DataCollector.run_cmd(['git', 'status', '--short'], cwd=work_dir)
        log_raw = DataCollector.run_cmd(['git', 'log', '--oneline', '-10'], cwd=work_dir)

        # Count changes
        changes = len([l for l in status.split('\n') if l.strip()]) if status and not status.startswith('[') else 0

        # Parse log
        logs = []
        if log_raw and not log_raw.startswith('['):
            for line in log_raw.split('\n')[:10]:
                if line.strip():
                    parts = line.split(' ', 1)
                    logs.append({
                        'hash': parts[0][:7] if parts else '',
                        'message': parts[1] if len(parts) > 1 else ''
                    })

        return {
            'branch': branch if branch and not branch.startswith('[') else 'N/A',
            'status': status if status else 'Clean',
            'log': logs,
            'changes': changes
        }

    @staticmethod
    def get_claude_processes():
        """Get Claude-related process information."""
        processes = []

        # Find claude processes
        ps_output = DataCollector.run_cmd([
            'ps', 'aux'
        ])

        if ps_output and not ps_output.startswith('['):
            for line in ps_output.split('\n'):
                if 'claude' in line.lower() and 'grep' not in line:
                    parts = line.split(None, 10)
                    if len(parts) >= 11:
                        processes.append({
                            'pid': parts[1],
                            'cpu': parts[2],
                            'mem': parts[3],
                            'cmd': parts[10][:60] + '...' if len(parts[10]) > 60 else parts[10]
                        })

        return processes

    @staticmethod
    def get_system_stats():
        """Get system resource usage."""
        stats = {'cpu': 'N/A', 'memory': 'N/A', 'load': 'N/A'}

        # CPU and memory via top (macOS compatible)
        top_output = DataCollector.run_cmd(['top', '-l', '1', '-n', '0', '-s', '0'], timeout=10)

        if top_output and not top_output.startswith('['):
            for line in top_output.split('\n'):
                if 'CPU usage' in line:
                    match = re.search(r'(\d+\.?\d*)% user.*?(\d+\.?\d*)% sys', line)
                    if match:
                        stats['cpu'] = f"{float(match.group(1)) + float(match.group(2)):.1f}%"
                elif 'PhysMem' in line:
                    match = re.search(r'(\d+[GM]) used', line)
                    if match:
                        stats['memory'] = match.group(1)
                elif 'Load Avg' in line:
                    match = re.search(r'Load Avg: ([\d.]+)', line)
                    if match:
                        stats['load'] = match.group(1)

        return stats

    @staticmethod
    def get_all_data(config):
        """Collect all dashboard data."""
        # Find active project from tmux or default
        sessions = DataCollector.get_tmux_sessions()
        active_session = sessions[0]['name'] if sessions else None

        # Determine work directory
        work_dir = None
        if active_session and active_session in config.work_dirs:
            work_dir = config.work_dirs[active_session]
        elif config.work_dirs:
            work_dir = list(config.work_dirs.values())[0]

        return {
            'timestamp': datetime.now().isoformat(),
            'tmux': {
                'sessions': sessions,
                'active_content': DataCollector.get_tmux_pane_content(active_session, config.tmux_pane_lines) if active_session else ''
            },
            'git': DataCollector.get_git_info(work_dir),
            'claude': DataCollector.get_claude_processes(),
            'system': DataCollector.get_system_stats() if config.show_system_stats else {},
            'work_dir': work_dir,
            'work_dirs': config.work_dirs
        }


class DashboardHandler(http.server.SimpleHTTPRequestHandler):
    """HTTP request handler for the dashboard."""

    config = DashboardConfig()

    def log_message(self, format, *args):
        pass  # Silent logging

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        if path == '/api/data':
            self._send_json(DataCollector.get_all_data(self.config))
        elif path == '/api/pane':
            session = query.get('session', [None])[0]
            window = query.get('window', [None])[0]
            pane = query.get('pane', [None])[0]
            if session:
                content = DataCollector.get_tmux_pane_content(session, self.config.tmux_pane_lines, window, pane)
                self._send_json({'content': content})
            else:
                self._send_json({'error': 'No session specified'})
        elif path == '/api/git':
            work_dir = query.get('dir', [None])[0]
            if work_dir and work_dir in self.config.work_dirs:
                self._send_json(DataCollector.get_git_info(self.config.work_dirs[work_dir]))
            else:
                self._send_json({'error': 'Invalid directory'})
        else:
            self._send_html()

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path

        # Read request body
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode('utf-8')

        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            self._send_json({'error': 'Invalid JSON'})
            return

        if path == '/api/send':
            session = data.get('session')
            window = data.get('window')
            pane = data.get('pane')
            text = data.get('text', '')
            press_enter = data.get('enter', True)

            if not session:
                # Get first available session
                sessions = DataCollector.get_tmux_sessions()
                if sessions:
                    session = sessions[0]['name']
                else:
                    self._send_json({'error': 'No tmux sessions available'})
                    return

            result = CommandSender.send_to_tmux(session, text, press_enter, window, pane)
            self._send_json(result)

        elif path == '/api/control':
            session = data.get('session')
            window = data.get('window')
            pane = data.get('pane')
            key = data.get('key', '')

            if not session:
                sessions = DataCollector.get_tmux_sessions()
                if sessions:
                    session = sessions[0]['name']
                else:
                    self._send_json({'error': 'No tmux sessions available'})
                    return

            result = CommandSender.send_control_key(session, key, window, pane)
            self._send_json(result)

        else:
            self._send_json({'error': 'Unknown endpoint'})

    def _send_json(self, data):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(data, default=str).encode())

    def _send_html(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html; charset=utf-8')
        self.end_headers()
        self.wfile.write(self._generate_html().encode())

    def _generate_html(self):
        return f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=no">
    <meta name="apple-mobile-web-app-capable" content="yes">
    <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
    <title>Claw</title>
    <style>
        :root {{
            --bg-primary: #0d1117;
            --bg-secondary: #161b22;
            --bg-tertiary: #21262d;
            --border: #30363d;
            --text-primary: #e6edf3;
            --text-secondary: #8b949e;
            --text-muted: #6e7681;
            --accent-blue: #58a6ff;
            --accent-green: #3fb950;
            --accent-yellow: #d29922;
            --accent-red: #f85149;
            --accent-purple: #a371f7;
        }}

        * {{
            box-sizing: border-box;
            -webkit-tap-highlight-color: transparent;
        }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            margin: 0;
            padding: 0;
            font-size: 14px;
            line-height: 1.5;
            overflow-x: hidden;
        }}

        .header {{
            background: var(--bg-secondary);
            padding: 12px 16px;
            position: sticky;
            top: 0;
            z-index: 100;
            border-bottom: 1px solid var(--border);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}

        .header h1 {{
            margin: 0;
            font-size: 18px;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 8px;
        }}

        .header-actions {{
            display: flex;
            gap: 8px;
            align-items: center;
        }}

        .status-dot {{
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: var(--accent-green);
            animation: pulse 2s infinite;
        }}

        .status-dot.warning {{ background: var(--accent-yellow); }}
        .status-dot.error {{ background: var(--accent-red); }}

        @keyframes pulse {{
            0%, 100% {{ opacity: 1; }}
            50% {{ opacity: 0.5; }}
        }}

        .refresh-btn {{
            background: var(--bg-tertiary);
            border: 1px solid var(--border);
            color: var(--text-secondary);
            padding: 6px 12px;
            border-radius: 6px;
            font-size: 12px;
            cursor: pointer;
            display: flex;
            align-items: center;
            gap: 4px;
        }}

        .refresh-btn:active {{
            background: var(--border);
        }}

        .refresh-btn.loading {{
            opacity: 0.7;
        }}

        .container {{
            padding: 12px;
            max-width: 100%;
        }}

        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 8px;
            margin-bottom: 12px;
        }}

        .stat-card {{
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 12px 8px;
            text-align: center;
        }}

        .stat-value {{
            font-size: 20px;
            font-weight: 600;
            color: var(--accent-blue);
        }}

        .stat-value.green {{ color: var(--accent-green); }}
        .stat-value.yellow {{ color: var(--accent-yellow); }}
        .stat-value.red {{ color: var(--accent-red); }}

        .stat-label {{
            font-size: 10px;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-top: 2px;
        }}

        .card {{
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 12px;
            margin-bottom: 12px;
            overflow: hidden;
        }}

        .card-header {{
            padding: 12px 16px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            cursor: pointer;
            user-select: none;
        }}

        .card-header:active {{
            background: var(--bg-tertiary);
        }}

        .card-title {{
            font-size: 14px;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 8px;
        }}

        .card-badge {{
            background: var(--bg-tertiary);
            color: var(--text-secondary);
            padding: 2px 8px;
            border-radius: 10px;
            font-size: 11px;
            font-weight: 500;
        }}

        .card-chevron {{
            color: var(--text-muted);
            transition: transform 0.2s;
        }}

        .card.collapsed .card-chevron {{
            transform: rotate(-90deg);
        }}

        .card.collapsed .card-content {{
            display: none;
        }}

        .card-content {{
            padding: 0 16px 16px;
        }}

        .terminal {{
            background: var(--bg-primary);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 12px;
            font-family: 'SF Mono', 'Menlo', 'Monaco', monospace;
            font-size: 11px;
            line-height: 1.4;
            overflow-x: auto;
            white-space: pre-wrap;
            word-break: break-all;
            max-height: 300px;
            overflow-y: auto;
            color: var(--text-secondary);
        }}

        .terminal::-webkit-scrollbar {{
            width: 6px;
            height: 6px;
        }}

        .terminal::-webkit-scrollbar-thumb {{
            background: var(--border);
            border-radius: 3px;
        }}

        .session-list {{
            display: flex;
            flex-direction: column;
            gap: 8px;
        }}

        .session-item {{
            background: var(--bg-tertiary);
            border-radius: 8px;
            padding: 10px 12px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            cursor: pointer;
        }}

        .session-item:active {{
            background: var(--border);
        }}

        .session-name {{
            font-weight: 500;
            display: flex;
            align-items: center;
            gap: 6px;
        }}

        .session-meta {{
            font-size: 11px;
            color: var(--text-muted);
        }}

        .session-group {{
            margin-bottom: 8px;
        }}

        .session-group.active > .session-item {{
            border-left: 3px solid var(--accent-green);
        }}

        .windows-list {{
            display: flex;
            flex-wrap: wrap;
            gap: 4px;
            margin-top: 6px;
            margin-left: 12px;
        }}

        .window-item {{
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 4px;
            padding: 4px 8px;
            font-size: 11px;
            cursor: pointer;
            display: flex;
            align-items: center;
            gap: 4px;
        }}

        .window-item:hover {{
            background: var(--bg-tertiary);
        }}

        .window-item.active {{
            border-color: var(--accent-blue);
            background: rgba(88, 166, 255, 0.1);
        }}

        .window-item.current {{
            border-color: var(--accent-green);
        }}

        .window-index {{
            color: var(--accent-purple);
            font-weight: 600;
            font-family: monospace;
        }}

        .window-name {{
            color: var(--text-secondary);
        }}

        .window-active-badge {{
            color: var(--accent-green);
            font-weight: bold;
        }}

        .window-group {{
            margin-bottom: 4px;
        }}

        .window-group.active > .window-item {{
            border-color: var(--accent-blue);
            background: rgba(88, 166, 255, 0.1);
        }}

        .pane-count {{
            color: var(--text-muted);
            font-size: 10px;
            margin-left: 4px;
        }}

        .panes-list {{
            display: flex;
            flex-wrap: wrap;
            gap: 4px;
            margin-top: 4px;
            margin-left: 16px;
        }}

        .pane-item {{
            background: var(--bg-primary);
            border: 1px solid var(--border);
            border-radius: 4px;
            padding: 3px 6px;
            font-size: 10px;
            cursor: pointer;
            display: flex;
            align-items: center;
            gap: 4px;
        }}

        .pane-item:hover {{
            background: var(--bg-tertiary);
        }}

        .pane-item.active {{
            border-color: var(--accent-yellow);
            background: rgba(210, 153, 34, 0.1);
        }}

        .pane-item.current {{
            border-color: var(--accent-green);
        }}

        .pane-index {{
            color: var(--accent-yellow);
            font-weight: 600;
            font-family: monospace;
        }}

        .pane-cmd {{
            color: var(--text-muted);
            max-width: 60px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }}

        .pane-active-badge {{
            color: var(--accent-green);
            font-weight: bold;
        }}

        .commit-list {{
            display: flex;
            flex-direction: column;
            gap: 6px;
        }}

        .commit-item {{
            display: flex;
            gap: 8px;
            align-items: flex-start;
            font-size: 12px;
        }}

        .commit-hash {{
            font-family: 'SF Mono', monospace;
            color: var(--accent-purple);
            font-size: 11px;
            flex-shrink: 0;
        }}

        .commit-msg {{
            color: var(--text-secondary);
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }}

        .git-changes {{
            display: flex;
            flex-wrap: wrap;
            gap: 6px;
            margin-bottom: 12px;
        }}

        .git-file {{
            background: var(--bg-tertiary);
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-family: monospace;
        }}

        .git-file.modified {{ border-left: 2px solid var(--accent-yellow); }}
        .git-file.added {{ border-left: 2px solid var(--accent-green); }}
        .git-file.deleted {{ border-left: 2px solid var(--accent-red); }}

        .process-list {{
            display: flex;
            flex-direction: column;
            gap: 6px;
        }}

        .process-item {{
            background: var(--bg-tertiary);
            border-radius: 6px;
            padding: 8px 10px;
            font-size: 11px;
        }}

        .process-cmd {{
            font-family: monospace;
            color: var(--text-secondary);
            word-break: break-all;
        }}

        .process-stats {{
            display: flex;
            gap: 12px;
            margin-top: 4px;
            color: var(--text-muted);
        }}

        .empty-state {{
            text-align: center;
            padding: 20px;
            color: var(--text-muted);
        }}

        .branch-badge {{
            background: var(--accent-purple);
            color: white;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 500;
        }}

        .footer {{
            text-align: center;
            padding: 16px;
            color: var(--text-muted);
            font-size: 11px;
        }}

        .footer .time {{
            color: var(--text-secondary);
        }}

        .pull-indicator {{
            position: fixed;
            top: 60px;
            left: 50%;
            transform: translateX(-50%);
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            padding: 8px 16px;
            border-radius: 20px;
            font-size: 12px;
            opacity: 0;
            transition: opacity 0.2s;
            z-index: 200;
        }}

        .pull-indicator.visible {{
            opacity: 1;
        }}

        /* Input Panel Styles */
        .input-panel {{
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 12px;
            margin-bottom: 12px;
            padding: 12px;
        }}

        .input-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }}

        .input-title {{
            font-size: 14px;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 8px;
        }}

        .session-select {{
            background: var(--bg-tertiary);
            border: 1px solid var(--border);
            color: var(--text-primary);
            padding: 4px 8px;
            border-radius: 6px;
            font-size: 12px;
        }}

        .input-area {{
            width: 100%;
            min-height: 60px;
            max-height: 150px;
            background: var(--bg-primary);
            border: 1px solid var(--border);
            border-radius: 8px;
            color: var(--text-primary);
            font-family: inherit;
            font-size: 14px;
            padding: 10px;
            resize: vertical;
            margin-bottom: 10px;
        }}

        .input-area:focus {{
            outline: none;
            border-color: var(--accent-blue);
        }}

        .input-area::placeholder {{
            color: var(--text-muted);
        }}

        .quick-actions {{
            display: flex;
            gap: 6px;
            flex-wrap: wrap;
            margin-bottom: 10px;
        }}

        .quick-btn {{
            background: var(--bg-tertiary);
            border: 1px solid var(--border);
            color: var(--text-secondary);
            padding: 6px 12px;
            border-radius: 6px;
            font-size: 12px;
            cursor: pointer;
            transition: all 0.15s;
        }}

        .quick-btn:active {{
            background: var(--border);
            transform: scale(0.98);
        }}

        .quick-btn.danger {{
            border-color: var(--accent-red);
            color: var(--accent-red);
        }}

        .quick-btn.primary {{
            background: var(--accent-blue);
            border-color: var(--accent-blue);
            color: white;
        }}

        .input-actions {{
            display: flex;
            gap: 8px;
        }}

        .send-btn {{
            flex: 1;
            background: var(--accent-green);
            border: none;
            color: white;
            padding: 10px 16px;
            border-radius: 8px;
            font-size: 14px;
            font-weight: 500;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 6px;
        }}

        .send-btn:active {{
            opacity: 0.9;
            transform: scale(0.98);
        }}

        .send-btn:disabled {{
            opacity: 0.5;
            cursor: not-allowed;
        }}

        .send-btn.sending {{
            background: var(--accent-yellow);
        }}

        .toast {{
            position: fixed;
            bottom: 20px;
            left: 50%;
            transform: translateX(-50%);
            background: var(--bg-secondary);
            border: 1px solid var(--accent-green);
            color: var(--accent-green);
            padding: 10px 20px;
            border-radius: 8px;
            font-size: 13px;
            opacity: 0;
            transition: opacity 0.3s;
            z-index: 300;
        }}

        .toast.error {{
            border-color: var(--accent-red);
            color: var(--accent-red);
        }}

        .toast.visible {{
            opacity: 1;
        }}

        @media (max-width: 400px) {{
            .stats-grid {{
                grid-template-columns: repeat(2, 1fr);
            }}
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>
            <svg width="28" height="28" viewBox="0 0 100 100" style="margin-right: 4px;">
                <!-- Claw mark - three scratches -->
                <path d="M 20 15 Q 25 50 35 90" stroke="#a371f7" stroke-width="10" stroke-linecap="round" fill="none"/>
                <path d="M 45 10 Q 50 50 50 95" stroke="#a371f7" stroke-width="10" stroke-linecap="round" fill="none"/>
                <path d="M 70 15 Q 65 50 55 90" stroke="#a371f7" stroke-width="10" stroke-linecap="round" fill="none"/>
                <!-- Shine effects -->
                <path d="M 22 20 Q 26 40 33 60" stroke="#c9b1fa" stroke-width="3" stroke-linecap="round" fill="none"/>
                <path d="M 47 15 Q 50 40 50 65" stroke="#c9b1fa" stroke-width="3" stroke-linecap="round" fill="none"/>
                <path d="M 68 20 Q 64 40 57 60" stroke="#c9b1fa" stroke-width="3" stroke-linecap="round" fill="none"/>
            </svg>
            <span class="status-dot" id="statusDot"></span>
            Claw
        </h1>
        <div class="header-actions">
            <button class="refresh-btn" id="refreshBtn" onclick="refreshData()">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M23 4v6h-6M1 20v-6h6"/>
                    <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/>
                </svg>
                <span id="refreshText">Refresh</span>
            </button>
        </div>
    </div>

    <div class="pull-indicator" id="pullIndicator">Pull to refresh</div>

    <div class="container">
        <div class="stats-grid" id="statsGrid">
            <div class="stat-card">
                <div class="stat-value" id="statClaude">-</div>
                <div class="stat-label">Claude</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="statSessions">-</div>
                <div class="stat-label">Sessions</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="statChanges">-</div>
                <div class="stat-label">Changes</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="statCpu">-</div>
                <div class="stat-label">CPU</div>
            </div>
        </div>

        <div class="input-panel" id="inputPanel">
            <div class="input-header">
                <span class="input-title">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>
                    </svg>
                    Send to Claude
                </span>
                <select class="session-select" id="targetSession">
                    <option value="">Session</option>
                </select>
                <select class="session-select" id="targetWindow" style="margin-left: 4px;">
                    <option value="">Win</option>
                </select>
                <select class="session-select" id="targetPane" style="margin-left: 4px;">
                    <option value="">Pane</option>
                </select>
            </div>
            <textarea class="input-area" id="inputText" placeholder="Type your message to Claude Code..." rows="2"></textarea>
            <div class="quick-actions">
                <button class="quick-btn" onclick="sendQuick('yes')">yes</button>
                <button class="quick-btn" onclick="sendQuick('y')">y</button>
                <button class="quick-btn" onclick="sendQuick('no')">no</button>
                <button class="quick-btn" onclick="sendQuick('continue')">continue</button>
                <button class="quick-btn" onclick="sendQuick('/compact')">compact</button>
                <button class="quick-btn danger" onclick="sendControl('C-c')">Ctrl+C</button>
            </div>
            <div class="input-actions">
                <button class="send-btn" id="sendBtn" onclick="sendMessage()">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/>
                    </svg>
                    Send
                </button>
            </div>
        </div>

        <div class="toast" id="toast"></div>

        <div class="card" id="terminalCard">
            <div class="card-header" onclick="toggleCard('terminalCard')">
                <span class="card-title">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/>
                    </svg>
                    Live Terminal
                    <span class="card-badge" id="terminalSession">-</span>
                </span>
                <span class="card-chevron">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <polyline points="6 9 12 15 18 9"/>
                    </svg>
                </span>
            </div>
            <div class="card-content">
                <div class="terminal" id="terminalContent">Loading...</div>
            </div>
        </div>

        <div class="card" id="sessionsCard">
            <div class="card-header" onclick="toggleCard('sessionsCard')">
                <span class="card-title">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <rect x="2" y="3" width="20" height="14" rx="2" ry="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/>
                    </svg>
                    Tmux Sessions
                </span>
                <span class="card-chevron">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <polyline points="6 9 12 15 18 9"/>
                    </svg>
                </span>
            </div>
            <div class="card-content">
                <div class="session-list" id="sessionList">Loading...</div>
            </div>
        </div>

        <div class="card" id="gitCard">
            <div class="card-header" onclick="toggleCard('gitCard')">
                <span class="card-title">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <circle cx="12" cy="12" r="4"/><line x1="1.05" y1="12" x2="7" y2="12"/><line x1="17.01" y1="12" x2="22.96" y2="12"/>
                    </svg>
                    Git Status
                    <span class="branch-badge" id="gitBranch">-</span>
                </span>
                <span class="card-chevron">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <polyline points="6 9 12 15 18 9"/>
                    </svg>
                </span>
            </div>
            <div class="card-content">
                <div class="git-changes" id="gitChanges"></div>
                <div class="commit-list" id="commitList">Loading...</div>
            </div>
        </div>

        <div class="card collapsed" id="processCard">
            <div class="card-header" onclick="toggleCard('processCard')">
                <span class="card-title">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M18 3a3 3 0 0 0-3 3v12a3 3 0 0 0 3 3 3 3 0 0 0 3-3 3 3 0 0 0-3-3H6a3 3 0 0 0-3 3 3 3 0 0 0 3 3 3 3 0 0 0 3-3V6a3 3 0 0 0-3-3 3 3 0 0 0-3 3 3 3 0 0 0 3 3h12a3 3 0 0 0 3-3 3 3 0 0 0-3-3z"/>
                    </svg>
                    Claude Processes
                </span>
                <span class="card-chevron">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <polyline points="6 9 12 15 18 9"/>
                    </svg>
                </span>
            </div>
            <div class="card-content">
                <div class="process-list" id="processList">Loading...</div>
            </div>
        </div>

        <div class="footer">
            <span class="time" id="lastUpdate">-</span>
            <br>Auto-refresh: <span id="refreshInterval">{self.config.refresh_interval}</span>s
        </div>
    </div>

    <script>
        let refreshInterval = {self.config.refresh_interval} * 1000;
        let refreshTimer = null;
        let activeSession = null;
        let activeWindow = null;
        let activePane = null;
        let sessionsData = [];
        let touchStartY = 0;
        let isPulling = false;

        // Toast notification
        function showToast(message, isError = false) {{
            const toast = document.getElementById('toast');
            toast.textContent = message;
            toast.className = 'toast visible' + (isError ? ' error' : '');
            setTimeout(() => toast.classList.remove('visible'), 2000);
        }}

        // Get selected session
        function getTargetSession() {{
            const select = document.getElementById('targetSession');
            return select.value || activeSession;
        }}

        // Get selected window
        function getTargetWindow() {{
            const select = document.getElementById('targetWindow');
            return select.value || null;
        }}

        // Get selected pane
        function getTargetPane() {{
            const select = document.getElementById('targetPane');
            return select.value || null;
        }}

        // Send message to Claude
        async function sendMessage() {{
            const input = document.getElementById('inputText');
            const btn = document.getElementById('sendBtn');
            const text = input.value.trim();

            if (!text) {{
                showToast('Please enter a message', true);
                return;
            }}

            btn.disabled = true;
            btn.classList.add('sending');
            btn.innerHTML = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/></svg> Sending...';

            try {{
                const response = await fetch('/api/send', {{
                    method: 'POST',
                    headers: {{ 'Content-Type': 'application/json' }},
                    body: JSON.stringify({{
                        session: getTargetSession(),
                        window: getTargetWindow(),
                        pane: getTargetPane(),
                        text: text,
                        enter: true
                    }})
                }});

                const result = await response.json();

                if (result.success) {{
                    showToast('Message sent!');
                    input.value = '';
                    // Refresh terminal view after short delay
                    setTimeout(refreshData, 500);
                }} else {{
                    showToast('Failed: ' + (result.error || 'Unknown error'), true);
                }}
            }} catch (e) {{
                showToast('Error: ' + e.message, true);
            }} finally {{
                btn.disabled = false;
                btn.classList.remove('sending');
                btn.innerHTML = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/></svg> Send';
            }}
        }}

        // Send quick message
        async function sendQuick(text) {{
            try {{
                const response = await fetch('/api/send', {{
                    method: 'POST',
                    headers: {{ 'Content-Type': 'application/json' }},
                    body: JSON.stringify({{
                        session: getTargetSession(),
                        window: getTargetWindow(),
                        pane: getTargetPane(),
                        text: text,
                        enter: true
                    }})
                }});

                const result = await response.json();
                if (result.success) {{
                    showToast('Sent: ' + text);
                    setTimeout(refreshData, 500);
                }} else {{
                    showToast('Failed to send', true);
                }}
            }} catch (e) {{
                showToast('Error: ' + e.message, true);
            }}
        }}

        // Send control key (like Ctrl+C)
        async function sendControl(key) {{
            try {{
                const response = await fetch('/api/control', {{
                    method: 'POST',
                    headers: {{ 'Content-Type': 'application/json' }},
                    body: JSON.stringify({{
                        session: getTargetSession(),
                        window: getTargetWindow(),
                        pane: getTargetPane(),
                        key: key
                    }})
                }});

                const result = await response.json();
                if (result.success) {{
                    showToast('Sent: ' + key);
                    setTimeout(refreshData, 500);
                }} else {{
                    showToast('Failed to send', true);
                }}
            }} catch (e) {{
                showToast('Error: ' + e.message, true);
            }}
        }}

        // Handle Enter key in input and dropdown changes
        document.addEventListener('DOMContentLoaded', () => {{
            const input = document.getElementById('inputText');
            input.addEventListener('keydown', (e) => {{
                if (e.key === 'Enter' && !e.shiftKey) {{
                    e.preventDefault();
                    sendMessage();
                }}
            }});

            // Update windows dropdown when session changes
            document.getElementById('targetSession').addEventListener('change', () => {{
                updateWindowsDropdown();
                updatePanesDropdown();
            }});

            // Update panes dropdown when window changes
            document.getElementById('targetWindow').addEventListener('change', () => {{
                updatePanesDropdown();
            }});
        }});

        // Toggle card collapse
        function toggleCard(cardId) {{
            document.getElementById(cardId).classList.toggle('collapsed');
        }}

        // Escape HTML
        function escapeHtml(text) {{
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }}

        // Format terminal content with ANSI handling
        function formatTerminal(content) {{
            if (!content) return '<span class="empty-state">No output</span>';
            // Strip ANSI codes for now
            return escapeHtml(content.replace(/\\x1b\\[[0-9;]*m/g, ''));
        }}

        // Render sessions with windows and panes
        function renderSessions(sessions) {{
            if (!sessions || sessions.length === 0) {{
                return '<div class="empty-state">No tmux sessions</div>';
            }}
            return sessions.map((s, i) => {{
                const isActiveSession = s.name === activeSession;
                const windowsHtml = s.windows && s.windows.length > 0 ? s.windows.map(w => {{
                    const isActiveWindow = isActiveSession && w.index === activeWindow;
                    const panesHtml = w.panes && w.panes.length > 0 ? w.panes.map(p => `
                        <div class="pane-item ${{isActiveWindow && p.index === activePane ? 'active' : ''}} ${{p.active ? 'current' : ''}}"
                             onclick="event.stopPropagation(); selectPane('${{s.name}}', '${{w.index}}', '${{p.index}}')">
                            <span class="pane-index">${{p.index}}</span>
                            <span class="pane-cmd">${{escapeHtml(p.command)}}</span>
                            ${{p.active ? '<span class="pane-active-badge">*</span>' : ''}}
                        </div>
                    `).join('') : '';

                    return `
                        <div class="window-group ${{isActiveWindow ? 'active' : ''}}">
                            <div class="window-item ${{w.active ? 'current' : ''}}"
                                 onclick="event.stopPropagation(); selectWindow('${{s.name}}', '${{w.index}}')">
                                <span class="window-index">${{w.index}}</span>
                                <span class="window-name">${{escapeHtml(w.name)}}</span>
                                <span class="pane-count">${{w.pane_count}}p</span>
                                ${{w.active ? '<span class="window-active-badge">*</span>' : ''}}
                            </div>
                            <div class="panes-list">${{panesHtml}}</div>
                        </div>
                    `;
                }}).join('') : '';

                return `
                    <div class="session-group ${{isActiveSession ? 'active' : ''}}">
                        <div class="session-item" onclick="selectSession('${{s.name}}')">
                            <span class="session-name">
                                ${{s.attached ? '🟢' : '⚪'}} ${{escapeHtml(s.name)}}
                            </span>
                            <span class="session-meta">${{s.window_count}} win · ${{s.created}}</span>
                        </div>
                        <div class="windows-list">${{windowsHtml}}</div>
                    </div>
                `;
            }}).join('');
        }}

        // Render git changes
        function renderGitChanges(status) {{
            if (!status || status === 'Clean' || status.startsWith('[')) {{
                return '';
            }}
            const files = status.split('\\n').filter(l => l.trim()).slice(0, 10);
            return files.map(f => {{
                const type = f.startsWith('M') ? 'modified' : f.startsWith('A') ? 'added' : f.startsWith('D') ? 'deleted' : 'modified';
                const name = f.substring(2).trim().split('/').pop();
                return `<span class="git-file ${{type}}">${{escapeHtml(name)}}</span>`;
            }}).join('');
        }}

        // Render commits
        function renderCommits(logs) {{
            if (!logs || logs.length === 0) {{
                return '<div class="empty-state">No commits</div>';
            }}
            return logs.map(c => `
                <div class="commit-item">
                    <span class="commit-hash">${{escapeHtml(c.hash)}}</span>
                    <span class="commit-msg">${{escapeHtml(c.message)}}</span>
                </div>
            `).join('');
        }}

        // Render processes
        function renderProcesses(processes) {{
            if (!processes || processes.length === 0) {{
                return '<div class="empty-state">No Claude processes</div>';
            }}
            return processes.map(p => `
                <div class="process-item">
                    <div class="process-cmd">${{escapeHtml(p.cmd)}}</div>
                    <div class="process-stats">
                        <span>PID: ${{p.pid}}</span>
                        <span>CPU: ${{p.cpu}}%</span>
                        <span>MEM: ${{p.mem}}%</span>
                    </div>
                </div>
            `).join('');
        }}

        // Update UI with data
        function updateUI(data) {{
            // Stats
            const claudeCount = data.claude ? data.claude.length : 0;
            const sessionCount = data.tmux && data.tmux.sessions ? data.tmux.sessions.length : 0;

            document.getElementById('statClaude').textContent = claudeCount;
            document.getElementById('statClaude').className = 'stat-value ' + (claudeCount > 0 ? 'green' : '');

            document.getElementById('statSessions').textContent = sessionCount;
            document.getElementById('statSessions').className = 'stat-value ' + (sessionCount > 0 ? 'green' : '');

            document.getElementById('statChanges').textContent = data.git ? data.git.changes : 0;
            document.getElementById('statChanges').className = 'stat-value ' + (data.git && data.git.changes > 0 ? 'yellow' : '');

            if (data.system && data.system.cpu) {{
                document.getElementById('statCpu').textContent = data.system.cpu;
            }}

            // Status dot
            const statusDot = document.getElementById('statusDot');
            statusDot.className = 'status-dot' + (claudeCount > 0 ? '' : sessionCount > 0 ? ' warning' : ' error');

            // Terminal
            if (data.tmux && data.tmux.active_content) {{
                document.getElementById('terminalContent').innerHTML = formatTerminal(data.tmux.active_content);
                // Auto-scroll to bottom
                const terminal = document.getElementById('terminalContent');
                terminal.scrollTop = terminal.scrollHeight;
            }}

            // Session badge
            if (data.tmux && data.tmux.sessions && data.tmux.sessions.length > 0) {{
                activeSession = data.tmux.sessions[0].name;
                document.getElementById('terminalSession').textContent = activeSession;
            }}

            // Store sessions data for later use
            sessionsData = data.tmux ? data.tmux.sessions : [];

            // Sessions list
            document.getElementById('sessionList').innerHTML = renderSessions(sessionsData);

            // Update session selector for input
            const sessionSelect = document.getElementById('targetSession');
            const currentValue = sessionSelect.value;
            sessionSelect.innerHTML = '<option value="">Auto</option>';
            if (sessionsData) {{
                sessionsData.forEach(s => {{
                    const opt = document.createElement('option');
                    opt.value = s.name;
                    opt.textContent = s.name;
                    sessionSelect.appendChild(opt);
                }});
            }}
            sessionSelect.value = currentValue;

            // Update windows and panes dropdowns
            updateWindowsDropdown();
            updatePanesDropdown();

            // Git
            if (data.git) {{
                document.getElementById('gitBranch').textContent = data.git.branch || '-';
                document.getElementById('gitChanges').innerHTML = renderGitChanges(data.git.status);
                document.getElementById('commitList').innerHTML = renderCommits(data.git.log);
            }}

            // Processes
            document.getElementById('processList').innerHTML = renderProcesses(data.claude);

            // Update time
            document.getElementById('lastUpdate').textContent = new Date().toLocaleTimeString();
        }}

        // Select a different session (uses active window/pane of that session)
        async function selectSession(name) {{
            activeSession = name;
            activeWindow = null;
            activePane = null;
            updateTerminalBadge();
            updateWindowsDropdown();
            updatePanesDropdown();

            try {{
                const response = await fetch(`/api/pane?session=${{encodeURIComponent(name)}}`);
                const data = await response.json();
                document.getElementById('terminalContent').innerHTML = formatTerminal(data.content);
                const terminal = document.getElementById('terminalContent');
                terminal.scrollTop = terminal.scrollHeight;
            }} catch (e) {{
                console.error('Failed to fetch pane:', e);
            }}

            document.getElementById('sessionList').innerHTML = renderSessions(sessionsData);
        }}

        // Select a specific window within a session
        async function selectWindow(sessionName, windowIndex) {{
            activeSession = sessionName;
            activeWindow = windowIndex;
            activePane = null;
            updateTerminalBadge();
            updateWindowsDropdown();
            updatePanesDropdown();

            try {{
                const response = await fetch(`/api/pane?session=${{encodeURIComponent(sessionName)}}&window=${{encodeURIComponent(windowIndex)}}`);
                const data = await response.json();
                document.getElementById('terminalContent').innerHTML = formatTerminal(data.content);
                const terminal = document.getElementById('terminalContent');
                terminal.scrollTop = terminal.scrollHeight;
            }} catch (e) {{
                console.error('Failed to fetch pane:', e);
            }}

            document.getElementById('sessionList').innerHTML = renderSessions(sessionsData);
        }}

        // Select a specific pane within a window
        async function selectPane(sessionName, windowIndex, paneIndex) {{
            activeSession = sessionName;
            activeWindow = windowIndex;
            activePane = paneIndex;
            updateTerminalBadge();
            updateWindowsDropdown();
            updatePanesDropdown();

            try {{
                const response = await fetch(`/api/pane?session=${{encodeURIComponent(sessionName)}}&window=${{encodeURIComponent(windowIndex)}}&pane=${{encodeURIComponent(paneIndex)}}`);
                const data = await response.json();
                document.getElementById('terminalContent').innerHTML = formatTerminal(data.content);
                const terminal = document.getElementById('terminalContent');
                terminal.scrollTop = terminal.scrollHeight;
            }} catch (e) {{
                console.error('Failed to fetch pane:', e);
            }}

            document.getElementById('sessionList').innerHTML = renderSessions(sessionsData);
        }}

        // Update terminal badge to show session:window.pane
        function updateTerminalBadge() {{
            const badge = document.getElementById('terminalSession');
            if (activePane !== null) {{
                badge.textContent = `${{activeSession}}:${{activeWindow}}.${{activePane}}`;
            }} else if (activeWindow !== null) {{
                badge.textContent = `${{activeSession}}:${{activeWindow}}`;
            }} else {{
                badge.textContent = activeSession || '-';
            }}
        }}

        // Update windows dropdown based on selected session
        function updateWindowsDropdown() {{
            const windowSelect = document.getElementById('targetWindow');
            const currentValue = windowSelect.value;
            windowSelect.innerHTML = '<option value="">Win</option>';

            const targetSession = getTargetSession();
            const session = sessionsData.find(s => s.name === targetSession);
            if (session && session.windows) {{
                session.windows.forEach(w => {{
                    const opt = document.createElement('option');
                    opt.value = w.index;
                    opt.textContent = `${{w.index}}: ${{w.name}}${{w.active ? ' *' : ''}}`;
                    windowSelect.appendChild(opt);
                }});
            }}
            if (currentValue && [...windowSelect.options].some(o => o.value === currentValue)) {{
                windowSelect.value = currentValue;
            }}
        }}

        // Update panes dropdown based on selected session and window
        function updatePanesDropdown() {{
            const paneSelect = document.getElementById('targetPane');
            const currentValue = paneSelect.value;
            paneSelect.innerHTML = '<option value="">Pane</option>';

            const targetSession = getTargetSession();
            const targetWindow = getTargetWindow();
            const session = sessionsData.find(s => s.name === targetSession);
            if (session && session.windows && targetWindow) {{
                const window = session.windows.find(w => w.index === targetWindow);
                if (window && window.panes) {{
                    window.panes.forEach(p => {{
                        const opt = document.createElement('option');
                        opt.value = p.index;
                        opt.textContent = `${{p.index}}: ${{p.command}}${{p.active ? ' *' : ''}}`;
                        paneSelect.appendChild(opt);
                    }});
                }}
            }}
            if (currentValue && [...paneSelect.options].some(o => o.value === currentValue)) {{
                paneSelect.value = currentValue;
            }}
        }}

        // Refresh data
        async function refreshData() {{
            const btn = document.getElementById('refreshBtn');
            const text = document.getElementById('refreshText');

            btn.classList.add('loading');
            text.textContent = '...';

            try {{
                const response = await fetch('/api/data');
                const data = await response.json();
                updateUI(data);
            }} catch (e) {{
                console.error('Failed to refresh:', e);
                document.getElementById('statusDot').className = 'status-dot error';
            }} finally {{
                btn.classList.remove('loading');
                text.textContent = 'Refresh';
            }}
        }}

        // Pull to refresh
        document.addEventListener('touchstart', (e) => {{
            if (window.scrollY === 0) {{
                touchStartY = e.touches[0].clientY;
            }}
        }});

        document.addEventListener('touchmove', (e) => {{
            if (touchStartY > 0 && window.scrollY === 0) {{
                const diff = e.touches[0].clientY - touchStartY;
                if (diff > 50) {{
                    isPulling = true;
                    document.getElementById('pullIndicator').classList.add('visible');
                }}
            }}
        }});

        document.addEventListener('touchend', () => {{
            if (isPulling) {{
                refreshData();
            }}
            touchStartY = 0;
            isPulling = false;
            document.getElementById('pullIndicator').classList.remove('visible');
        }});

        // Initial load and auto-refresh
        refreshData();
        refreshTimer = setInterval(refreshData, refreshInterval);

        // Visibility change handling
        document.addEventListener('visibilitychange', () => {{
            if (document.hidden) {{
                clearInterval(refreshTimer);
            }} else {{
                refreshData();
                refreshTimer = setInterval(refreshData, refreshInterval);
            }}
        }});
    </script>
</body>
</html>'''


def main():
    parser = argparse.ArgumentParser(description='Claw - Remote control for Claude Code sessions')
    parser.add_argument('-p', '--port', type=int, default=8080, help='Port to run on')
    parser.add_argument('-r', '--refresh', type=int, default=5, help='Refresh interval in seconds')
    parser.add_argument('-d', '--dir', type=str, help='Add a work directory to monitor')
    args = parser.parse_args()

    config = DashboardConfig()
    config.port = args.port
    config.refresh_interval = args.refresh

    if args.dir:
        name = Path(args.dir).name
        config.work_dirs[name] = args.dir

    DashboardHandler.config = config

    # Allow port reuse
    socketserver.TCPServer.allow_reuse_address = True

    print(f'''
\033[38;5;141m    ╱╱╱
   ╱╱╱   \033[0m\033[1mClaw\033[0m - CLaude AnyWhere
\033[38;5;141m  ╱╱╱    \033[0m\033[2mRemote control for Claude Code\033[0m

  \033[38;5;244m→\033[0m  http://0.0.0.0:{config.port}
  \033[38;5;244m→\033[0m  Refresh: {config.refresh_interval}s | Projects: {len(config.work_dirs)}
    ''')

    print("  Projects:")
    for name, path in config.work_dirs.items():
        print(f"    • {name}: {path}")
    print()
    print("  \033[2mPress Ctrl+C to stop\033[0m")
    print()

    try:
        with socketserver.TCPServer(("", config.port), DashboardHandler) as httpd:
            httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n  \033[2mClaw stopped.\033[0m")
    except OSError as e:
        if 'Address already in use' in str(e):
            print(f"\033[31mError:\033[0m Port {config.port} already in use. Try: claw -p {config.port + 1}")
        else:
            raise


if __name__ == '__main__':
    main()
