"""SwarmForge Web Studio Launcher.

Launches the SwarmForge Web Studio and API server on 0.0.0.0:8765,
displaying local, LAN, and public worldwide URLs (via Cloudflare tunnel).
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
import webbrowser
from pathlib import Path

import uvicorn

from swarmforge.server import create_app


def get_local_ip() -> str:
    """Detect LAN IP address for network sharing."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def find_cloudflared() -> str | None:
    """Find cloudflared executable."""
    found = shutil.which("cloudflared")
    if found:
        return found
    candidates = [
        Path(__file__).parent / "cloudflared.exe",
        Path(__file__).parent.parent / "cloudflared.exe",
        Path.home() / ".cloudflared" / "cloudflared.exe",
    ]
    for c in candidates:
        if c.exists():
            return str(c)
    return None


def start_public_tunnel(port: int = 8765) -> tuple[subprocess.Popen | None, str | None]:
    cf = find_cloudflared()
    if not cf:
        return None, None
    try:
        proc = subprocess.Popen(
            [cf, "tunnel", "--url", f"http://127.0.0.1:{port}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        public_url = None
        start = time.time()
        while time.time() - start < 15:
            line = proc.stdout.readline()
            if not line:
                time.sleep(0.1)
                continue
            m = re.search(r"https://[a-zA-Z0-9-]+\.trycloudflare\.com", line)
            if m:
                public_url = m.group(0)
                break
        return proc, public_url
    except Exception:
        return None, None


def open_browser_later(url: str, delay: float = 1.2) -> None:
    def _worker():
        time.sleep(delay)
        webbrowser.open(url)

    t = threading.Thread(target=_worker, daemon=True)
    t.start()


def main():
    parser = argparse.ArgumentParser(description="SwarmForge Web Studio Launcher")
    parser.add_argument("--host", default="0.0.0.0", help="Host interface (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8765, help="Port (default: 8765)")
    parser.add_argument("--public", action="store_true", default=True, help="Create a public worldwide HTTPS tunnel")
    parser.add_argument("--no-browser", action="store_true", help="Do not open browser automatically")
    args = parser.parse_args()

    local_ip = get_local_ip()
    public_proc = None
    public_url = None

    if args.public:
        print("[*] Establishing secure public worldwide tunnel...")
        public_proc, public_url = start_public_tunnel(args.port)

    app = create_app(seed_demo=True)

    print("=" * 76)
    print("  SwarmForge — Multi-Agent DAG Orchestrator & Policy Firewall Studio")
    print("=" * 76)
    if public_url:
        print(f"  [>>>] PUBLIC WORLDWIDE URL: {public_url}")
        print("        ^ Anyone anywhere on the internet can use this link to operate!")
    print(f"  [+] Localhost URL:          http://localhost:{args.port}")
    print(f"  [+] Local Network (LAN) URL: http://{local_ip}:{args.port}")
    print(f"  [+] REST API / Docs:        http://localhost:{args.port}/docs")
    print(f"  [+] Policy Firewall Lab:    http://localhost:{args.port}/#firewall")
    print("=" * 76)
    print("  Press Ctrl+C to stop the server.\n")

    if not args.no_browser:
        target_browser_url = public_url or f"http://localhost:{args.port}"
        open_browser_later(target_browser_url)

    try:
        uvicorn.run(app, host=args.host, port=args.port, log_level="info")
    finally:
        if public_proc:
            public_proc.terminate()


if __name__ == "__main__":
    main()
