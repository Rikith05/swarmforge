"""SwarmForge Web Studio Launcher.

Launches the SwarmForge Web Studio and API server on 0.0.0.0:8765,
displaying local and network URLs, and opens your default browser.
"""

from __future__ import annotations

import socket
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


def open_browser_later(url: str, delay: float = 1.2) -> None:
    def _worker():
        time.sleep(delay)
        webbrowser.open(url)

    t = threading.Thread(target=_worker, daemon=True)
    t.start()


def main():
    host = "0.0.0.0"
    port = 8765
    local_ip = get_local_ip()

    app = create_app(seed_demo=True)

    print("=" * 70)
    print("  SwarmForge — Multi-Agent DAG Orchestrator & Policy Firewall Studio")
    print("=" * 70)
    print(f"  [+] Local URL:    http://localhost:{port}")
    print(f"  [+] Network URL:  http://{local_ip}:{port} (share on your LAN)")
    print(f"  [+] REST / Docs:  http://localhost:{port}/docs")
    print(f"  [+] Firewall Lab: http://localhost:{port}/#firewall")
    print("=" * 70)
    print("  Opening browser automatically...")
    print("  Press Ctrl+C to stop the server.\n")

    open_browser_later(f"http://localhost:{port}")
    uvicorn.run(app, host=host, port=port, log_level="info")


if __name__ == "__main__":
    main()
