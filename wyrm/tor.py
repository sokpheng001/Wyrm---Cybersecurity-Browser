"""Tor integration, built the way Brave's "Private window with Tor" works:

* the official Tor binary (Tor Expert Bundle from dist.torproject.org) runs as a separate process,
  downloaded on first use and verified against the Tor Project's published SHA-256 checksums;
* it is driven with `stem`, the Tor Project's official controller library (bootstrap progress, new identity);
* the Tor window is a separate browser process whose Chromium engine is pinned to Tor's SOCKS5 proxy, with
  local DNS resolution disabled and WebRTC restricted to the proxy (no IP/DNS leaks), and an off-the-record
  profile (nothing written to disk);
* the browser's own Python features (search, analysis, recon) are routed through Tor as well.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import platform
import shutil
import socket
import sys
import tarfile
from pathlib import Path

import requests

DIST = "https://dist.torproject.org/torbrowser"
VERSION_URL = "https://aus1.torproject.org/torbrowser/update_3/release/downloads.json"


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def platform_tag() -> str:
    m = platform.machine().lower()
    arch = "aarch64" if m in ("arm64", "aarch64") else "x86_64"
    if sys.platform == "win32":
        return "windows-x86_64"
    if sys.platform == "darwin":
        return f"macos-{arch}"
    return f"linux-{arch}"


def chromium_flags(socks_port: int) -> list[str]:
    """Engine flags for a Tor window. No spaces in any value (they go in QTWEBENGINE_CHROMIUM_FLAGS,
    which is split on spaces). Chromium resolves DNS through the SOCKS5 proxy, so no names leak locally."""
    return [
        f"--proxy-server=socks5://127.0.0.1:{socks_port}",
        "--proxy-bypass-list=<-loopback>",  # don't proxy 127.0.0.1 (the Tor control port)
        "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
        "--disable-features=WebRtcHideLocalIpsWithMdns,DnsOverHttps,NetworkPrediction",
    ]


class TorManager:
    def __init__(self, data_dir: Path):
        self.root = data_dir / "tor"
        self.process = None
        self.socks_port = 0
        self.control_port = 0

    # ---------------------------------------------------------- binary
    def tor_path(self) -> str | None:
        exe = "tor.exe" if sys.platform == "win32" else "tor"
        bundled = self.root / "tor" / exe
        if bundled.exists():
            return str(bundled)
        return shutil.which("tor")

    def install(self, log) -> str:
        """Download + verify + unpack the Tor Expert Bundle. Runs in a worker thread."""
        # direct connection: the Tor window's proxy env vars point at a Tor that isn't running yet
        http = requests.Session()
        http.trust_env = False
        log(0, "Finding the latest Tor release…")
        version = http.get(VERSION_URL, timeout=30).json()["version"]
        name = f"tor-expert-bundle-{platform_tag()}-{version}.tar.gz"
        sums = http.get(f"{DIST}/{version}/sha256sums-signed-build.txt", timeout=30).text
        expected = next((line.split()[0] for line in sums.splitlines() if line.endswith(name)), None)
        if not expected:
            raise RuntimeError(f"No published checksum for {name}")
        log(2, f"Downloading {name}…")
        r = http.get(f"{DIST}/{version}/{name}", timeout=120, stream=True)
        r.raise_for_status()
        total = int(r.headers.get("content-length", 0)) or 1
        buf = io.BytesIO()
        for chunk in r.iter_content(256 * 1024):
            buf.write(chunk)
            log(2 + int(8 * buf.tell() / total), f"Downloading Tor {version}… {buf.tell() // 1024 // 1024} MB")
        data = buf.getvalue()
        digest = hashlib.sha256(data).hexdigest()
        if digest != expected:
            raise RuntimeError(f"Checksum mismatch for {name}: refusing to run it")
        log(10, "Checksum verified (SHA-256 matches torproject.org). Unpacking…")
        if self.root.exists():
            shutil.rmtree(self.root)
        self.root.mkdir(parents=True)
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
            tf.extractall(self.root, filter="data")
        exe = self.root / "tor" / ("tor.exe" if sys.platform == "win32" else "tor")
        if sys.platform != "win32":
            exe.chmod(0o755)
        (self.root / "version.json").write_text(json.dumps({"version": version, "sha256": digest}))
        return str(exe)

    # ---------------------------------------------------------- process
    def start(self, socks_port: int, log) -> None:
        import stem.process

        tor = self.tor_path() or self.install(log)
        self.socks_port = socks_port
        self.control_port = free_port()
        data = self.root / "data-dir"
        data.mkdir(parents=True, exist_ok=True)
        cfg = {"SocksPort": f"127.0.0.1:{socks_port}", "ControlPort": f"127.0.0.1:{self.control_port}",
               "CookieAuthentication": "1", "DataDirectory": str(data), "ClientOnly": "1",
               "AvoidDiskWrites": "1", "Log": "notice stdout"}
        # Tor needs ABSOLUTE geoip paths (a relative/empty one makes it refuse to start). The Expert
        # Bundle ships them under data/ — find them wherever they extracted and pass absolute paths.
        for cfgkey, fname in (("GeoIPFile", "geoip"), ("GeoIPv6File", "geoip6")):
            hits = list(self.root.rglob(fname))
            if hits:
                cfg[cfgkey] = str(hits[0].resolve())
        if sys.platform.startswith("linux"):  # bundled tor ships its own libs next to the binary
            os.environ["LD_LIBRARY_PATH"] = str(Path(tor).parent) + os.pathsep + os.environ.get("LD_LIBRARY_PATH", "")

        def on_line(line):
            if "Bootstrapped" in line:
                try:
                    pct = int(line.split("Bootstrapped", 1)[1].split("%", 1)[0])
                except ValueError:
                    pct = 0
                log(10 + int(pct * 0.9), line.split("]", 1)[-1].strip())
        log(10, "Starting Tor…")
        self.process = stem.process.launch_tor_with_config(config=cfg, tor_cmd=tor, init_msg_handler=on_line,
                                                           take_ownership=True,
                                                           timeout=None if sys.platform == "win32" else 180)
        # one long-lived control connection: with take_ownership, tor exits when it closes (i.e. with us)
        from stem.control import Controller
        self.controller = Controller.from_port(address="127.0.0.1", port=self.control_port)
        self.controller.authenticate()
        log(100, "Connected to the Tor network")

    def new_identity(self) -> None:
        from stem import Signal
        self.controller.signal(Signal.NEWNYM)

    def circuit_summary(self) -> str:
        c = getattr(self, "controller", None)
        if not c:
            return "Not connected"
        try:
            circs = [ci for ci in c.get_circuits() if ci.status == "BUILT" and ci.purpose == "GENERAL"]
            if not circs:
                return "No circuit built yet"
            hops = []
            for fp, nick in circs[-1].path:
                desc = c.get_network_status(fp, None)
                country = c.get_info(f"ip-to-country/{desc.address}", "??") if desc else "??"
                hops.append(f"{nick} ({country.upper()})")
            return " → ".join(hops)
        except Exception as e:  # noqa: BLE001
            return f"Circuit info unavailable: {e}"

    def stop(self):
        if getattr(self, "controller", None):
            try:
                self.controller.close()
            except Exception:  # noqa: BLE001
                pass
            self.controller = None
        if self.process:
            self.process.kill()
            self.process = None

    def version(self) -> str:
        try:
            return json.loads((self.root / "version.json").read_text())["version"]
        except (OSError, ValueError, KeyError):
            return "system"
