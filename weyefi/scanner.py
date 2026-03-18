"""Network scanner using nmap + ARP cache fallback for MAC addresses."""

import re
import shutil
import subprocess
from pathlib import Path

import nmap


def _read_arp_table():
    """Read MAC addresses from the ARP cache (works without root).

    Tries multiple methods in order:
      1. `ip neigh show` (works on Termux without root)
      2. /proc/net/arp (needs permission on some Android versions)
      3. `arp -a` (macOS / BSD fallback)

    Returns dict mapping IP -> MAC address.
    """
    arp_map = {}

    # Method 1: `ip neigh show` — best option for Termux (no root needed)
    try:
        out = subprocess.run(
            ["ip", "neigh", "show"], capture_output=True, text=True, timeout=10
        ).stdout
        for match in re.finditer(
            r"(\d+\.\d+\.\d+\.\d+)\s+.*lladdr\s+([\da-fA-F:]+)", out
        ):
            arp_map[match.group(1)] = match.group(2).upper()
        if arp_map:
            return arp_map
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # Method 2: /proc/net/arp (may be blocked on Termux without root)
    try:
        arp_path = Path("/proc/net/arp")
        if arp_path.exists():
            for line in arp_path.read_text().splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 4 and parts[3] != "00:00:00:00:00:00":
                    arp_map[parts[0]] = parts[3].upper()
            if arp_map:
                return arp_map
    except (PermissionError, OSError):
        pass

    # Method 3: `arp -a` (macOS / BSD fallback)
    try:
        out = subprocess.run(
            ["arp", "-a"], capture_output=True, text=True, timeout=10
        ).stdout
        for match in re.finditer(
            r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([\da-fA-F:]+)", out
        ):
            arp_map[match.group(1)] = match.group(2).upper()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    return arp_map


def _ping_sweep(subnet):
    """Ping all hosts in the subnet to populate the ARP cache.

    Uses nmap -sn which, without root, falls back to TCP probes on 80/443.
    """
    nm = nmap.PortScanner()
    nm.scan(hosts=subnet, arguments="-sn")
    return nm


def scan_network(subnet="192.168.1.0/24"):
    """Scan the local network and return a list of discovered devices.

    Strategy (no-root friendly):
      1. Run nmap -sn to discover live hosts (TCP probes on 80/443).
      2. Read /proc/net/arp to harvest MAC addresses.
      3. Merge by IP.

    Returns:
        list[dict]: Each dict has keys: ip, mac, hostname, state.
    """
    if not shutil.which("nmap"):
        raise RuntimeError(
            "nmap is not installed. Run: pkg install nmap (Termux) "
            "or sudo apt install nmap"
        )

    nm = _ping_sweep(subnet)
    arp_map = _read_arp_table()

    devices = []
    for host in nm.all_hosts():
        addresses = nm[host].get("addresses", {})
        # Prefer nmap MAC (only available as root), fall back to ARP cache
        mac = addresses.get("mac", arp_map.get(host, ""))
        hostname = nm[host].hostname() or ""
        state = nm[host].state()
        devices.append(
            {
                "ip": host,
                "mac": mac.upper() if mac else "",
                "hostname": hostname,
                "state": state,
            }
        )

    return devices
