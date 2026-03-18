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
    """Discover live hosts using multiple techniques for maximum coverage.

    Without root, nmap -sn only probes TCP 80/443 which misses many devices.
    We combine multiple methods to catch everything:
      1. nmap -sn (TCP 80/443 probes)
      2. nmap TCP probe on common IoT/device ports
      3. ARP-populated IPs from ip neigh
    """
    nm = nmap.PortScanner()
    # Standard ping sweep + probe extra ports that phones/TVs/consoles respond on
    nm.scan(
        hosts=subnet,
        arguments="-sn -PA21,22,23,80,443,554,5353,8008,8080,8443,62078",
    )
    return nm


def _mdns_discover():
    """Discover device names/models via mDNS (Bonjour/Avahi).

    Uses dns-sd or avahi-browse if available. Returns dict mapping IP -> model string.
    Falls back gracefully if neither tool is present.
    """
    mdns_map = {}

    # Try avahi-browse (Linux / Termux with avahi)
    try:
        out = subprocess.run(
            ["avahi-browse", "-atpr", "--no-db-lookup"],
            capture_output=True, text=True, timeout=8,
        ).stdout
        for line in out.splitlines():
            if line.startswith("="):
                parts = line.split(";")
                if len(parts) >= 8:
                    ip = parts[7]
                    name = parts[3]
                    if re.match(r"\d+\.\d+\.\d+\.\d+", ip) and name:
                        mdns_map.setdefault(ip, name)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # Try nmap mDNS script (works without root)
    if not mdns_map and shutil.which("nmap"):
        try:
            out = subprocess.run(
                ["nmap", "--script", "dns-service-discovery", "-p", "5353",
                 "--open", "-oG", "-", "224.0.0.251"],
                capture_output=True, text=True, timeout=10,
            ).stdout
            # Parse any useful hostnames from output
            for match in re.finditer(
                r"(\d+\.\d+\.\d+\.\d+).*?name:\s*(.+?)\s*[,;\n]", out, re.IGNORECASE
            ):
                mdns_map.setdefault(match.group(1), match.group(2))
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

    return mdns_map


# Patterns for guessing device type from hostname or vendor
_DEVICE_TYPE_PATTERNS = [
    (r"(?i)(iphone|ipad|ipod|macbook|imac|apple.?tv|airpods|homepod)", "Apple"),
    (r"(?i)(galaxy|samsung|sm-[a-z])", "Samsung"),
    (r"(?i)(pixel|chromecast|google.?home|nest|android)", "Google"),
    (r"(?i)(echo|fire.?tv|kindle|amazon|ring)", "Amazon"),
    (r"(?i)(roku)", "Roku"),
    (r"(?i)(playstation|ps[345])", "PlayStation"),
    (r"(?i)(xbox)", "Xbox"),
    (r"(?i)(nintendo|switch)", "Nintendo"),
    (r"(?i)(printer|epson|canon|brother|hp.?print|laserjet)", "Printer"),
    (r"(?i)(tv|roku|vizio|lg.?web|tizen|bravia|firetv)", "Smart TV"),
    (r"(?i)(cam|camera|ring|wyze|arlo|blink)", "Camera"),
    (r"(?i)(router|gateway|netgear|asus.?rt|tp.?link|linksys|ubiquiti|arris|modem)", "Router/Gateway"),
    (r"(?i)(raspberr)", "Raspberry Pi"),
]


def _guess_device_type(hostname="", vendor=""):
    """Guess device type from hostname and vendor strings."""
    combined = f"{hostname} {vendor}"
    for pattern, device_type in _DEVICE_TYPE_PATTERNS:
        if re.search(pattern, combined):
            return device_type
    return ""


def scan_network(subnet="192.168.1.0/24"):
    """Scan the local network and return a list of discovered devices.

    Strategy (no-root friendly):
      1. Run nmap -sn to discover live hosts (TCP probes on 80/443).
      2. Read ARP cache to harvest MAC addresses.
      3. Attempt mDNS discovery for device names/models.
      4. Merge all data by IP.

    Returns:
        list[dict]: Each dict has keys: ip, mac, hostname, state, mdns_name, device_type.
    """
    if not shutil.which("nmap"):
        raise RuntimeError(
            "nmap is not installed. Run: pkg install nmap (Termux) "
            "or sudo apt install nmap"
        )

    nm = _ping_sweep(subnet)
    arp_map = _read_arp_table()
    mdns_map = _mdns_discover()

    seen_ips = set()
    devices = []
    for host in nm.all_hosts():
        seen_ips.add(host)
        addresses = nm[host].get("addresses", {})
        # Prefer nmap MAC (only available as root), fall back to ARP cache
        mac = addresses.get("mac", arp_map.get(host, ""))
        hostname = nm[host].hostname() or ""
        state = nm[host].state()
        mdns_name = mdns_map.get(host, "")
        # Use mDNS name as hostname if nmap didn't find one
        if not hostname and mdns_name:
            hostname = mdns_name
        devices.append(
            {
                "ip": host,
                "mac": mac.upper() if mac else "",
                "hostname": hostname,
                "state": state,
                "mdns_name": mdns_name,
                "device_type": "",  # filled after vendor lookup
            }
        )

    # Add any hosts found in ARP cache but missed by nmap
    for ip, mac in arp_map.items():
        if ip not in seen_ips and _ip_in_subnet(ip, subnet):
            mdns_name = mdns_map.get(ip, "")
            devices.append(
                {
                    "ip": ip,
                    "mac": mac.upper(),
                    "hostname": mdns_name,
                    "state": "up",
                    "mdns_name": mdns_name,
                    "device_type": "",
                }
            )

    return devices


def _ip_in_subnet(ip, subnet):
    """Simple check if an IP is in a /24 subnet (covers most home networks)."""
    try:
        ip_parts = ip.split(".")
        subnet_base = subnet.split("/")[0].split(".")
        return ip_parts[:3] == subnet_base[:3]
    except (IndexError, ValueError):
        return False
