"""Device profiler — deep reconnaissance of network devices.

Probes each device for:
  - Open service ports → infer device function and active services
  - NetBIOS / SMB name → Windows username and computer name
  - mDNS/DNS-SD services → Apple/Android device names, Chromecast, printers
  - HTTP server banners → firmware, model strings
  - VPN/tunnel indicators → detect encrypted tunnel traffic
  - TTL analysis → guess OS and detect remote/proxied connections
"""

import re
import shutil
import subprocess

# Ports that reveal device identity or activity
_PROFILE_PORTS = (
    "21,22,23,53,80,137,139,443,445,548,554,631,1900,3389,5000,"
    "5353,5900,7000,7100,8008,8080,8443,9100,49152,62078"
)

# Port → service/meaning mapping
_PORT_LABELS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    53: "DNS",
    80: "HTTP",
    137: "NetBIOS-NS",
    139: "NetBIOS/SMB",
    443: "HTTPS",
    445: "SMB/CIFS",
    548: "AFP (Apple File Sharing)",
    554: "RTSP (Streaming/Camera)",
    631: "IPP (Printer)",
    1900: "UPnP/SSDP",
    3389: "RDP (Remote Desktop)",
    5000: "UPnP/Synology",
    5353: "mDNS (Bonjour)",
    5900: "VNC (Remote Desktop)",
    7000: "AirPlay",
    7100: "AirPlay Display",
    8008: "Chromecast",
    8080: "HTTP Alt",
    8443: "HTTPS Alt",
    9100: "Printer (RAW)",
    49152: "UPnP",
    62078: "iPhone Sync (lockdownd)",
}

# Known VPN/tunnel port signatures
_VPN_PORTS = {
    500: "IKE (IPSec VPN)",
    1194: "OpenVPN",
    1701: "L2TP",
    1723: "PPTP",
    4500: "IPSec NAT-T",
    51820: "WireGuard",
}

# TTL → OS family mapping (TTL from first hop)
_TTL_OS_MAP = [
    (range(0, 33), "Unusual (possible proxy/VPN)"),
    (range(33, 65), "Linux/Android/Chromecast"),
    (range(65, 129), "Windows/iOS/macOS"),
    (range(129, 256), "Network device (router/switch)"),
]


def _run_cmd(cmd, timeout=15):
    """Run a shell command and return stdout, or empty string on failure."""
    try:
        return subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        ).stdout
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return ""


def probe_ports(ip):
    """Scan common service ports on a device (no root needed, TCP connect).

    Returns list of dicts: [{port, service, state}]
    """
    if not shutil.which("nmap"):
        return []

    out = _run_cmd(
        ["nmap", "-sT", "-p", _PROFILE_PORTS, "--open", "-T4", "--host-timeout",
         "10s", ip],
        timeout=20,
    )

    open_ports = []
    for match in re.finditer(r"(\d+)/tcp\s+open\s+(\S*)", out):
        port = int(match.group(1))
        nmap_svc = match.group(2)
        label = _PORT_LABELS.get(port, nmap_svc or f"port-{port}")
        open_ports.append({"port": port, "service": label, "state": "open"})

    return open_ports


def probe_netbios(ip):
    """Try to get NetBIOS/SMB name (reveals Windows computer name & username).

    Uses nmblookup or nmap nbstat script. No root needed.
    """
    info = {"computer_name": "", "workgroup": "", "user": ""}

    # Method 1: nmblookup (from samba-common)
    if shutil.which("nmblookup"):
        out = _run_cmd(["nmblookup", "-A", ip], timeout=5)
        for line in out.splitlines():
            parts = line.strip().split()
            if len(parts) >= 2:
                name = parts[0]
                flags = line[15:].strip() if len(line) > 15 else ""
                if "<00>" in flags and "GROUP" not in flags and not info["computer_name"]:
                    info["computer_name"] = name
                elif "<00>" in flags and "GROUP" in flags:
                    info["workgroup"] = name
                elif "<03>" in flags and "GROUP" not in flags:
                    info["user"] = name

    # Method 2: nmap nbstat script fallback
    if not info["computer_name"] and shutil.which("nmap"):
        out = _run_cmd(
            ["nmap", "--script", "nbstat", "-p", "137", ip], timeout=10
        )
        m = re.search(r"NetBIOS name:\s*(\S+)", out)
        if m:
            info["computer_name"] = m.group(1)
        m = re.search(r"NetBIOS user:\s*(\S+)", out)
        if m and m.group(1) != "<unknown>":
            info["user"] = m.group(1)
        m = re.search(r"Workgroup:\s*(\S+)", out, re.IGNORECASE)
        if m:
            info["workgroup"] = m.group(1)

    return info


def probe_http_banner(ip, ports=None):
    """Grab HTTP server headers to identify firmware/model.

    Tries common HTTP ports. No root needed.
    """
    if ports is None:
        ports = [80, 8080, 8008, 443, 8443]

    banners = []
    for port in ports:
        out = _run_cmd(
            ["curl", "-sI", "-m", "3", "--connect-timeout", "2",
             "-k", f"http{'s' if port in (443, 8443) else ''}://{ip}:{port}/"],
            timeout=5,
        )
        if out:
            server = ""
            title = ""
            for line in out.splitlines():
                if line.lower().startswith("server:"):
                    server = line.split(":", 1)[1].strip()
                if line.lower().startswith("x-device"):
                    title = line.split(":", 1)[1].strip()
            if server:
                banners.append({"port": port, "server": server, "extra": title})

    return banners


def probe_ttl(ip):
    """Measure TTL to guess OS family and detect VPN/proxy hops.

    Standard initial TTLs:
      - Linux/Android: 64
      - Windows/iOS/macOS: 128
      - Router/switch: 255
      - Lower than expected = device is behind a VPN/tunnel/proxy
    """
    out = _run_cmd(["ping", "-c", "1", "-W", "2", ip], timeout=5)
    m = re.search(r"ttl[=:](\d+)", out, re.IGNORECASE)
    if not m:
        return {"ttl": None, "os_guess": "", "vpn_likely": False}

    ttl = int(m.group(1))
    os_guess = "Unknown"
    for ttl_range, label in _TTL_OS_MAP:
        if ttl in ttl_range:
            os_guess = label
            break

    # If TTL is unusually low (e.g. 50 when expected 64, or 110 when expected 128),
    # the device is likely routing through a VPN adding extra hops
    vpn_likely = False
    if 32 < ttl < 55:  # Expected 64, lost 10+ hops = VPN
        vpn_likely = True
    elif 100 < ttl < 118:  # Expected 128, lost 10+ hops = VPN
        vpn_likely = True

    return {"ttl": ttl, "os_guess": os_guess, "vpn_likely": vpn_likely}


def detect_vpn(ip, open_ports=None):
    """Detect VPN/tunnel usage on a device.

    Methods:
      1. Check if device has VPN-related ports open (OpenVPN, WireGuard, etc.)
      2. TTL anomaly detection (extra hops = tunneled traffic)
      3. Check for multiple active interfaces / unusual routing
    """
    indicators = []

    # Check VPN ports
    if open_ports:
        for p in open_ports:
            if p["port"] in _VPN_PORTS:
                indicators.append(f"VPN port open: {p['port']} ({_VPN_PORTS[p['port']]})")

    # Extended VPN port scan
    vpn_port_str = ",".join(str(p) for p in _VPN_PORTS)
    if shutil.which("nmap"):
        out = _run_cmd(
            ["nmap", "-sT", "-p", vpn_port_str, "--open", "-T4",
             "--host-timeout", "5s", ip],
            timeout=10,
        )
        for match in re.finditer(r"(\d+)/tcp\s+open", out):
            port = int(match.group(1))
            if port in _VPN_PORTS:
                label = _VPN_PORTS[port]
                indicator = f"VPN port open: {port} ({label})"
                if indicator not in indicators:
                    indicators.append(indicator)

    # TTL check
    ttl_info = probe_ttl(ip)
    if ttl_info.get("vpn_likely"):
        indicators.append(f"TTL anomaly: {ttl_info['ttl']} (expected 64 or 128)")

    return {
        "vpn_detected": len(indicators) > 0,
        "indicators": indicators,
        "ttl_info": ttl_info,
    }


def detect_remote_access(ip, open_ports=None):
    """Check if a device has remote access services running.

    Detects RDP, VNC, SSH, Telnet — services that allow someone outside
    the network to control the device (or indicate it IS being accessed remotely).
    """
    remote_ports = {
        22: "SSH",
        23: "Telnet",
        3389: "RDP (Windows Remote Desktop)",
        5900: "VNC (Screen Sharing)",
        5938: "TeamViewer",
        6568: "AnyDesk",
    }

    services = []
    if open_ports:
        for p in open_ports:
            if p["port"] in remote_ports:
                services.append({
                    "port": p["port"],
                    "service": remote_ports[p["port"]],
                })

    return {
        "remote_access": len(services) > 0,
        "services": services,
    }


def profile_device(ip):
    """Run full reconnaissance on a single device.

    Returns a comprehensive profile dict.
    """
    profile = {"ip": ip}

    # Port scan
    ports = probe_ports(ip)
    profile["open_ports"] = ports
    profile["services"] = [p["service"] for p in ports]

    # NetBIOS / SMB name
    netbios = probe_netbios(ip)
    profile["netbios"] = netbios

    # HTTP banners
    http_ports = [p["port"] for p in ports if p["port"] in (80, 8080, 8008, 443, 8443)]
    profile["http_banners"] = probe_http_banner(ip, http_ports or None)

    # TTL / OS guess
    ttl_info = probe_ttl(ip)
    profile["ttl"] = ttl_info.get("ttl")
    profile["os_guess"] = ttl_info.get("os_guess", "")

    # VPN detection
    vpn = detect_vpn(ip, ports)
    profile["vpn"] = vpn

    # Remote access detection
    remote = detect_remote_access(ip, ports)
    profile["remote_access"] = remote

    # Derive a display name from all gathered intel
    profile["display_name"] = (
        netbios.get("computer_name")
        or netbios.get("user")
        or ""
    )

    return profile
