# WeyeFI

**Keep eye on your WiFi** — A network intelligence CLI tool built for Termux on Android.

Scan your local network, identify every connected device, detect DNS hijacking, and get instant alerts when an unknown device appears.

---

## Features

- **Network Scanner** — Discover all devices on your WiFi (IP, MAC, vendor, hostname)
- **Known-Good Manifest** — Track trusted devices in a Git-versioned JSON file
- **Intruder Detection** — Instantly flag unknown MACs that aren't in your manifest
- **DNS Hijack Detection** — Compare your ISP's DNS answers against trusted resolvers (Google, Cloudflare)
- **NXDOMAIN Hijack Check** — Detect if non-existent domains are being redirected
- **Termux Notifications** — Push alerts with vibration directly on your Galaxy Tab
- **Scan History** — JSON log of every scan for trending and forensics
- **Watch Mode** — Continuous monitoring loop with configurable interval

## Root vs. No-Root

| Feature | No Root | Root |
|---|---|---|
| Host discovery (TCP connect) | Yes | Yes |
| Host discovery (ARP) | No | Yes |
| MAC addresses via `/proc/net/arp` | **Yes** | Yes |
| MAC addresses via nmap | No | Yes |
| DNS hijack detection | Yes | Yes |
| Termux notifications | Yes | Yes |

> The tool is designed to work **without root** by combining nmap host discovery with the system ARP cache.

---

## Termux Setup (Galaxy Tab)

```bash
# 1. Install packages
pkg update && pkg upgrade
pkg install nmap python termux-api dnsutils net-tools

# 2. Install the Termux:API companion app
#    (from F-Droid or GitHub — required for notifications)

# 3. Clone the repo
git clone https://github.com/azank1/WeyeFI.git
cd WeyeFI

# 4. Install Python dependencies
pip install -r requirements.txt
```

---

## Usage

```bash
# Scan the network and list all devices
python -m weyefi scan

# Scan and compare against your known-good manifest
python -m weyefi scan --diff

# Check for DNS hijacking
python -m weyefi dns-check

# Show recent scan history
python -m weyefi history
python -m weyefi history -n 5

# Interactively add new devices to the manifest
python -m weyefi manifest-add

# Continuous monitoring (scan every 5 minutes)
python -m weyefi watch
python -m weyefi watch --interval 120
```

### Options

```
-s, --subnet    Override network subnet (e.g. 192.168.0.0/24)
-m, --manifest  Path to a custom manifest.json
-V, --version   Show version
```

---

## Configuration

Edit `config/manifest.json` to set your network and trusted devices:

```json
{
  "known_devices": [
    {
      "mac": "AA:BB:CC:DD:EE:FF",
      "name": "My Router",
      "vendor": "Netgear",
      "first_seen": "2026-01-15T10:30:00Z"
    }
  ],
  "trusted_dns": ["8.8.8.8", "1.1.1.1"],
  "monitored_domains": ["google.com", "example.com"],
  "network_subnet": "192.168.1.0/24"
}
```

- **known_devices** — Your trusted devices (added via `manifest-add` or manually)
- **trusted_dns** — Resolvers used as ground truth for DNS hijack checks
- **monitored_domains** — Domains checked for DNS tampering
- **network_subnet** — Default subnet to scan

---

## Project Structure

```
WeyeFI/
├── config/
│   └── manifest.json      # Known-good device list & settings
├── data/                   # Runtime data (gitignored)
├── weyefi/
│   ├── __init__.py
│   ├── __main__.py         # python -m weyefi entry point
│   ├── cli.py              # Argparse CLI with subcommands
│   ├── scanner.py          # nmap + /proc/net/arp merge
│   ├── mac_lookup.py       # MACVendors API + local OUI cache
│   ├── manifest.py         # Load/diff known-good devices
│   ├── dns_check.py        # DNS hijack detection
│   ├── notifier.py         # Termux notification wrapper
│   └── history.py          # Scan history (JSON log)
├── tests/
│   ├── test_scanner.py
│   ├── test_dns_check.py
│   └── test_manifest.py
├── requirements.txt
└── .gitignore
```

---

## How It Works

1. **`scan`** runs `nmap -sn` to ping-sweep the subnet, then reads `/proc/net/arp` for MAC addresses (no root needed)
2. **`--diff`** compares discovered MACs against `config/manifest.json` and classifies each device as **known**, **new**, or **missing**
3. **Unknown devices** trigger a `termux-notification` alert with vibration
4. **`dns-check`** queries each monitored domain via your system resolver AND a trusted resolver, flagging mismatches as potential hijacking
5. **`watch`** loops steps 1-3 on a timer for continuous monitoring

---

## License

MIT
