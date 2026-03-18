"""Encrypted Shadow — DNS privacy and traffic encryption tools.

Provides:
  - DNS-over-HTTPS (DoH) query engine — bypass plaintext DNS snooping
  - Privacy audit — check if your current DNS is encrypted
  - DoH configuration helpers for Termux / Android
  - DNS leak detection — verify no plaintext DNS escapes
"""

import re
import subprocess

import dns.resolver
import requests

# Well-known DoH (DNS-over-HTTPS) endpoints — all free, no account needed
DOH_PROVIDERS = {
    "cloudflare": {
        "url": "https://cloudflare-dns.com/dns-query",
        "name": "Cloudflare 1.1.1.1",
        "ip": "1.1.1.1",
        "privacy": "Logs purged within 24h, audited by KPMG",
    },
    "google": {
        "url": "https://dns.google/dns-query",
        "name": "Google DNS",
        "ip": "8.8.8.8",
        "privacy": "Logs anonymized within 48h",
    },
    "quad9": {
        "url": "https://dns.quad9.net:5053/dns-query",
        "name": "Quad9 (malware blocking)",
        "ip": "9.9.9.9",
        "privacy": "No logging, Swiss jurisdiction, blocks malware domains",
    },
    "mullvad": {
        "url": "https://dns.mullvad.net/dns-query",
        "name": "Mullvad DNS",
        "ip": "194.242.2.2",
        "privacy": "No logging, Swedish jurisdiction, ad blocking available",
    },
}


def doh_resolve(domain, provider="cloudflare", record_type="A"):
    """Resolve a domain using DNS-over-HTTPS (encrypted DNS).

    Your ISP sees an HTTPS connection to the DoH provider but CANNOT see
    which domain you're looking up — the query is encrypted inside TLS.
    """
    prov = DOH_PROVIDERS.get(provider, DOH_PROVIDERS["cloudflare"])

    try:
        resp = requests.get(
            prov["url"],
            params={"name": domain, "type": record_type},
            headers={
                "Accept": "application/dns-json",
                "User-Agent": "WeyeFI/0.1",
            },
            timeout=5,
        )
        resp.raise_for_status()
        data = resp.json()

        ips = []
        ttl = 0
        for answer in data.get("Answer", []):
            if answer.get("type") in (1, 28):  # A or AAAA
                ips.append(answer["data"])
                ttl = answer.get("TTL", 0)

        return {
            "domain": domain,
            "ips": ips,
            "ttl": ttl,
            "provider": prov["name"],
            "encrypted": True,
        }
    except requests.RequestException as e:
        return {
            "domain": domain,
            "ips": [],
            "ttl": 0,
            "provider": prov["name"],
            "encrypted": True,
            "error": str(e),
        }


def privacy_audit():
    """Check the current DNS privacy state of this device.

    Detects system DNS servers, checks encryption status,
    and compares system vs DoH resolution for leak detection.
    """
    results = {
        "system_dns": [],
        "dns_encrypted": False,
        "isp_can_see_queries": True,
        "recommendations": [],
    }

    # 1. Detect system DNS servers (Android first, then resolv.conf)
    try:
        out = subprocess.run(
            ["getprop", "net.dns1"], capture_output=True, text=True, timeout=5
        ).stdout.strip()
        if out:
            results["system_dns"].append(out)
        out2 = subprocess.run(
            ["getprop", "net.dns2"], capture_output=True, text=True, timeout=5
        ).stdout.strip()
        if out2:
            results["system_dns"].append(out2)
    except FileNotFoundError:
        pass

    if not results["system_dns"]:
        try:
            with open("/etc/resolv.conf") as f:
                for line in f:
                    m = re.match(r"nameserver\s+(\S+)", line)
                    if m:
                        results["system_dns"].append(m.group(1))
        except (FileNotFoundError, PermissionError):
            pass

    # 2. Check if system DNS is a known encrypted provider
    encrypted_ips = {
        "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4",
        "9.9.9.9", "149.112.112.112", "194.242.2.2",
    }
    if any(ip in encrypted_ips for ip in results["system_dns"]):
        results["recommendations"].append(
            "Your DNS server supports DoH/DoT, but you should enable Private DNS "
            "in Android settings to ensure encryption."
        )

    # 3. Check Android Private DNS setting (DoT)
    try:
        mode = subprocess.run(
            ["settings", "get", "global", "private_dns_mode"],
            capture_output=True, text=True, timeout=5,
        ).stdout.strip()
        if mode in ("hostname", "opportunistic"):
            results["dns_encrypted"] = True
            results["isp_can_see_queries"] = False
        elif mode == "off":
            results["dns_encrypted"] = False
            results["recommendations"].append(
                "Enable Private DNS: Settings > Network > Private DNS > "
                "Set to 'one.one.one.one' (Cloudflare) or 'dns.google'"
            )
    except FileNotFoundError:
        results["recommendations"].append(
            "Set DNS-over-HTTPS in your browser: "
            "Chrome > Settings > Privacy > Use Secure DNS > Cloudflare (1.1.1.1)"
        )

    # 4. Check for DNS leaks — compare system vs DoH resolution
    test_domain = "cloudflare.com"
    try:
        sys_resolver = dns.resolver.Resolver()
        sys_ips = {r.address for r in sys_resolver.resolve(test_domain, "A")}
    except Exception:
        sys_ips = set()

    doh_result = doh_resolve(test_domain, "cloudflare")
    doh_ips = set(doh_result.get("ips", []))

    if sys_ips and doh_ips and sys_ips != doh_ips:
        results["dns_leak"] = True
        results["recommendations"].append(
            "DNS LEAK: System resolver returns different IPs than encrypted DNS. "
            "Your ISP may be injecting or redirecting DNS responses."
        )
    else:
        results["dns_leak"] = False

    if results["isp_can_see_queries"]:
        results["recommendations"].insert(
            0, "YOUR DNS IS NOT ENCRYPTED. Your ISP can see every domain you visit."
        )

    return results


def dns_leak_test():
    """Resolve example.com via system resolver vs each DoH provider.

    If system resolution differs, may indicate ISP interference.
    """
    results = {"leaks": [], "clean": True}

    for name in DOH_PROVIDERS:
        doh = doh_resolve("example.com", name)
        try:
            sys_r = dns.resolver.Resolver()
            sys_ips = {r.address for r in sys_r.resolve("example.com", "A")}
        except Exception:
            sys_ips = set()

        doh_ips = set(doh.get("ips", []))
        match = sys_ips == doh_ips if (sys_ips and doh_ips) else None

        results[name] = {
            "doh_ips": sorted(doh_ips),
            "system_ips": sorted(sys_ips),
            "match": match,
        }

    return results


def get_setup_instructions(provider="cloudflare"):
    """Get step-by-step instructions to enable encrypted DNS on Android/Termux."""
    prov = DOH_PROVIDERS.get(provider, DOH_PROVIDERS["cloudflare"])

    hostnames = {
        "cloudflare": "one.one.one.one",
        "google": "dns.google",
        "quad9": "dns.quad9.net",
        "mullvad": "dns.mullvad.net",
    }
    hostname = hostnames.get(provider, "one.one.one.one")

    return {
        "provider": prov["name"],
        "privacy_policy": prov["privacy"],
        "methods": {
            "android_private_dns": {
                "name": "Android Private DNS (DoT) — Easiest",
                "steps": [
                    "Open Settings on your device",
                    "Go to Network & Internet > Private DNS",
                    "Select 'Private DNS provider hostname'",
                    f"Enter: {hostname}",
                    "Tap Save",
                    "All DNS queries on this device are now encrypted",
                ],
                "covers": "All apps and browsers on this device",
            },
            "browser_doh": {
                "name": "Browser DNS-over-HTTPS — Per-browser",
                "steps": [
                    "Open Chrome/Firefox/Brave",
                    "Go to Settings > Privacy & Security > Use Secure DNS",
                    f"Select {prov['name']} or enter: {prov['url']}",
                    "Browser DNS is now encrypted (other apps still use plaintext)",
                ],
                "covers": "Only this browser",
            },
            "termux_doh": {
                "name": "Termux DNS override — For scripts only",
                "steps": [
                    "In Termux, your scripts can use DoH directly via WeyeFI:",
                    "  python -m weyefi doh-resolve example.com",
                    "This bypasses the system DNS entirely for that query",
                    f"Uses {prov['name']} ({prov['url']})",
                ],
                "covers": "WeyeFI commands only",
            },
        },
    }
