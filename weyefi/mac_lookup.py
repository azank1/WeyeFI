"""MAC address vendor lookup with local caching."""

import json
import time
from pathlib import Path
from urllib.parse import quote

import requests

_CACHE_PATH = Path(__file__).resolve().parent.parent / "data" / "oui_cache.json"
_API_URL = "https://api.macvendors.com/"
_RATE_LIMIT_DELAY = 1.1  # seconds between API calls (free tier: 1 req/s)


def _load_cache():
    if _CACHE_PATH.exists():
        return json.loads(_CACHE_PATH.read_text())
    return {}


def _save_cache(cache):
    _CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    _CACHE_PATH.write_text(json.dumps(cache, indent=2))


def _oui_prefix(mac):
    """Extract the first 3 octets (OUI) from a MAC address."""
    cleaned = mac.upper().replace("-", ":").replace(".", ":")
    parts = cleaned.split(":")
    if len(parts) >= 3:
        return ":".join(parts[:3])
    return cleaned


def lookup_vendor(mac):
    """Look up the vendor for a MAC address.

    Checks local cache first, then queries the MACVendors API.
    Returns the vendor string or "Unknown".
    """
    if not mac:
        return "Unknown"

    oui = _oui_prefix(mac)
    cache = _load_cache()

    if oui in cache:
        return cache[oui]

    try:
        resp = requests.get(
            _API_URL + quote(mac, safe=""),
            timeout=5,
            headers={"User-Agent": "WeyeFI/0.1"},
        )
        if resp.status_code == 200:
            vendor = resp.text.strip()
            cache[oui] = vendor
            _save_cache(cache)
            return vendor
        if resp.status_code == 404:
            cache[oui] = "Unknown"
            _save_cache(cache)
            return "Unknown"
        # 429 Too Many Requests — don't cache, just return unknown
        return "Unknown"
    except requests.RequestException:
        return "Unknown"


def enrich_scan(devices):
    """Add vendor and device_type information to a list of scanned devices.

    Respects the MACVendors free-tier rate limit (1 req/s).
    """
    from .scanner import _guess_device_type

    cache = _load_cache()
    uncached_count = 0

    for device in devices:
        mac = device.get("mac", "")
        if not mac:
            device["vendor"] = "Unknown"
        else:
            oui = _oui_prefix(mac)
            if oui in cache:
                device["vendor"] = cache[oui]
            else:
                # Rate-limit API calls
                if uncached_count > 0:
                    time.sleep(_RATE_LIMIT_DELAY)
                device["vendor"] = lookup_vendor(mac)
                uncached_count += 1

        # Guess device type from hostname + vendor
        device["device_type"] = _guess_device_type(
            device.get("hostname", ""), device.get("vendor", "")
        )

    return devices
