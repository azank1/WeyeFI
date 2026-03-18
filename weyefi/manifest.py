"""Load and diff the known-good device manifest."""

import json
from datetime import datetime, timezone
from pathlib import Path

_DEFAULT_MANIFEST = Path(__file__).resolve().parent.parent / "config" / "manifest.json"


def load_manifest(path=None):
    """Load the manifest JSON file.

    Returns:
        dict with keys: known_devices, trusted_dns, monitored_domains, network_subnet.
    """
    p = Path(path) if path else _DEFAULT_MANIFEST
    if not p.exists():
        return {
            "known_devices": [],
            "trusted_dns": ["8.8.8.8", "1.1.1.1"],
            "monitored_domains": ["google.com", "example.com"],
            "network_subnet": "192.168.1.0/24",
        }
    return json.loads(p.read_text())


def save_manifest(manifest, path=None):
    """Write the manifest back to disk."""
    p = Path(path) if path else _DEFAULT_MANIFEST
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(manifest, indent=2) + "\n")


def diff_devices(scan_results, manifest):
    """Compare scan results against the known-good manifest.

    Returns:
        dict with keys:
            known   — devices in both scan and manifest
            new     — devices in scan but NOT in manifest (potential intruders)
            missing — devices in manifest but NOT in scan (offline / removed)
    """
    known_macs = {
        d["mac"].upper() for d in manifest.get("known_devices", []) if d.get("mac")
    }
    scanned_macs = {d["mac"].upper() for d in scan_results if d.get("mac")}

    known = [d for d in scan_results if d.get("mac", "").upper() in known_macs]
    new = [d for d in scan_results if d.get("mac") and d["mac"].upper() not in known_macs]
    missing = [
        d for d in manifest.get("known_devices", [])
        if d.get("mac", "").upper() not in scanned_macs
    ]

    return {"known": known, "new": new, "missing": missing}


def add_device(manifest, device, name=None):
    """Add a device to the manifest's known_devices list.

    Args:
        manifest: The manifest dict (mutated in place).
        device: A scan result dict with at least 'mac' and 'ip'.
        name: Optional friendly name for the device.
    """
    entry = {
        "mac": device["mac"].upper(),
        "name": name or device.get("hostname") or device["ip"],
        "vendor": device.get("vendor", "Unknown"),
        "first_seen": datetime.now(timezone.utc).isoformat(),
    }
    # Don't add duplicates
    existing_macs = {d["mac"].upper() for d in manifest.get("known_devices", [])}
    if entry["mac"] not in existing_macs:
        manifest.setdefault("known_devices", []).append(entry)
    return manifest
