"""Scan history storage (JSON-based, append-only log)."""

import json
from datetime import datetime, timezone
from pathlib import Path

_HISTORY_PATH = Path(__file__).resolve().parent.parent / "data" / "scan_history.json"


def _load_history(filepath=None):
    p = Path(filepath) if filepath else _HISTORY_PATH
    if p.exists():
        return json.loads(p.read_text())
    return []


def _save_history(entries, filepath=None):
    p = Path(filepath) if filepath else _HISTORY_PATH
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(entries, indent=2) + "\n")


def save_scan(scan_results, dns_results=None, filepath=None):
    """Append a timestamped scan entry to the history file.

    Args:
        scan_results: List of device dicts from scanner.scan_network().
        dns_results: Optional DNS check results dict.
        filepath: Override history file path.
    """
    history = _load_history(filepath)
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "device_count": len(scan_results),
        "devices": scan_results,
    }
    if dns_results:
        entry["dns"] = dns_results
    history.append(entry)
    _save_history(history, filepath)


def get_history(filepath=None, last_n=10):
    """Retrieve the most recent scan entries.

    Args:
        filepath: Override history file path.
        last_n: Number of recent entries to return.

    Returns:
        list of scan entry dicts (newest last).
    """
    history = _load_history(filepath)
    return history[-last_n:]
