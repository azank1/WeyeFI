"""Termux notification wrapper with graceful fallback for non-Termux environments."""

import shutil
import subprocess
import sys


def _in_termux():
    """Check if we're running inside Termux."""
    return shutil.which("termux-notification") is not None


def send_alert(title, message, priority="high"):
    """Send an alert notification.

    On Termux: uses termux-notification with vibration.
    Elsewhere: prints to stderr as fallback.
    """
    if _in_termux():
        cmd = [
            "termux-notification",
            "--id", "weyefi",
            "--title", title,
            "--content", message,
            "--priority", priority,
            "--vibrate", "250,250,250",
        ]
        subprocess.run(cmd, timeout=10, check=False)
    else:
        print(f"[ALERT] {title}: {message}", file=sys.stderr)


def clear_alert():
    """Remove the WeyeFI notification (Termux only)."""
    if _in_termux():
        subprocess.run(
            ["termux-notification-remove", "weyefi"], timeout=10, check=False
        )
