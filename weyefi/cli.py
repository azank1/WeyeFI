"""WeyeFI CLI — Network Intelligence Dashboard for Termux."""

import argparse
import json
import sys
import time

from . import __version__
from .dns_check import run_all_dns_checks
from .history import get_history, save_scan
from .mac_lookup import enrich_scan
from .manifest import add_device, diff_devices, load_manifest, save_manifest
from .notifier import send_alert
from .scanner import scan_network


def _print_devices(devices, header="Devices"):
    print(f"\n{'=' * 60}")
    print(f"  {header}  ({len(devices)} found)")
    print(f"{'=' * 60}")
    for d in devices:
        vendor = d.get("vendor", "")
        name = d.get("hostname") or d.get("name") or ""
        dtype = d.get("device_type", "")
        parts = [d["ip"]]
        if d.get("mac"):
            parts.append(d["mac"])
        if vendor and vendor != "Unknown":
            parts.append(f"[{vendor}]")
        if dtype:
            parts.append(f"<{dtype}>")
        if name:
            parts.append(f"({name})")
        print(f"  {' | '.join(parts)}")
    if not devices:
        print("  (none)")


def _print_dns(results):
    print(f"\n{'=' * 60}")
    print("  DNS Hijack Check")
    print(f"{'=' * 60}")
    for chk in results.get("domain_checks", []):
        status = "HIJACKED" if chk["hijacked"] else "OK"
        icon = "!!" if chk["hijacked"] else "ok"
        print(f"  [{icon}] {chk['domain']}: {status}")
        if chk["hijacked"]:
            print(f"       System:  {chk['system_ips']}")
            print(f"       Trusted: {chk['trusted_ips']}")
    nx = results.get("nxdomain_check", {})
    nx_status = "HIJACKED" if nx.get("hijacked") else "OK"
    nx_icon = "!!" if nx.get("hijacked") else "ok"
    print(f"  [{nx_icon}] NXDOMAIN redirect: {nx_status}")
    if nx.get("redirected_to"):
        print(f"       Redirected to: {nx['redirected_to']}")


def cmd_scan(args):
    manifest = load_manifest(args.manifest)
    subnet = args.subnet or manifest.get("network_subnet", "192.168.1.0/24")

    print(f"Scanning {subnet} ...")
    devices = scan_network(subnet)
    devices = enrich_scan(devices)

    _print_devices(devices, "Network Scan Results")

    if args.diff:
        result = diff_devices(devices, manifest)
        if result["new"]:
            _print_devices(result["new"], "NEW / UNKNOWN Devices")
            msg = ", ".join(
                f"{d['ip']} ({d.get('mac', '?')})" for d in result["new"]
            )
            send_alert("Unknown Device Detected", msg)
        else:
            print("\n  All devices are known. Network looks clean.")
        if result["missing"]:
            _print_devices(result["missing"], "MISSING Devices (in manifest but offline)")

    save_scan(devices)
    print(f"\nScan saved to history. ({len(devices)} devices)")


def cmd_dns_check(args):
    manifest = load_manifest(args.manifest)
    print("Running DNS hijack checks ...")
    results = run_all_dns_checks(manifest)
    _print_dns(results)

    hijacked = [c for c in results["domain_checks"] if c["hijacked"]]
    if hijacked or results["nxdomain_check"].get("hijacked"):
        names = [c["domain"] for c in hijacked]
        if results["nxdomain_check"].get("hijacked"):
            names.append("NXDOMAIN")
        send_alert("DNS Hijacking Detected", f"Affected: {', '.join(names)}")


def cmd_history(args):
    entries = get_history(last_n=args.count)
    if not entries:
        print("No scan history yet.")
        return
    for entry in entries:
        ts = entry.get("timestamp", "?")
        count = entry.get("device_count", 0)
        print(f"\n[{ts}] — {count} devices")
        for d in entry.get("devices", []):
            mac = d.get("mac", "")
            vendor = d.get("vendor", "")
            line = f"  {d['ip']}"
            if mac:
                line += f" | {mac}"
            if vendor and vendor != "Unknown":
                line += f" [{vendor}]"
            print(line)


def cmd_manifest_add(args):
    manifest = load_manifest(args.manifest)
    subnet = args.subnet or manifest.get("network_subnet", "192.168.1.0/24")

    print(f"Scanning {subnet} to discover devices ...")
    devices = scan_network(subnet)
    devices = enrich_scan(devices)

    result = diff_devices(devices, manifest)
    if not result["new"]:
        print("No new devices found. Manifest is up to date.")
        return

    _print_devices(result["new"], "New Devices Found")
    for device in result["new"]:
        vendor = device.get("vendor", "Unknown")
        prompt = (
            f"\nAdd {device['ip']} | {device.get('mac', '?')} [{vendor}]? "
            f"Enter name (or skip): "
        )
        try:
            name = input(prompt).strip()
        except (EOFError, KeyboardInterrupt):
            print("\nAborted.")
            return
        if name.lower() == "skip" or name == "":
            continue
        add_device(manifest, device, name)
        print(f"  Added as '{name}'")

    save_manifest(manifest, args.manifest)
    print(f"\nManifest updated ({len(manifest['known_devices'])} devices).")


def cmd_watch(args):
    manifest = load_manifest(args.manifest)
    subnet = args.subnet or manifest.get("network_subnet", "192.168.1.0/24")
    interval = args.interval

    print(f"Watch mode: scanning {subnet} every {interval}s  (Ctrl+C to stop)")
    try:
        while True:
            devices = scan_network(subnet)
            devices = enrich_scan(devices)
            result = diff_devices(devices, manifest)

            ts = time.strftime("%H:%M:%S")
            new_count = len(result["new"])
            print(f"[{ts}] {len(devices)} devices | {new_count} unknown", flush=True)

            if result["new"]:
                for d in result["new"]:
                    print(f"  !! {d['ip']} | {d.get('mac', '?')} [{d.get('vendor', '?')}]")
                msg = ", ".join(
                    f"{d['ip']} ({d.get('mac', '?')})" for d in result["new"]
                )
                send_alert("Unknown Device Detected", msg)

            save_scan(devices)
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\nWatch stopped.")


def main():
    parser = argparse.ArgumentParser(
        prog="weyefi",
        description="WeyeFI — Keep eye on your WiFi",
    )
    parser.add_argument(
        "-V", "--version", action="version", version=f"%(prog)s {__version__}"
    )
    parser.add_argument(
        "-m", "--manifest", default=None,
        help="Path to manifest.json (default: config/manifest.json)",
    )
    parser.add_argument(
        "-s", "--subnet", default=None,
        help="Network subnet to scan (overrides manifest setting)",
    )
    subparsers = parser.add_subparsers(dest="command")

    # scan
    p_scan = subparsers.add_parser("scan", help="Scan the network for devices")
    p_scan.add_argument(
        "-d", "--diff", action="store_true",
        help="Compare scan results against the known-good manifest",
    )

    # dns-check
    subparsers.add_parser("dns-check", help="Check for DNS hijacking")

    # history
    p_hist = subparsers.add_parser("history", help="Show scan history")
    p_hist.add_argument(
        "-n", "--count", type=int, default=10,
        help="Number of recent scans to show (default: 10)",
    )

    # manifest add
    subparsers.add_parser("manifest-add", help="Add new devices to the manifest")

    # watch
    p_watch = subparsers.add_parser("watch", help="Continuous monitoring mode")
    p_watch.add_argument(
        "-i", "--interval", type=int, default=300,
        help="Seconds between scans (default: 300)",
    )

    args = parser.parse_args()

    commands = {
        "scan": cmd_scan,
        "dns-check": cmd_dns_check,
        "history": cmd_history,
        "manifest-add": cmd_manifest_add,
        "watch": cmd_watch,
    }

    if args.command in commands:
        commands[args.command](args)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
