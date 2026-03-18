"""WeyeFI CLI — Network Intelligence Dashboard for Termux."""

import argparse
import json
import sys
import time

from . import __version__
from .dns_check import run_all_dns_checks
from .encrypted_dns import (
    DOH_PROVIDERS,
    doh_resolve,
    dns_leak_test,
    get_setup_instructions,
    privacy_audit,
)
from .history import get_history, save_scan
from .mac_lookup import enrich_scan
from .manifest import add_device, diff_devices, load_manifest, save_manifest
from .notifier import send_alert
from .profiler import profile_device
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


def _print_profile(profile):
    """Pretty-print a device profile."""
    ip = profile["ip"]
    print(f"\n{'=' * 60}")
    print(f"  DEVICE PROFILE: {ip}")
    print(f"{'=' * 60}")

    # Identity
    nb = profile.get("netbios", {})
    if nb.get("computer_name"):
        print(f"  Computer Name : {nb['computer_name']}")
    if nb.get("user"):
        print(f"  Username      : {nb['user']}")
    if nb.get("workgroup"):
        print(f"  Workgroup     : {nb['workgroup']}")
    if profile.get("display_name"):
        print(f"  Display Name  : {profile['display_name']}")

    # OS / TTL
    if profile.get("os_guess"):
        print(f"  OS Guess      : {profile['os_guess']}")
    if profile.get("ttl") is not None:
        print(f"  TTL           : {profile['ttl']}")

    # Open ports
    ports = profile.get("open_ports", [])
    if ports:
        print(f"\n  OPEN PORTS ({len(ports)}):")
        for p in ports:
            print(f"    {p['port']:>5}/tcp  {p['service']}")
    else:
        print("\n  No open ports detected.")

    # HTTP banners
    banners = profile.get("http_banners", [])
    if banners:
        print("\n  HTTP BANNERS:")
        for b in banners:
            extra = f" — {b['extra']}" if b.get("extra") else ""
            print(f"    :{b['port']}  {b['server']}{extra}")

    # VPN
    vpn = profile.get("vpn", {})
    if vpn.get("vpn_detected"):
        print("\n  !! VPN / TUNNEL DETECTED:")
        for ind in vpn.get("indicators", []):
            print(f"    - {ind}")
    else:
        print("\n  VPN: Not detected")

    # Remote access
    remote = profile.get("remote_access", {})
    if remote.get("remote_access"):
        print("\n  !! REMOTE ACCESS SERVICES:")
        for svc in remote.get("services", []):
            print(f"    - {svc['service']} (port {svc['port']})")
    else:
        print("  Remote Access: None detected")

    print(f"{'=' * 60}")


def cmd_trace(args):
    """Deep profile a specific device or all devices on the network."""
    manifest = load_manifest(args.manifest)
    subnet = args.subnet or manifest.get("network_subnet", "192.168.1.0/24")

    if args.target:
        # Profile a specific IP
        targets = [args.target]
    else:
        # Scan network first, then profile all found devices
        print(f"Scanning {subnet} to find targets ...")
        devices = scan_network(subnet)
        devices = enrich_scan(devices)
        targets = [d["ip"] for d in devices]
        print(f"Found {len(targets)} devices. Profiling each one ...\n")

    for ip in targets:
        print(f"\nTracing {ip} ...", flush=True)
        profile = profile_device(ip)
        _print_profile(profile)

        # Alert on VPN or remote access
        vpn = profile.get("vpn", {})
        remote = profile.get("remote_access", {})
        alerts = []
        if vpn.get("vpn_detected"):
            alerts.append(f"VPN detected on {ip}")
        if remote.get("remote_access"):
            svc_names = [s["service"] for s in remote.get("services", [])]
            alerts.append(f"Remote access on {ip}: {', '.join(svc_names)}")
        if alerts:
            send_alert("WeyeFI Trace Alert", "; ".join(alerts))


def _print_privacy_audit(audit):
    """Pretty-print privacy audit results."""
    print(f"\n{'=' * 60}")
    print("  PRIVACY AUDIT")
    print(f"{'=' * 60}")

    dns_list = audit.get("system_dns", [])
    print(f"  System DNS   : {', '.join(dns_list) if dns_list else 'Unknown'}")
    enc = "YES" if audit.get("dns_encrypted") else "NO"
    enc_icon = "ok" if audit.get("dns_encrypted") else "!!"
    print(f"  DNS Encrypted: [{enc_icon}] {enc}")

    isp = "NO" if not audit.get("isp_can_see_queries") else "YES"
    isp_icon = "ok" if not audit.get("isp_can_see_queries") else "!!"
    print(f"  ISP Can Snoop: [{isp_icon}] {isp}")

    leak = audit.get("dns_leak", False)
    leak_icon = "!!" if leak else "ok"
    print(f"  DNS Leak     : [{leak_icon}] {'DETECTED' if leak else 'None'}")

    recs = audit.get("recommendations", [])
    if recs:
        print(f"\n  RECOMMENDATIONS:")
        for r in recs:
            print(f"    > {r}")

    print(f"{'=' * 60}")


def cmd_privacy(args):
    """Run privacy audit on this device."""
    print("Running privacy audit ...")
    audit = privacy_audit()
    _print_privacy_audit(audit)

    if args.setup:
        provider = args.provider or "cloudflare"
        inst = get_setup_instructions(provider)
        print(f"\n{'=' * 60}")
        print(f"  SETUP: {inst['provider']}")
        print(f"  Privacy: {inst['privacy_policy']}")
        print(f"{'=' * 60}")
        for method_key, method in inst["methods"].items():
            print(f"\n  [{method['name']}]")
            print(f"  Covers: {method['covers']}")
            for i, step in enumerate(method["steps"], 1):
                print(f"    {i}. {step}")
        print(f"{'=' * 60}")


def cmd_doh_resolve(args):
    """Resolve a domain using encrypted DNS-over-HTTPS."""
    domain = args.domain
    provider = args.provider or "cloudflare"

    print(f"Resolving {domain} via DoH ({provider}) ...")
    result = doh_resolve(domain, provider)

    print(f"\n  Domain   : {result['domain']}")
    print(f"  Provider : {result['provider']}")
    print(f"  Encrypted: {'YES' if result['encrypted'] else 'NO'}")
    if result.get("error"):
        print(f"  Error    : {result['error']}")
    elif result["ips"]:
        print(f"  IPs      : {', '.join(result['ips'])}")
        print(f"  TTL      : {result['ttl']}s")
    else:
        print(f"  IPs      : (none)")

    if args.compare:
        print(f"\n  Comparing with system DNS ...")
        try:
            import dns.resolver
            sys_r = dns.resolver.Resolver()
            sys_ips = sorted({r.address for r in sys_r.resolve(domain, "A")})
            print(f"  System DNS: {', '.join(sys_ips)}")
            doh_ips = sorted(result.get("ips", []))
            if sys_ips == doh_ips:
                print(f"  [ok] Results match — no DNS tampering detected")
            else:
                print(f"  [!!] MISMATCH — possible DNS tampering or CDN difference")
        except Exception as e:
            print(f"  System DNS: Error ({e})")


def cmd_leak_test(args):
    """Run DNS leak test across all DoH providers."""
    print("Running DNS leak test ...")
    results = dns_leak_test()
    print(f"\n{'=' * 60}")
    print("  DNS LEAK TEST")
    print(f"{'=' * 60}")
    for name in DOH_PROVIDERS:
        if name in results:
            r = results[name]
            icon = "ok" if r.get("match") else ("!!" if r.get("match") is False else "??")
            print(f"  [{icon}] {DOH_PROVIDERS[name]['name']}")
            print(f"       DoH IPs   : {', '.join(r['doh_ips'])}")
            print(f"       System IPs: {', '.join(r['system_ips'])}")
    print(f"{'=' * 60}")


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

    # trace
    p_trace = subparsers.add_parser(
        "trace", help="Deep profile devices: ports, names, VPN, remote access"
    )
    p_trace.add_argument(
        "target", nargs="?", default=None,
        help="IP address to profile (omit to profile all devices)",
    )

    # privacy
    p_privacy = subparsers.add_parser("privacy", help="Audit DNS privacy of this device")
    p_privacy.add_argument(
        "--setup", action="store_true",
        help="Show setup instructions for encrypted DNS",
    )
    p_privacy.add_argument(
        "--provider", choices=list(DOH_PROVIDERS.keys()), default=None,
        help="DoH provider for setup instructions (default: cloudflare)",
    )

    # doh-resolve
    p_doh = subparsers.add_parser("doh-resolve", help="Resolve a domain via encrypted DoH")
    p_doh.add_argument("domain", help="Domain to resolve")
    p_doh.add_argument(
        "--provider", choices=list(DOH_PROVIDERS.keys()), default="cloudflare",
        help="DoH provider (default: cloudflare)",
    )
    p_doh.add_argument(
        "--compare", action="store_true",
        help="Compare DoH results with system DNS",
    )

    # leak-test
    subparsers.add_parser("leak-test", help="Test for DNS leaks across providers")

    args = parser.parse_args()

    commands = {
        "scan": cmd_scan,
        "dns-check": cmd_dns_check,
        "history": cmd_history,
        "manifest-add": cmd_manifest_add,
        "watch": cmd_watch,
        "trace": cmd_trace,
        "privacy": cmd_privacy,
        "doh-resolve": cmd_doh_resolve,
        "leak-test": cmd_leak_test,
    }

    if args.command in commands:
        commands[args.command](args)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
