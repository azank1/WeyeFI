"""DNS hijacking detection — compare system resolver vs. trusted resolvers."""

import uuid

import dns.resolver


def check_dns_hijack(domain, trusted_ns="8.8.8.8"):
    """Check if DNS resolution for a domain differs between system and trusted resolver.

    Returns:
        dict with keys: domain, hijacked (bool), system_ips, trusted_ips.
    """
    try:
        sys_resolver = dns.resolver.Resolver()
        sys_answers = {r.address for r in sys_resolver.resolve(domain, "A")}
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.LifetimeTimeout):
        sys_answers = set()

    try:
        trusted = dns.resolver.Resolver()
        trusted.nameservers = [trusted_ns]
        trusted_answers = {r.address for r in trusted.resolve(domain, "A")}
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.LifetimeTimeout):
        trusted_answers = set()

    return {
        "domain": domain,
        "hijacked": sys_answers != trusted_answers and bool(sys_answers),
        "system_ips": sorted(sys_answers),
        "trusted_ips": sorted(trusted_answers),
    }


def check_nxdomain_hijack(trusted_ns="1.1.1.1"):
    """Detect NXDOMAIN hijacking (ISP redirecting non-existent domains).

    Queries a random UUID domain under .example.invalid which MUST return NXDOMAIN.
    If the system resolver returns an IP, NXDOMAIN hijacking is active.

    Returns:
        dict with keys: hijacked (bool), redirected_to (list of IPs or empty).
    """
    bogus = f"{uuid.uuid4().hex}.example.invalid"
    sys_resolver = dns.resolver.Resolver()

    try:
        answers = sys_resolver.resolve(bogus, "A")
        # Getting an answer means NXDOMAIN is hijacked
        return {
            "hijacked": True,
            "redirected_to": [r.address for r in answers],
        }
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return {"hijacked": False, "redirected_to": []}
    except dns.resolver.LifetimeTimeout:
        return {"hijacked": False, "redirected_to": [], "error": "timeout"}


def run_all_dns_checks(manifest):
    """Run DNS hijack checks for all monitored domains + NXDOMAIN check.

    Args:
        manifest: The manifest dict containing trusted_dns and monitored_domains.

    Returns:
        dict with keys: domain_checks (list), nxdomain_check (dict).
    """
    trusted_dns = manifest.get("trusted_dns", ["8.8.8.8"])
    domains = manifest.get("monitored_domains", ["google.com", "example.com"])
    primary_ns = trusted_dns[0] if trusted_dns else "8.8.8.8"

    domain_checks = [check_dns_hijack(d, primary_ns) for d in domains]
    nxdomain = check_nxdomain_hijack(primary_ns)

    return {"domain_checks": domain_checks, "nxdomain_check": nxdomain}
