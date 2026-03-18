"""Tests for weyefi.dns_check — DNS hijack detection logic."""

from unittest.mock import MagicMock, patch

import dns.resolver

from weyefi.dns_check import check_dns_hijack, check_nxdomain_hijack, run_all_dns_checks


def _mock_resolve(answers_map):
    """Create a mock resolver whose resolve() returns IPs from answers_map."""
    def _resolve(domain, rdtype):
        if domain in answers_map:
            return [MagicMock(address=ip) for ip in answers_map[domain]]
        raise dns.resolver.NXDOMAIN()
    return _resolve


class TestCheckDnsHijack:
    @patch("weyefi.dns_check.dns.resolver.Resolver")
    def test_clean_dns(self, mock_resolver_cls):
        # Both resolvers return the same IPs
        instance = MagicMock()
        instance.resolve.side_effect = _mock_resolve({"example.com": ["93.184.216.34"]})
        mock_resolver_cls.return_value = instance

        result = check_dns_hijack("example.com", "8.8.8.8")
        assert result["hijacked"] is False
        assert result["domain"] == "example.com"

    @patch("weyefi.dns_check.dns.resolver.Resolver")
    def test_hijacked_dns(self, mock_resolver_cls):
        resolvers = iter([
            MagicMock(),  # system resolver
            MagicMock(),  # trusted resolver
        ])

        def make_resolver():
            r = next(resolvers)
            return r

        mock_resolver_cls.side_effect = make_resolver

        # System returns bad IP, trusted returns real IP
        sys_r = mock_resolver_cls()
        sys_r.resolve.side_effect = _mock_resolve({"example.com": ["10.0.0.1"]})

        trust_r = mock_resolver_cls()
        trust_r.resolve.side_effect = _mock_resolve({"example.com": ["93.184.216.34"]})

        # Patch to use our specific resolvers
        with patch("weyefi.dns_check.dns.resolver.Resolver") as mock_cls:
            mock_cls.side_effect = [sys_r, trust_r]
            result = check_dns_hijack("example.com", "8.8.8.8")

        assert result["hijacked"] is True


class TestCheckNxdomainHijack:
    @patch("weyefi.dns_check.dns.resolver.Resolver")
    def test_clean_nxdomain(self, mock_resolver_cls):
        instance = MagicMock()
        instance.resolve.side_effect = dns.resolver.NXDOMAIN()
        mock_resolver_cls.return_value = instance

        result = check_nxdomain_hijack("1.1.1.1")
        assert result["hijacked"] is False

    @patch("weyefi.dns_check.dns.resolver.Resolver")
    def test_hijacked_nxdomain(self, mock_resolver_cls):
        instance = MagicMock()
        instance.resolve.return_value = [MagicMock(address="198.51.100.1")]
        mock_resolver_cls.return_value = instance

        result = check_nxdomain_hijack("1.1.1.1")
        assert result["hijacked"] is True
        assert "198.51.100.1" in result["redirected_to"]


class TestRunAllDnsChecks:
    @patch("weyefi.dns_check.check_nxdomain_hijack")
    @patch("weyefi.dns_check.check_dns_hijack")
    def test_runs_all_checks(self, mock_dns, mock_nx):
        mock_dns.return_value = {"domain": "test.com", "hijacked": False, "system_ips": [], "trusted_ips": []}
        mock_nx.return_value = {"hijacked": False, "redirected_to": []}

        manifest = {
            "trusted_dns": ["8.8.8.8"],
            "monitored_domains": ["google.com", "example.com"],
        }
        result = run_all_dns_checks(manifest)

        assert len(result["domain_checks"]) == 2
        assert mock_dns.call_count == 2
        assert mock_nx.call_count == 1
