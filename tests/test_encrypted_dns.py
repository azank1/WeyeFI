"""Tests for weyefi.encrypted_dns — DoH resolution and privacy audit."""

from unittest.mock import MagicMock, patch

from weyefi.encrypted_dns import (
    DOH_PROVIDERS,
    doh_resolve,
    get_setup_instructions,
)


class TestDohResolve:
    @patch("weyefi.encrypted_dns.requests.get")
    def test_successful_resolve(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "Answer": [
                {"type": 1, "data": "93.184.216.34", "TTL": 300},
            ]
        }
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        result = doh_resolve("example.com", "cloudflare")
        assert result["encrypted"] is True
        assert result["ips"] == ["93.184.216.34"]
        assert result["provider"] == "Cloudflare 1.1.1.1"

    @patch("weyefi.encrypted_dns.requests.get")
    def test_failed_resolve(self, mock_get):
        import requests

        mock_get.side_effect = requests.RequestException("timeout")

        result = doh_resolve("example.com", "cloudflare")
        assert result["encrypted"] is True
        assert result["ips"] == []
        assert "error" in result

    @patch("weyefi.encrypted_dns.requests.get")
    def test_google_provider(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "Answer": [{"type": 1, "data": "1.2.3.4", "TTL": 60}]
        }
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        result = doh_resolve("test.com", "google")
        assert result["provider"] == "Google DNS"
        mock_get.assert_called_once()
        assert "dns.google" in mock_get.call_args[0][0]

    @patch("weyefi.encrypted_dns.requests.get")
    def test_unknown_provider_falls_back_to_cloudflare(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"Answer": []}
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        result = doh_resolve("test.com", "nonexistent")
        assert result["provider"] == "Cloudflare 1.1.1.1"


class TestDohProviders:
    def test_all_providers_have_required_keys(self):
        for name, prov in DOH_PROVIDERS.items():
            assert "url" in prov, f"{name} missing url"
            assert "name" in prov, f"{name} missing name"
            assert "ip" in prov, f"{name} missing ip"
            assert "privacy" in prov, f"{name} missing privacy"
            assert prov["url"].startswith("https://"), f"{name} url not HTTPS"


class TestSetupInstructions:
    def test_cloudflare_instructions(self):
        inst = get_setup_instructions("cloudflare")
        assert inst["provider"] == "Cloudflare 1.1.1.1"
        assert "android_private_dns" in inst["methods"]
        steps = inst["methods"]["android_private_dns"]["steps"]
        assert any("one.one.one.one" in s for s in steps)

    def test_google_instructions(self):
        inst = get_setup_instructions("google")
        assert inst["provider"] == "Google DNS"
        steps = inst["methods"]["android_private_dns"]["steps"]
        assert any("dns.google" in s for s in steps)
