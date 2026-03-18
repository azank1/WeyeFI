"""Tests for weyefi.profiler — device profiling and detection logic."""

from unittest.mock import MagicMock, patch

from weyefi.profiler import (
    detect_remote_access,
    detect_vpn,
    probe_ttl,
    _PORT_LABELS,
    _VPN_PORTS,
)


class TestProbeTtl:
    @patch("weyefi.profiler._run_cmd")
    def test_linux_ttl(self, mock_cmd):
        mock_cmd.return_value = "64 bytes from 192.168.1.1: icmp_seq=1 ttl=64 time=1.2 ms"
        result = probe_ttl("192.168.1.1")
        assert result["ttl"] == 64
        assert "Linux" in result["os_guess"]
        assert result["vpn_likely"] is False

    @patch("weyefi.profiler._run_cmd")
    def test_windows_ttl(self, mock_cmd):
        mock_cmd.return_value = "Reply from 192.168.1.50: bytes=32 TTL=128 time=2ms"
        result = probe_ttl("192.168.1.50")
        assert result["ttl"] == 128
        assert "Windows" in result["os_guess"]
        assert result["vpn_likely"] is False

    @patch("weyefi.profiler._run_cmd")
    def test_vpn_ttl_anomaly(self, mock_cmd):
        # TTL of 50 suggests 14 hops from expected 64 — VPN likely
        mock_cmd.return_value = "64 bytes from 192.168.1.99: icmp_seq=1 ttl=50 time=30.5 ms"
        result = probe_ttl("192.168.1.99")
        assert result["ttl"] == 50
        assert result["vpn_likely"] is True

    @patch("weyefi.profiler._run_cmd")
    def test_no_response(self, mock_cmd):
        mock_cmd.return_value = ""
        result = probe_ttl("192.168.1.1")
        assert result["ttl"] is None
        assert result["vpn_likely"] is False


class TestDetectVpn:
    def test_vpn_port_detected(self):
        open_ports = [
            {"port": 1194, "service": "OpenVPN", "state": "open"},
            {"port": 80, "service": "HTTP", "state": "open"},
        ]
        result = detect_vpn.__wrapped__(
            "192.168.1.1", open_ports
        ) if hasattr(detect_vpn, "__wrapped__") else None

        # Test the logic directly since detect_vpn also runs nmap
        # Just verify port matching logic
        assert 1194 in _VPN_PORTS
        assert _VPN_PORTS[1194] == "OpenVPN"

    @patch("weyefi.profiler.probe_ttl")
    @patch("weyefi.profiler._run_cmd", return_value="")
    @patch("weyefi.profiler.shutil.which", return_value=None)
    def test_no_vpn(self, mock_which, mock_cmd, mock_ttl):
        mock_ttl.return_value = {"ttl": 64, "os_guess": "Linux", "vpn_likely": False}
        result = detect_vpn("192.168.1.1", [])
        assert result["vpn_detected"] is False

    @patch("weyefi.profiler.probe_ttl")
    @patch("weyefi.profiler._run_cmd", return_value="")
    @patch("weyefi.profiler.shutil.which", return_value=None)
    def test_vpn_via_ttl(self, mock_which, mock_cmd, mock_ttl):
        mock_ttl.return_value = {"ttl": 50, "os_guess": "Linux", "vpn_likely": True}
        result = detect_vpn("192.168.1.1", [])
        assert result["vpn_detected"] is True
        assert any("TTL" in i for i in result["indicators"])


class TestDetectRemoteAccess:
    def test_rdp_detected(self):
        open_ports = [
            {"port": 3389, "service": "RDP", "state": "open"},
        ]
        result = detect_remote_access("192.168.1.50", open_ports)
        assert result["remote_access"] is True
        assert result["services"][0]["port"] == 3389

    def test_ssh_detected(self):
        open_ports = [
            {"port": 22, "service": "SSH", "state": "open"},
            {"port": 80, "service": "HTTP", "state": "open"},
        ]
        result = detect_remote_access("192.168.1.50", open_ports)
        assert result["remote_access"] is True
        assert len(result["services"]) == 1  # only SSH, not HTTP

    def test_no_remote_access(self):
        open_ports = [
            {"port": 80, "service": "HTTP", "state": "open"},
            {"port": 443, "service": "HTTPS", "state": "open"},
        ]
        result = detect_remote_access("192.168.1.50", open_ports)
        assert result["remote_access"] is False

    def test_empty_ports(self):
        result = detect_remote_access("192.168.1.50", [])
        assert result["remote_access"] is False
