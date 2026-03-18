"""Tests for weyefi.scanner — nmap + ARP merge logic."""

import textwrap
from unittest.mock import MagicMock, mock_open, patch

from weyefi.scanner import _read_arp_table, scan_network


class TestReadArpTable:
    ARP_CONTENT = textwrap.dedent("""\
        IP address       HW type     Flags       HW address            Mask     Device
        192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:01     *        wlan0
        192.168.1.50     0x1         0x2         aa:bb:cc:dd:ee:02     *        wlan0
        192.168.1.99     0x1         0x0         00:00:00:00:00:00     *        wlan0
    """)

    @patch("weyefi.scanner.subprocess.run")
    @patch("weyefi.scanner.Path")
    def test_parses_proc_net_arp(self, mock_path_cls, mock_run):
        # Make `ip neigh show` return nothing so we fall through to /proc/net/arp
        mock_run.return_value = MagicMock(stdout="")

        mock_path = MagicMock()
        mock_path.exists.return_value = True
        mock_path.read_text.return_value = self.ARP_CONTENT
        mock_path_cls.return_value = mock_path

        result = _read_arp_table()

        assert "192.168.1.1" in result
        assert result["192.168.1.1"] == "AA:BB:CC:DD:EE:01"
        assert "192.168.1.50" in result
        assert result["192.168.1.50"] == "AA:BB:CC:DD:EE:02"
        # Zero MAC should be excluded
        assert "192.168.1.99" not in result

    @patch("weyefi.scanner.Path")
    @patch("weyefi.scanner.subprocess")
    def test_fallback_to_arp_command(self, mock_subprocess, mock_path_cls):
        mock_path = MagicMock()
        mock_path.exists.return_value = False
        mock_path_cls.return_value = mock_path

        mock_subprocess.run.return_value = MagicMock(
            stdout="router (192.168.1.1) at aa:bb:cc:dd:ee:01 on en0\n"
        )
        mock_subprocess.TimeoutExpired = TimeoutError

        result = _read_arp_table()
        assert result.get("192.168.1.1") == "AA:BB:CC:DD:EE:01"


class TestScanNetwork:
    @patch("weyefi.scanner._read_arp_table")
    @patch("weyefi.scanner._ping_sweep")
    @patch("weyefi.scanner.shutil.which", return_value="/usr/bin/nmap")
    def test_merges_nmap_and_arp(self, mock_which, mock_sweep, mock_arp):
        # Mock nmap results
        mock_nm = MagicMock()
        mock_nm.all_hosts.return_value = ["192.168.1.1", "192.168.1.50"]
        mock_nm.__getitem__ = lambda self, key: {
            "192.168.1.1": MagicMock(
                hostname=lambda: "router.local",
                state=lambda: "up",
                get=lambda k, d=None: {"addresses": {"ipv4": "192.168.1.1"}}.get(k, d),
            ),
            "192.168.1.50": MagicMock(
                hostname=lambda: "",
                state=lambda: "up",
                get=lambda k, d=None: {"addresses": {"ipv4": "192.168.1.50"}}.get(k, d),
            ),
        }[key]
        mock_sweep.return_value = mock_nm

        # Mock ARP cache
        mock_arp.return_value = {
            "192.168.1.1": "AA:BB:CC:DD:EE:01",
            "192.168.1.50": "AA:BB:CC:DD:EE:02",
        }

        devices = scan_network("192.168.1.0/24")

        assert len(devices) == 2
        d1 = next(d for d in devices if d["ip"] == "192.168.1.1")
        assert d1["mac"] == "AA:BB:CC:DD:EE:01"
        assert d1["hostname"] == "router.local"
        d2 = next(d for d in devices if d["ip"] == "192.168.1.50")
        assert d2["mac"] == "AA:BB:CC:DD:EE:02"

    @patch("weyefi.scanner.shutil.which", return_value=None)
    def test_raises_without_nmap(self, mock_which):
        try:
            scan_network("192.168.1.0/24")
            assert False, "Should have raised RuntimeError"
        except RuntimeError as e:
            assert "nmap" in str(e)
