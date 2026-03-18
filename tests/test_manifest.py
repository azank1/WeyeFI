"""Tests for weyefi.manifest — known-good device diffing."""

import json
import tempfile
from pathlib import Path

from weyefi.manifest import add_device, diff_devices, load_manifest, save_manifest


SAMPLE_MANIFEST = {
    "known_devices": [
        {"mac": "AA:BB:CC:DD:EE:01", "name": "Router", "vendor": "Netgear", "first_seen": "2026-01-01T00:00:00Z"},
        {"mac": "AA:BB:CC:DD:EE:02", "name": "My Phone", "vendor": "Samsung", "first_seen": "2026-01-01T00:00:00Z"},
    ],
    "trusted_dns": ["8.8.8.8"],
    "monitored_domains": ["google.com"],
    "network_subnet": "192.168.1.0/24",
}


class TestLoadSaveManifest:
    def test_load_nonexistent_returns_defaults(self, tmp_path):
        result = load_manifest(tmp_path / "does_not_exist.json")
        assert "known_devices" in result
        assert result["known_devices"] == []

    def test_round_trip(self, tmp_path):
        path = tmp_path / "manifest.json"
        save_manifest(SAMPLE_MANIFEST, path)
        loaded = load_manifest(path)
        assert loaded["known_devices"] == SAMPLE_MANIFEST["known_devices"]
        assert loaded["network_subnet"] == "192.168.1.0/24"


class TestDiffDevices:
    def test_all_known(self):
        scan = [
            {"ip": "192.168.1.1", "mac": "AA:BB:CC:DD:EE:01", "hostname": "router"},
            {"ip": "192.168.1.50", "mac": "AA:BB:CC:DD:EE:02", "hostname": "phone"},
        ]
        result = diff_devices(scan, SAMPLE_MANIFEST)
        assert len(result["known"]) == 2
        assert len(result["new"]) == 0
        assert len(result["missing"]) == 0

    def test_new_device_detected(self):
        scan = [
            {"ip": "192.168.1.1", "mac": "AA:BB:CC:DD:EE:01", "hostname": "router"},
            {"ip": "192.168.1.99", "mac": "FF:FF:FF:00:00:01", "hostname": "intruder"},
        ]
        result = diff_devices(scan, SAMPLE_MANIFEST)
        assert len(result["known"]) == 1
        assert len(result["new"]) == 1
        assert result["new"][0]["ip"] == "192.168.1.99"
        # Phone is missing
        assert len(result["missing"]) == 1
        assert result["missing"][0]["name"] == "My Phone"

    def test_missing_device(self):
        scan = [
            {"ip": "192.168.1.1", "mac": "AA:BB:CC:DD:EE:01", "hostname": "router"},
        ]
        result = diff_devices(scan, SAMPLE_MANIFEST)
        assert len(result["missing"]) == 1
        assert result["missing"][0]["mac"] == "AA:BB:CC:DD:EE:02"

    def test_empty_mac_ignored(self):
        scan = [
            {"ip": "192.168.1.100", "mac": "", "hostname": ""},
        ]
        result = diff_devices(scan, SAMPLE_MANIFEST)
        # Device with no MAC can't be classified as new
        assert len(result["new"]) == 0


class TestAddDevice:
    def test_adds_new_device(self):
        manifest = {"known_devices": []}
        device = {"ip": "192.168.1.99", "mac": "FF:FF:FF:00:00:01", "hostname": "new-device", "vendor": "TestCo"}
        add_device(manifest, device, name="Test Device")
        assert len(manifest["known_devices"]) == 1
        assert manifest["known_devices"][0]["name"] == "Test Device"
        assert manifest["known_devices"][0]["mac"] == "FF:FF:FF:00:00:01"

    def test_no_duplicate(self):
        manifest = {
            "known_devices": [
                {"mac": "FF:FF:FF:00:00:01", "name": "Existing"},
            ]
        }
        device = {"ip": "192.168.1.99", "mac": "ff:ff:ff:00:00:01", "vendor": "TestCo"}
        add_device(manifest, device, name="Duplicate")
        assert len(manifest["known_devices"]) == 1
