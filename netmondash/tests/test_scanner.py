"""
Unit tests for the network scanner module.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from modules.scanner import NetworkScanner, DeviceInfo, WiFiMetrics


class TestDeviceInfo:
    """Tests for DeviceInfo class."""

    def test_device_info_creation(self):
        """Test creating a DeviceInfo object."""
        device = DeviceInfo(
            ip="192.168.1.100",
            mac="00:11:22:33:44:55",
            hostname="test-device",
            vendor="Test Vendor",
            open_ports=[80, 443],
        )

        assert device.ip == "192.168.1.100"
        assert device.mac == "00:11:22:33:44:55"
        assert device.hostname == "test-device"
        assert device.vendor == "Test Vendor"
        assert 80 in device.open_ports
        assert 443 in device.open_ports

    def test_device_to_dict(self):
        """Test converting DeviceInfo to dictionary."""
        device = DeviceInfo(
            ip="192.168.1.100",
            mac="00:11:22:33:44:55",
        )

        device_dict = device.to_dict()

        assert isinstance(device_dict, dict)
        assert device_dict["ip"] == "192.168.1.100"
        assert device_dict["mac"] == "00:11:22:33:44:55"
        assert "last_seen" in device_dict


class TestWiFiMetrics:
    """Tests for WiFiMetrics class."""

    def test_wifi_metrics_creation(self):
        """Test creating WiFiMetrics object."""
        metrics = WiFiMetrics(
            interface="wlan0",
            ssid="TestNetwork",
            signal_strength=-60,
            bit_rate="300 Mbps",
        )

        assert metrics.interface == "wlan0"
        assert metrics.ssid == "TestNetwork"
        assert metrics.signal_strength == -60
        assert metrics.bit_rate == "300 Mbps"

    def test_signal_quality_excellent(self):
        """Test signal quality for excellent signal."""
        metrics = WiFiMetrics(
            interface="wlan0",
            signal_strength=-45,
        )

        assert metrics.get_signal_quality() == "Excellent"
        assert not metrics.needs_attention()

    def test_signal_quality_poor(self):
        """Test signal quality for poor signal."""
        metrics = WiFiMetrics(
            interface="wlan0",
            signal_strength=-75,
        )

        assert metrics.get_signal_quality() == "Poor"
        assert metrics.needs_attention()

    def test_wifi_metrics_to_dict(self):
        """Test converting WiFiMetrics to dictionary."""
        metrics = WiFiMetrics(
            interface="wlan0",
            signal_strength=-60,
        )

        metrics_dict = metrics.to_dict()

        assert isinstance(metrics_dict, dict)
        assert metrics_dict["interface"] == "wlan0"
        assert metrics_dict["signal_quality"] == "Good"
        assert "needs_attention" in metrics_dict


class TestNetworkScanner:
    """Tests for NetworkScanner class."""

    def test_scanner_initialization(self):
        """Test scanner initialization."""
        scanner = NetworkScanner(interface="eth0")

        assert scanner.interface == "eth0"
        assert scanner.last_scan_time is None
        assert len(scanner.devices) == 0

    @patch('modules.scanner.subprocess.run')
    def test_get_network_range(self, mock_run):
        """Test getting network range from interface."""
        # Mock ip command output
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "2: eth0    inet 192.168.1.100/24 brd 192.168.1.255"
        mock_result.stderr = ""
        mock_run.return_value = mock_result

        scanner = NetworkScanner()
        network_range = scanner._get_network_range("eth0")

        assert network_range == "192.168.1.0/24"

    @patch('modules.scanner.NetworkScanner._parse_nmap_xml')
    @patch('modules.scanner.subprocess.run')
    def test_scan_network(self, mock_run, mock_parse):
        """Test network scanning."""
        # Mock nmap command
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "<nmaprun></nmaprun>"
        mock_result.stderr = ""
        mock_run.return_value = mock_result

        # Mock parsing to return test devices
        test_devices = [
            DeviceInfo(ip="192.168.1.1", mac="00:11:22:33:44:55"),
            DeviceInfo(ip="192.168.1.2", mac="AA:BB:CC:DD:EE:FF"),
        ]
        mock_parse.return_value = test_devices

        scanner = NetworkScanner()
        devices = scanner.scan_network(target="192.168.1.0/24")

        assert len(devices) == 2
        assert devices[0].ip == "192.168.1.1"
        assert scanner.last_scan_time is not None

    def test_get_scan_summary(self):
        """Test getting scan summary."""
        scanner = NetworkScanner()
        scanner.devices = [
            DeviceInfo(ip="192.168.1.1", mac="00:11:22:33:44:55"),
        ]

        summary = scanner.get_scan_summary()

        assert isinstance(summary, dict)
        assert summary["device_count"] == 1
        assert "devices" in summary
        assert summary["interface"] is None


@pytest.fixture
def sample_nmap_xml():
    """Sample nmap XML output for testing."""
    return """<?xml version="1.0"?>
    <nmaprun>
        <host>
            <status state="up"/>
            <address addr="192.168.1.1" addrtype="ipv4"/>
            <address addr="00:11:22:33:44:55" addrtype="mac" vendor="Test Vendor"/>
            <hostnames>
                <hostname name="router.local"/>
            </hostnames>
            <ports>
                <port protocol="tcp" portid="80">
                    <state state="open"/>
                    <service name="http"/>
                </port>
                <port protocol="tcp" portid="443">
                    <state state="open"/>
                    <service name="https"/>
                </port>
            </ports>
        </host>
    </nmaprun>"""


class TestNmapParsing:
    """Tests for nmap XML parsing."""

    def test_parse_nmap_xml(self, sample_nmap_xml):
        """Test parsing nmap XML output."""
        scanner = NetworkScanner()
        devices = scanner._parse_nmap_xml(sample_nmap_xml)

        assert len(devices) == 1

        device = devices[0]
        assert device.ip == "192.168.1.1"
        assert device.mac == "00:11:22:33:44:55"
        assert device.hostname == "router.local"
        assert device.vendor == "Test Vendor"
        assert 80 in device.open_ports
        assert 443 in device.open_ports

    def test_parse_empty_xml(self):
        """Test parsing empty nmap XML."""
        scanner = NetworkScanner()
        devices = scanner._parse_nmap_xml("<nmaprun></nmaprun>")

        assert len(devices) == 0

    def test_parse_invalid_xml(self):
        """Test handling invalid XML."""
        scanner = NetworkScanner()
        devices = scanner._parse_nmap_xml("invalid xml")

        assert len(devices) == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
