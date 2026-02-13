"""
Unit tests for the network scanner module.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from modules.scanner import NetworkScanner, DeviceInfo, WiFiMetrics


# ─── DeviceInfo Tests ────────────────────────────────────────────────────────


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

    def test_device_info_defaults(self):
        """Test DeviceInfo default values for optional fields."""
        device = DeviceInfo(ip="10.0.0.1")

        assert device.mac is None
        assert device.hostname is None
        assert device.vendor is None
        assert device.open_ports == []
        assert device.services == {}
        assert device.last_seen is not None
        assert device.latency_ms is None
        assert device.os_guess is None

    def test_device_info_with_latency(self):
        """Test DeviceInfo with latency_ms set."""
        device = DeviceInfo(
            ip="192.168.1.1",
            mac="AA:BB:CC:DD:EE:FF",
            latency_ms=5.42,
        )

        assert device.latency_ms == 5.42
        d = device.to_dict()
        assert d["latency_ms"] == 5.42

    def test_device_info_repr(self):
        """Test DeviceInfo string representation."""
        device = DeviceInfo(
            ip="192.168.1.1",
            mac="AA:BB:CC:DD:EE:FF",
            hostname="router",
        )
        rep = repr(device)
        assert "192.168.1.1" in rep
        assert "router" in rep

    def test_device_info_repr_with_latency(self):
        """Test DeviceInfo repr includes latency when present."""
        device = DeviceInfo(
            ip="192.168.1.1",
            mac="AA:BB:CC:DD:EE:FF",
            latency_ms=3.5,
        )
        rep = repr(device)
        assert "3.5ms" in rep


# ─── WiFiMetrics Tests ───────────────────────────────────────────────────────


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
        """Test signal quality for excellent signal (-50 dBm threshold)."""
        metrics = WiFiMetrics(
            interface="wlan0",
            signal_strength=-45,
        )

        assert metrics.get_signal_quality() == "Excellent"
        assert not metrics.needs_attention()

    def test_signal_quality_good(self):
        """Test signal quality for good signal (-60 dBm threshold)."""
        metrics = WiFiMetrics(
            interface="wlan0",
            signal_strength=-55,
        )

        assert metrics.get_signal_quality() == "Good"
        assert not metrics.needs_attention()

    def test_signal_quality_fair(self):
        """Test signal quality for fair signal (-70 dBm threshold)."""
        metrics = WiFiMetrics(
            interface="wlan0",
            signal_strength=-65,
        )

        assert metrics.get_signal_quality() == "Fair"
        # Fair is >= SIGNAL_FAIR so needs_attention should be False
        assert not metrics.needs_attention()

    def test_signal_quality_poor(self):
        """Test signal quality for poor signal (-80 dBm threshold)."""
        metrics = WiFiMetrics(
            interface="wlan0",
            signal_strength=-75,
        )

        assert metrics.get_signal_quality() == "Poor"
        assert metrics.needs_attention()

    def test_signal_quality_critical(self):
        """Test signal quality for critical signal (below -80 dBm)."""
        metrics = WiFiMetrics(
            interface="wlan0",
            signal_strength=-95,
        )

        assert metrics.get_signal_quality() == "Critical"
        assert metrics.needs_attention()

    def test_signal_quality_unknown(self):
        """Test signal quality when signal_strength is None."""
        metrics = WiFiMetrics(
            interface="wlan0",
            signal_strength=None,
        )

        assert metrics.get_signal_quality() == "Unknown"
        # No signal strength -> needs_attention returns False
        assert not metrics.needs_attention()

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

    def test_wifi_metrics_boundary_excellent(self):
        """Test signal quality at the exact Excellent boundary (-50 dBm)."""
        metrics = WiFiMetrics(interface="wlan0", signal_strength=-50)
        assert metrics.get_signal_quality() == "Excellent"

    def test_wifi_metrics_boundary_good(self):
        """Test signal quality at the exact Good boundary (-60 dBm)."""
        metrics = WiFiMetrics(interface="wlan0", signal_strength=-60)
        assert metrics.get_signal_quality() == "Good"

    def test_wifi_metrics_boundary_fair(self):
        """Test signal quality at the exact Fair boundary (-70 dBm)."""
        metrics = WiFiMetrics(interface="wlan0", signal_strength=-70)
        assert metrics.get_signal_quality() == "Fair"

    def test_wifi_metrics_boundary_poor(self):
        """Test signal quality at the exact Poor boundary (-80 dBm)."""
        metrics = WiFiMetrics(interface="wlan0", signal_strength=-80)
        assert metrics.get_signal_quality() == "Poor"


# ─── NetworkScanner Tests ────────────────────────────────────────────────────


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

    @patch('modules.scanner.subprocess.run')
    def test_ping_host_success(self, mock_run):
        """Test successful ping_host returning average latency."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = (
            "PING 192.168.1.1 (192.168.1.1) 56(84) bytes of data.\n"
            "64 bytes from 192.168.1.1: icmp_seq=1 ttl=64 time=1.23 ms\n"
            "64 bytes from 192.168.1.1: icmp_seq=2 ttl=64 time=1.45 ms\n"
            "64 bytes from 192.168.1.1: icmp_seq=3 ttl=64 time=1.10 ms\n"
            "\n"
            "--- 192.168.1.1 ping statistics ---\n"
            "3 packets transmitted, 3 received, 0% packet loss, time 2003ms\n"
            "rtt min/avg/max/mdev = 1.100/1.260/1.450/0.145 ms\n"
        )
        mock_result.stderr = ""
        mock_run.return_value = mock_result

        scanner = NetworkScanner()
        latency = scanner.ping_host("192.168.1.1")

        assert latency is not None
        assert abs(latency - 1.260) < 0.001

    @patch('modules.scanner.subprocess.run')
    def test_ping_host_failure(self, mock_run):
        """Test ping_host returns None on failure (returncode > 1)."""
        mock_result = MagicMock()
        mock_result.returncode = 2  # Network unreachable
        mock_result.stdout = ""
        mock_result.stderr = "connect: Network is unreachable"
        mock_run.return_value = mock_result

        scanner = NetworkScanner()
        latency = scanner.ping_host("10.99.99.99")

        assert latency is None

    @patch('modules.scanner.subprocess.run')
    def test_ping_host_partial_loss(self, mock_run):
        """Test ping_host with returncode 1 (partial packet loss) still parses."""
        mock_result = MagicMock()
        mock_result.returncode = 1  # some packets lost
        mock_result.stdout = (
            "PING 192.168.1.1 (192.168.1.1) 56(84) bytes of data.\n"
            "64 bytes from 192.168.1.1: icmp_seq=1 ttl=64 time=2.50 ms\n"
            "\n"
            "--- 192.168.1.1 ping statistics ---\n"
            "3 packets transmitted, 1 received, 66% packet loss, time 2004ms\n"
            "rtt min/avg/max/mdev = 2.500/2.500/2.500/0.000 ms\n"
        )
        mock_result.stderr = ""
        mock_run.return_value = mock_result

        scanner = NetworkScanner()
        latency = scanner.ping_host("192.168.1.1")

        assert latency is not None
        assert abs(latency - 2.500) < 0.001

    @patch('modules.scanner.subprocess.run')
    def test_get_gateway_ip_ip_route(self, mock_run):
        """Test get_gateway_ip via `ip route show default`."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "default via 192.168.1.1 dev eth0 proto dhcp metric 100"
        mock_result.stderr = ""
        mock_run.return_value = mock_result

        scanner = NetworkScanner()
        gw = scanner.get_gateway_ip()

        assert gw == "192.168.1.1"

    @patch('modules.scanner.subprocess.run')
    def test_get_gateway_ip_caches_result(self, mock_run):
        """Test that get_gateway_ip caches the result and does not call again."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "default via 10.0.0.1 dev wlan0"
        mock_result.stderr = ""
        mock_run.return_value = mock_result

        scanner = NetworkScanner()
        gw1 = scanner.get_gateway_ip()
        gw2 = scanner.get_gateway_ip()

        assert gw1 == "10.0.0.1"
        assert gw2 == "10.0.0.1"
        # Only one call to subprocess because the result is cached
        assert mock_run.call_count == 1

    @patch('modules.scanner.subprocess.run')
    def test_get_gateway_ip_fallback_route_n(self, mock_run):
        """Test get_gateway_ip falls back to `route -n` when ip route fails."""
        def side_effect(cmd, **kwargs):
            result = MagicMock()
            if cmd[0] == "ip":
                result.returncode = 1
                result.stdout = ""
                result.stderr = "command failed"
            elif cmd[0] == "route":
                result.returncode = 0
                result.stdout = (
                    "Kernel IP routing table\n"
                    "Destination     Gateway         Genmask         Flags Metric Ref    Use Iface\n"
                    "0.0.0.0         192.168.0.1     0.0.0.0         UG    100    0        0 eth0\n"
                    "192.168.0.0     0.0.0.0         255.255.255.0   U     100    0        0 eth0\n"
                )
                result.stderr = ""
            else:
                result.returncode = 1
                result.stdout = ""
                result.stderr = ""
            return result

        mock_run.side_effect = side_effect

        scanner = NetworkScanner()
        gw = scanner.get_gateway_ip()

        assert gw == "192.168.0.1"

    def test_get_network_summary_empty(self):
        """Test get_network_summary with no devices."""
        scanner = NetworkScanner(interface="eth0")

        summary = scanner.get_network_summary()

        assert summary["device_count"] == 0
        assert summary["devices_by_status"]["reachable"] == 0
        assert summary["devices_by_status"]["unreachable"] == 0
        assert summary["latency"]["average_ms"] is None
        assert summary["interface"] == "eth0"

    @patch.object(NetworkScanner, 'get_gateway_ip', return_value="192.168.1.1")
    def test_get_network_summary_with_devices(self, mock_gw):
        """Test get_network_summary with some devices and latencies."""
        scanner = NetworkScanner(interface="wlan0")
        scanner.devices = [
            DeviceInfo(ip="192.168.1.1", mac="AA:BB:CC:DD:EE:01", latency_ms=1.5),
            DeviceInfo(ip="192.168.1.2", mac="AA:BB:CC:DD:EE:02", latency_ms=3.5),
            DeviceInfo(ip="192.168.1.3", mac="AA:BB:CC:DD:EE:03"),  # no latency
        ]

        summary = scanner.get_network_summary()

        assert summary["device_count"] == 3
        assert summary["devices_by_status"]["reachable"] == 2
        assert summary["devices_by_status"]["unreachable"] == 1
        assert summary["latency"]["average_ms"] == 2.5
        assert summary["latency"]["min_ms"] == 1.5
        assert summary["latency"]["max_ms"] == 3.5
        assert summary["gateway"]["ip"] == "192.168.1.1"
        # Gateway device should be found
        assert summary["gateway"]["device"] is not None
        assert summary["gateway"]["device"]["ip"] == "192.168.1.1"


# ─── Nmap XML Parsing Tests ─────────────────────────────────────────────────


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


@pytest.fixture
def nmap_xml_with_services():
    """Nmap XML output with detailed service information."""
    return """<?xml version="1.0"?>
    <nmaprun>
        <host>
            <status state="up"/>
            <address addr="192.168.1.10" addrtype="ipv4"/>
            <address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" vendor="ServerCo"/>
            <hostnames>
                <hostname name="webserver.local"/>
            </hostnames>
            <ports>
                <port protocol="tcp" portid="22">
                    <state state="open"/>
                    <service name="ssh" product="OpenSSH" version="8.9"/>
                </port>
                <port protocol="tcp" portid="80">
                    <state state="open"/>
                    <service name="http" product="nginx" version="1.24"/>
                </port>
                <port protocol="tcp" portid="443">
                    <state state="closed"/>
                    <service name="https"/>
                </port>
            </ports>
        </host>
    </nmaprun>"""


@pytest.fixture
def nmap_xml_no_mac():
    """Nmap XML output where host has no MAC address (e.g., localhost scan)."""
    return """<?xml version="1.0"?>
    <nmaprun>
        <host>
            <status state="up"/>
            <address addr="192.168.1.50" addrtype="ipv4"/>
            <hostnames>
                <hostname name="mystery-host"/>
            </hostnames>
            <ports>
                <port protocol="tcp" portid="8080">
                    <state state="open"/>
                    <service name="http-proxy"/>
                </port>
            </ports>
        </host>
    </nmaprun>"""


@pytest.fixture
def nmap_xml_multiple_hosts():
    """Nmap XML output with multiple hosts."""
    return """<?xml version="1.0"?>
    <nmaprun>
        <host>
            <status state="up"/>
            <address addr="192.168.1.1" addrtype="ipv4"/>
            <address addr="00:11:22:33:44:01" addrtype="mac" vendor="RouterCo"/>
            <hostnames><hostname name="gw.local"/></hostnames>
        </host>
        <host>
            <status state="up"/>
            <address addr="192.168.1.100" addrtype="ipv4"/>
            <address addr="00:11:22:33:44:02" addrtype="mac" vendor="PhoneCo"/>
            <hostnames><hostname name="phone.local"/></hostnames>
        </host>
        <host>
            <status state="down"/>
            <address addr="192.168.1.200" addrtype="ipv4"/>
            <address addr="00:11:22:33:44:03" addrtype="mac"/>
        </host>
        <host>
            <status state="up"/>
            <address addr="192.168.1.150" addrtype="ipv4"/>
            <address addr="00:11:22:33:44:04" addrtype="mac"/>
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

    def test_parse_nmap_xml_with_services(self, nmap_xml_with_services):
        """Test parsing nmap XML with detailed service info (product/version)."""
        scanner = NetworkScanner()
        devices = scanner._parse_nmap_xml(nmap_xml_with_services)

        assert len(devices) == 1
        device = devices[0]

        assert device.ip == "192.168.1.10"
        assert device.mac == "AA:BB:CC:DD:EE:FF"
        assert device.hostname == "webserver.local"
        assert device.vendor == "ServerCo"

        # Port 22 should be open with service info
        assert 22 in device.open_ports
        assert 22 in device.services
        assert "ssh" in device.services[22]
        assert "OpenSSH" in device.services[22]
        assert "8.9" in device.services[22]

        # Port 80 should be open with service info
        assert 80 in device.open_ports
        assert "nginx" in device.services[80]

        # Port 443 is closed, so should not appear
        assert 443 not in device.open_ports

    def test_parse_nmap_xml_host_no_mac(self, nmap_xml_no_mac):
        """Test parsing a host that has no MAC address element."""
        scanner = NetworkScanner()
        devices = scanner._parse_nmap_xml(nmap_xml_no_mac)

        assert len(devices) == 1
        device = devices[0]

        assert device.ip == "192.168.1.50"
        assert device.mac is None
        assert device.vendor is None
        assert device.hostname == "mystery-host"
        assert 8080 in device.open_ports

    def test_parse_nmap_xml_multiple_hosts(self, nmap_xml_multiple_hosts):
        """Test parsing XML with multiple hosts, including one that is down."""
        scanner = NetworkScanner()
        devices = scanner._parse_nmap_xml(nmap_xml_multiple_hosts)

        # Only hosts with state="up" should be included (3 up, 1 down)
        assert len(devices) == 3
        ips = [d.ip for d in devices]
        assert "192.168.1.1" in ips
        assert "192.168.1.100" in ips
        assert "192.168.1.150" in ips
        # The down host should not be included
        assert "192.168.1.200" not in ips


# ─── ARP Scan Fallback Tests ────────────────────────────────────────────────


class TestArpScanFallback:
    """Tests for ARP scan fallback mechanism."""

    @patch('modules.scanner.subprocess.run')
    def test_arp_scan_fallback_arp_scan_success(self, mock_run):
        """Test _arp_scan_fallback succeeds with arp-scan output."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = (
            "Interface: eth0, datalink type: EN10MB (Ethernet)\n"
            "Starting arp-scan 1.9.7\n"
            "192.168.1.1\t00:11:22:33:44:55\tRouterVendor\n"
            "192.168.1.100\tAA:BB:CC:DD:EE:FF\tPhoneVendor\n"
            "\n"
            "2 packets received by filter, 0 packets dropped by kernel\n"
            "Ending arp-scan: 256 hosts scanned in 1.234 seconds\n"
        )
        mock_result.stderr = ""
        mock_run.return_value = mock_result

        scanner = NetworkScanner()
        devices = scanner._arp_scan_fallback("192.168.1.0/24")

        assert len(devices) == 2
        assert devices[0].ip == "192.168.1.1"
        assert devices[0].mac == "00:11:22:33:44:55"
        assert devices[0].vendor == "RouterVendor"
        assert devices[1].ip == "192.168.1.100"
        assert devices[1].mac == "AA:BB:CC:DD:EE:FF"

    @patch('modules.scanner.subprocess.run')
    def test_arp_scan_fallback_reads_proc_arp(self, mock_run):
        """Test _arp_scan_fallback falls through to /proc/net/arp when arp-scan fails."""
        call_count = [0]

        def side_effect(cmd, **kwargs):
            call_count[0] += 1
            result = MagicMock()
            if cmd[0] == "sudo":
                # arp-scan fails
                result.returncode = 1
                result.stdout = ""
                result.stderr = "arp-scan not found"
            elif cmd[0] == "cat":
                # /proc/net/arp read succeeds
                result.returncode = 0
                result.stdout = (
                    "IP address       HW type     Flags       HW address            Mask     Device\n"
                    "192.168.1.1      0x1         0x2         00:11:22:33:44:55     *        eth0\n"
                    "192.168.1.100    0x1         0x2         AA:BB:CC:DD:EE:FF     *        eth0\n"
                    "10.0.0.1         0x1         0x2         FF:FF:FF:FF:FF:01     *        eth1\n"
                )
                result.stderr = ""
            else:
                result.returncode = 1
                result.stdout = ""
                result.stderr = ""
            return result

        mock_run.side_effect = side_effect

        scanner = NetworkScanner()
        devices = scanner._arp_scan_fallback("192.168.1.0/24")

        # Should find 2 devices in the 192.168.1.0/24 range (not the 10.0.0.1)
        assert len(devices) == 2
        ips = [d.ip for d in devices]
        assert "192.168.1.1" in ips
        assert "192.168.1.100" in ips
        assert "10.0.0.1" not in ips


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
