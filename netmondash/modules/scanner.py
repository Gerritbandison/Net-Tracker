"""
Network Scanner Module

Performs network device discovery and WiFi analysis.
"""

import logging
import subprocess
import re
import json
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from pathlib import Path
import ipaddress

from config import (
    NMAP_PING_SWEEP_ARGS,
    NMAP_SERVICE_DETECTION_ARGS,
    NMAP_TIMEOUT,
    SIGNAL_EXCELLENT,
    SIGNAL_GOOD,
    SIGNAL_FAIR,
    SIGNAL_POOR,
    SIGNAL_CRITICAL,
)

logger = logging.getLogger(__name__)


class DeviceInfo:
    """Network device information container."""

    def __init__(
        self,
        ip: str,
        mac: Optional[str] = None,
        hostname: Optional[str] = None,
        vendor: Optional[str] = None,
        open_ports: Optional[List[int]] = None,
        services: Optional[Dict[int, str]] = None,
        last_seen: Optional[datetime] = None,
    ):
        self.ip = ip
        self.mac = mac
        self.hostname = hostname
        self.vendor = vendor
        self.open_ports = open_ports or []
        self.services = services or {}
        self.last_seen = last_seen or datetime.now()

    def to_dict(self) -> Dict:
        """Convert to dictionary representation."""
        return {
            "ip": self.ip,
            "mac": self.mac,
            "hostname": self.hostname,
            "vendor": self.vendor,
            "open_ports": self.open_ports,
            "services": self.services,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
        }

    def __repr__(self) -> str:
        return f"<DeviceInfo {self.ip} ({self.mac}) - {self.hostname or 'Unknown'}>"


class WiFiMetrics:
    """WiFi signal metrics container."""

    def __init__(
        self,
        interface: str,
        ssid: Optional[str] = None,
        signal_strength: Optional[int] = None,
        noise_floor: Optional[int] = None,
        bit_rate: Optional[str] = None,
        frequency: Optional[str] = None,
        channel: Optional[int] = None,
        link_quality: Optional[str] = None,
    ):
        self.interface = interface
        self.ssid = ssid
        self.signal_strength = signal_strength
        self.noise_floor = noise_floor
        self.bit_rate = bit_rate
        self.frequency = frequency
        self.channel = channel
        self.link_quality = link_quality

    def get_signal_quality(self) -> str:
        """Get human-readable signal quality assessment."""
        if self.signal_strength is None:
            return "Unknown"

        if self.signal_strength >= SIGNAL_EXCELLENT:
            return "Excellent"
        elif self.signal_strength >= SIGNAL_GOOD:
            return "Good"
        elif self.signal_strength >= SIGNAL_FAIR:
            return "Fair"
        elif self.signal_strength >= SIGNAL_POOR:
            return "Poor"
        else:
            return "Critical"

    def needs_attention(self) -> bool:
        """Check if signal strength requires attention."""
        if self.signal_strength is None:
            return False
        return self.signal_strength < SIGNAL_FAIR

    def to_dict(self) -> Dict:
        """Convert to dictionary representation."""
        return {
            "interface": self.interface,
            "ssid": self.ssid,
            "signal_strength": self.signal_strength,
            "signal_quality": self.get_signal_quality(),
            "noise_floor": self.noise_floor,
            "bit_rate": self.bit_rate,
            "frequency": self.frequency,
            "channel": self.channel,
            "link_quality": self.link_quality,
            "needs_attention": self.needs_attention(),
        }


class NetworkScanner:
    """Network scanner for device discovery and WiFi analysis."""

    def __init__(self, interface: Optional[str] = None):
        """
        Initialize network scanner.

        Args:
            interface: Network interface to use for scanning
        """
        self.interface = interface
        self.last_scan_time: Optional[datetime] = None
        self.devices: List[DeviceInfo] = []

    def _run_command(self, cmd: List[str], timeout: int = NMAP_TIMEOUT) -> Tuple[str, str, int]:
        """
        Execute a command and return output.

        Args:
            cmd: Command and arguments
            timeout: Command timeout in seconds

        Returns:
            Tuple of (stdout, stderr, return_code)
        """
        try:
            logger.debug(f"Running command: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            logger.error(f"Command timed out: {' '.join(cmd)}")
            return "", "Command timed out", -1
        except FileNotFoundError:
            logger.error(f"Command not found: {cmd[0]}")
            return "", f"Command not found: {cmd[0]}", -1
        except Exception as e:
            logger.error(f"Error running command: {e}")
            return "", str(e), -1

    def _get_network_range(self, interface: Optional[str] = None) -> Optional[str]:
        """
        Get network CIDR range for scanning.

        Args:
            interface: Network interface name

        Returns:
            CIDR notation network range (e.g., '192.168.1.0/24')
        """
        iface = interface or self.interface

        # Try using 'ip' command
        cmd = ["ip", "-o", "-f", "inet", "addr", "show"]
        if iface:
            cmd.append(iface)

        stdout, stderr, returncode = self._run_command(cmd, timeout=5)

        if returncode != 0:
            logger.error("Failed to get network range")
            return None

        # Parse output: "2: eth0    inet 192.168.1.100/24 ..."
        match = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)', stdout)
        if match:
            ip_addr = match.group(1)
            prefix = match.group(2)

            # Calculate network address
            network = ipaddress.IPv4Network(f"{ip_addr}/{prefix}", strict=False)
            cidr = str(network)
            logger.debug(f"Detected network range: {cidr}")
            return cidr

        logger.warning("Could not determine network range")
        return None

    def _parse_nmap_xml(self, xml_output: str) -> List[DeviceInfo]:
        """
        Parse nmap XML output into DeviceInfo objects.

        Args:
            xml_output: nmap XML output

        Returns:
            List of DeviceInfo objects
        """
        devices = []

        try:
            root = ET.fromstring(xml_output)

            for host in root.findall('host'):
                # Check if host is up
                status = host.find('status')
                if status is None or status.get('state') != 'up':
                    continue

                # Get IP address
                address_elem = host.find("address[@addrtype='ipv4']")
                if address_elem is None:
                    continue

                ip = address_elem.get('addr')
                if not ip:
                    continue

                # Get MAC address and vendor
                mac = None
                vendor = None
                mac_elem = host.find("address[@addrtype='mac']")
                if mac_elem is not None:
                    mac = mac_elem.get('addr')
                    vendor = mac_elem.get('vendor')

                # Get hostname
                hostname = None
                hostnames = host.find('hostnames')
                if hostnames is not None:
                    hostname_elem = hostnames.find('hostname')
                    if hostname_elem is not None:
                        hostname = hostname_elem.get('name')

                # Get open ports and services
                open_ports = []
                services = {}
                ports = host.find('ports')
                if ports is not None:
                    for port in ports.findall('port'):
                        port_state = port.find('state')
                        if port_state is not None and port_state.get('state') == 'open':
                            port_id = int(port.get('portid', 0))
                            open_ports.append(port_id)

                            # Get service info
                            service = port.find('service')
                            if service is not None:
                                service_name = service.get('name', 'unknown')
                                service_product = service.get('product', '')
                                service_version = service.get('version', '')

                                service_str = service_name
                                if service_product:
                                    service_str += f" ({service_product}"
                                    if service_version:
                                        service_str += f" {service_version}"
                                    service_str += ")"

                                services[port_id] = service_str

                device = DeviceInfo(
                    ip=ip,
                    mac=mac,
                    hostname=hostname,
                    vendor=vendor,
                    open_ports=open_ports,
                    services=services,
                )

                devices.append(device)
                logger.debug(f"Parsed device: {device}")

        except ET.ParseError as e:
            logger.error(f"Error parsing nmap XML: {e}")
        except Exception as e:
            logger.error(f"Unexpected error parsing nmap output: {e}")

        return devices

    def scan_network(self, target: Optional[str] = None, service_detection: bool = False) -> List[DeviceInfo]:
        """
        Scan network for devices.

        Args:
            target: Target network/host (CIDR or IP). If None, auto-detect.
            service_detection: Perform service version detection

        Returns:
            List of discovered DeviceInfo objects
        """
        logger.info("Starting network scan")

        # Determine target
        if target is None:
            target = self._get_network_range(self.interface)
            if target is None:
                logger.error("Could not determine scan target")
                return []

        # Build nmap command
        cmd = ["nmap", "-oX", "-"]  # Output XML to stdout

        if service_detection:
            cmd.extend(NMAP_SERVICE_DETECTION_ARGS)
        else:
            cmd.extend(NMAP_PING_SWEEP_ARGS)

        if self.interface:
            cmd.extend(["-e", self.interface])

        cmd.append(target)

        # Execute scan
        logger.info(f"Scanning {target} with command: {' '.join(cmd)}")
        stdout, stderr, returncode = self._run_command(cmd)

        if returncode != 0:
            logger.error(f"nmap scan failed: {stderr}")
            return []

        # Parse results
        devices = self._parse_nmap_xml(stdout)

        self.devices = devices
        self.last_scan_time = datetime.now()

        logger.info(f"Scan complete. Found {len(devices)} devices.")
        return devices

    def get_wifi_metrics(self, interface: Optional[str] = None) -> Optional[WiFiMetrics]:
        """
        Get WiFi signal metrics for an interface.

        Args:
            interface: WiFi interface name

        Returns:
            WiFiMetrics object or None if not available
        """
        iface = interface or self.interface

        if not iface:
            logger.error("No interface specified for WiFi metrics")
            return None

        # Try iwconfig first
        metrics = self._get_wifi_metrics_iwconfig(iface)
        if metrics:
            return metrics

        # Fallback to iw
        metrics = self._get_wifi_metrics_iw(iface)
        return metrics

    def _get_wifi_metrics_iwconfig(self, interface: str) -> Optional[WiFiMetrics]:
        """Get WiFi metrics using iwconfig."""
        stdout, stderr, returncode = self._run_command(["iwconfig", interface], timeout=5)

        if returncode != 0:
            logger.debug(f"iwconfig failed for {interface}")
            return None

        # Parse iwconfig output
        ssid = None
        signal_strength = None
        noise_floor = None
        bit_rate = None
        frequency = None
        link_quality = None

        # ESSID
        ssid_match = re.search(r'ESSID:"([^"]+)"', stdout)
        if ssid_match:
            ssid = ssid_match.group(1)

        # Bit Rate
        bitrate_match = re.search(r'Bit Rate[=:](\S+\s+\S+)', stdout)
        if bitrate_match:
            bit_rate = bitrate_match.group(1)

        # Frequency
        freq_match = re.search(r'Frequency:([\d.]+\s+GHz)', stdout)
        if freq_match:
            frequency = freq_match.group(1)

        # Signal level
        signal_match = re.search(r'Signal level[=:](-?\d+)\s*dBm', stdout)
        if signal_match:
            signal_strength = int(signal_match.group(1))

        # Link Quality
        quality_match = re.search(r'Link Quality[=:](\d+/\d+)', stdout)
        if quality_match:
            link_quality = quality_match.group(1)

        return WiFiMetrics(
            interface=interface,
            ssid=ssid,
            signal_strength=signal_strength,
            noise_floor=noise_floor,
            bit_rate=bit_rate,
            frequency=frequency,
            link_quality=link_quality,
        )

    def _get_wifi_metrics_iw(self, interface: str) -> Optional[WiFiMetrics]:
        """Get WiFi metrics using iw."""
        stdout, stderr, returncode = self._run_command(["iw", "dev", interface, "link"], timeout=5)

        if returncode != 0:
            logger.debug(f"iw link failed for {interface}")
            return None

        # Parse iw output
        ssid = None
        signal_strength = None
        frequency = None

        # SSID
        ssid_match = re.search(r'SSID:\s*(.+)', stdout)
        if ssid_match:
            ssid = ssid_match.group(1).strip()

        # Frequency
        freq_match = re.search(r'freq:\s*(\d+)', stdout)
        if freq_match:
            freq_mhz = int(freq_match.group(1))
            frequency = f"{freq_mhz / 1000:.1f} GHz"

        # Signal
        signal_match = re.search(r'signal:\s*(-?\d+)\s*dBm', stdout)
        if signal_match:
            signal_strength = int(signal_match.group(1))

        # Get bit rate from station dump
        stdout2, _, returncode2 = self._run_command(["iw", "dev", interface, "station", "dump"], timeout=5)
        bit_rate = None
        if returncode2 == 0:
            bitrate_match = re.search(r'tx bitrate:\s*(\S+\s+\S+)', stdout2)
            if bitrate_match:
                bit_rate = bitrate_match.group(1)

        return WiFiMetrics(
            interface=interface,
            ssid=ssid,
            signal_strength=signal_strength,
            bit_rate=bit_rate,
            frequency=frequency,
        )

    def scan_wifi_networks(self, interface: Optional[str] = None) -> List[Dict]:
        """
        Scan for available WiFi networks.

        Args:
            interface: WiFi interface name

        Returns:
            List of WiFi network information dictionaries
        """
        iface = interface or self.interface

        if not iface:
            logger.error("No interface specified for WiFi scan")
            return []

        logger.info(f"Scanning for WiFi networks on {iface}")

        # Use iw to scan
        stdout, stderr, returncode = self._run_command(["sudo", "iw", "dev", iface, "scan"], timeout=30)

        if returncode != 0:
            logger.error(f"WiFi scan failed: {stderr}")
            return []

        # Parse scan results
        networks = []
        current_network = {}

        for line in stdout.split('\n'):
            line = line.strip()

            # New BSS (network)
            if line.startswith('BSS '):
                if current_network:
                    networks.append(current_network)
                mac_match = re.search(r'BSS ([0-9a-f:]+)', line)
                current_network = {
                    'bssid': mac_match.group(1) if mac_match else None,
                }

            # SSID
            elif line.startswith('SSID:'):
                current_network['ssid'] = line.split(':', 1)[1].strip()

            # Signal
            elif 'signal:' in line:
                signal_match = re.search(r'signal:\s*(-?\d+\.\d+)\s*dBm', line)
                if signal_match:
                    current_network['signal'] = float(signal_match.group(1))

            # Frequency
            elif line.startswith('freq:'):
                freq = line.split(':', 1)[1].strip()
                current_network['frequency'] = int(freq)

            # Channel
            elif 'DS Parameter set: channel' in line:
                channel_match = re.search(r'channel\s*(\d+)', line)
                if channel_match:
                    current_network['channel'] = int(channel_match.group(1))

        # Add last network
        if current_network:
            networks.append(current_network)

        logger.info(f"Found {len(networks)} WiFi networks")
        return networks

    def get_scan_summary(self) -> Dict:
        """
        Get summary of last scan.

        Returns:
            Dictionary with scan summary information
        """
        return {
            "last_scan_time": self.last_scan_time.isoformat() if self.last_scan_time else None,
            "device_count": len(self.devices),
            "devices": [device.to_dict() for device in self.devices],
            "interface": self.interface,
        }


if __name__ == "__main__":
    # Test the scanner
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    scanner = NetworkScanner()

    print("Scanning network...")
    devices = scanner.scan_network()

    print(f"\nFound {len(devices)} devices:\n")
    for device in devices:
        print(f"IP: {device.ip}")
        print(f"  MAC: {device.mac or 'N/A'}")
        print(f"  Hostname: {device.hostname or 'Unknown'}")
        print(f"  Vendor: {device.vendor or 'Unknown'}")
        if device.open_ports:
            print(f"  Open Ports: {', '.join(map(str, device.open_ports))}")
        print()
