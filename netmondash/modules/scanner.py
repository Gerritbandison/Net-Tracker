"""
Network Scanner Module

Performs network device discovery and WiFi analysis with enhanced
ARP fallback scanning, ping latency measurement, gateway detection,
channel utilization tracking, SNR monitoring, and scan rate limiting.
"""

import logging
import subprocess
import re
import json
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from pathlib import Path
import ipaddress
from collections import defaultdict

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

# Scan rate limiting defaults
_MIN_SCAN_INTERVAL_SECONDS = 10
_DEFAULT_PING_TIMEOUT = 2
_DEFAULT_PING_COUNT = 3
_ARP_SCAN_TIMEOUT = 30


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
        latency_ms: Optional[float] = None,
        os_guess: Optional[str] = None,
    ):
        self.ip = ip
        self.mac = mac
        self.hostname = hostname
        self.vendor = vendor
        self.open_ports = open_ports or []
        self.services = services or {}
        self.last_seen = last_seen or datetime.now()
        self.latency_ms = latency_ms
        self.os_guess = os_guess

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
            "latency_ms": self.latency_ms,
            "os_guess": self.os_guess,
        }

    def __repr__(self) -> str:
        latency_str = f", {self.latency_ms:.1f}ms" if self.latency_ms is not None else ""
        return (
            f"<DeviceInfo {self.ip} ({self.mac})"
            f" - {self.hostname or 'Unknown'}{latency_str}>"
        )


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
        snr: Optional[float] = None,
        band: Optional[str] = None,
        channel_utilization: Optional[float] = None,
    ):
        self.interface = interface
        self.ssid = ssid
        self.signal_strength = signal_strength
        self.noise_floor = noise_floor
        self.bit_rate = bit_rate
        self.frequency = frequency
        self.channel = channel
        self.link_quality = link_quality
        self.channel_utilization = channel_utilization

        # Compute SNR from signal and noise if not explicitly provided
        if snr is not None:
            self.snr = snr
        elif signal_strength is not None and noise_floor is not None:
            self.snr = float(signal_strength - noise_floor)
        else:
            self.snr = None

        # Classify band from frequency if not explicitly provided
        if band is not None:
            self.band = band
        else:
            self.band = self._classify_band()

    def _classify_band(self) -> Optional[str]:
        """Classify WiFi band from frequency string or channel number."""
        if self.frequency is not None:
            try:
                # Handle formats like "2.437 GHz" or "5.18 GHz"
                freq_match = re.search(r'([\d.]+)\s*GHz', self.frequency)
                if freq_match:
                    freq_ghz = float(freq_match.group(1))
                    if 2.0 <= freq_ghz < 3.0:
                        return "2.4GHz"
                    elif 5.0 <= freq_ghz < 6.0:
                        return "5GHz"
                    elif 5.9 <= freq_ghz <= 7.2:
                        return "6GHz"
            except (ValueError, AttributeError):
                pass

        if self.channel is not None:
            if 1 <= self.channel <= 14:
                return "2.4GHz"
            elif 32 <= self.channel <= 177:
                return "5GHz"

        return None

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
            "snr": self.snr,
            "bit_rate": self.bit_rate,
            "frequency": self.frequency,
            "band": self.band,
            "channel": self.channel,
            "link_quality": self.link_quality,
            "channel_utilization": self.channel_utilization,
            "needs_attention": self.needs_attention(),
        }


class NetworkScanner:
    """Network scanner for device discovery and WiFi analysis."""

    def __init__(
        self,
        interface: Optional[str] = None,
        min_scan_interval: int = _MIN_SCAN_INTERVAL_SECONDS,
    ):
        """
        Initialize network scanner.

        Args:
            interface: Network interface to use for scanning
            min_scan_interval: Minimum seconds between consecutive scans
                (rate limiting / throttle)
        """
        self.interface = interface
        self.last_scan_time: Optional[datetime] = None
        self.devices: List[DeviceInfo] = []
        self._min_scan_interval = min_scan_interval
        self._gateway_ip: Optional[str] = None

    # ------------------------------------------------------------------
    # Command execution
    # ------------------------------------------------------------------

    def _run_command(
        self, cmd: List[str], timeout: int = NMAP_TIMEOUT
    ) -> Tuple[str, str, int]:
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
            logger.error(f"Command timed out after {timeout}s: {' '.join(cmd)}")
            return "", "Command timed out", -1
        except FileNotFoundError:
            logger.error(f"Command not found: {cmd[0]}")
            return "", f"Command not found: {cmd[0]}", -1
        except PermissionError:
            logger.error(f"Permission denied running: {cmd[0]}")
            return "", f"Permission denied: {cmd[0]}", -1
        except OSError as e:
            logger.error(f"OS error running command {cmd[0]}: {e}")
            return "", str(e), -1
        except Exception as e:
            logger.error(f"Error running command: {e}")
            return "", str(e), -1

    # ------------------------------------------------------------------
    # Rate limiting
    # ------------------------------------------------------------------

    def _is_scan_throttled(self) -> bool:
        """Check if scanning should be throttled based on rate limit.

        Returns:
            True if we should skip this scan because the previous one
            was too recent.
        """
        if self.last_scan_time is None:
            return False
        elapsed = (datetime.now() - self.last_scan_time).total_seconds()
        if elapsed < self._min_scan_interval:
            logger.warning(
                f"Scan throttled: only {elapsed:.1f}s since last scan "
                f"(minimum interval is {self._min_scan_interval}s)"
            )
            return True
        return False

    # ------------------------------------------------------------------
    # Network range detection
    # ------------------------------------------------------------------

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

    # ------------------------------------------------------------------
    # Gateway detection
    # ------------------------------------------------------------------

    def get_gateway_ip(self) -> Optional[str]:
        """Detect the default gateway/router IP from the system routing table.

        Returns:
            Gateway IP address string or None if not detected.
        """
        if self._gateway_ip is not None:
            return self._gateway_ip

        # Method 1: parse `ip route`
        stdout, stderr, returncode = self._run_command(
            ["ip", "route", "show", "default"], timeout=5
        )
        if returncode == 0 and stdout:
            match = re.search(
                r'default\s+via\s+(\d+\.\d+\.\d+\.\d+)', stdout
            )
            if match:
                self._gateway_ip = match.group(1)
                logger.info(f"Detected gateway IP: {self._gateway_ip}")
                return self._gateway_ip

        # Method 2: fallback to `route -n`
        stdout, stderr, returncode = self._run_command(
            ["route", "-n"], timeout=5
        )
        if returncode == 0 and stdout:
            for line in stdout.splitlines():
                parts = line.split()
                if len(parts) >= 2 and parts[0] == "0.0.0.0":
                    self._gateway_ip = parts[1]
                    logger.info(
                        f"Detected gateway IP (route -n): {self._gateway_ip}"
                    )
                    return self._gateway_ip

        logger.warning("Could not detect default gateway")
        return None

    # ------------------------------------------------------------------
    # Ping latency measurement
    # ------------------------------------------------------------------

    def ping_host(
        self,
        ip: str,
        count: int = _DEFAULT_PING_COUNT,
        timeout: int = _DEFAULT_PING_TIMEOUT,
    ) -> Optional[float]:
        """Measure round-trip latency to a host via ICMP ping.

        Args:
            ip: Target IP address.
            count: Number of ping packets to send.
            timeout: Per-packet timeout in seconds.

        Returns:
            Average latency in milliseconds, or None on failure.
        """
        cmd = [
            "ping",
            "-c", str(count),
            "-W", str(timeout),
            ip,
        ]
        stdout, stderr, returncode = self._run_command(
            cmd, timeout=count * timeout + 5
        )
        if returncode not in (0, 1):
            # returncode 1 means some packets lost but output is still usable
            logger.debug(f"Ping to {ip} failed (rc={returncode})")
            return None

        # Parse average from "rtt min/avg/max/mdev = 0.1/0.2/0.3/0.01 ms"
        rtt_match = re.search(
            r'rtt\s+min/avg/max/mdev\s*=\s*[\d.]+/([\d.]+)/[\d.]+/[\d.]+\s*ms',
            stdout,
        )
        if rtt_match:
            try:
                return float(rtt_match.group(1))
            except ValueError:
                pass

        # Alternative format: "round-trip min/avg/max/stddev = ..."
        rtt_match = re.search(
            r'round-trip\s+min/avg/max/(?:std-dev|stddev)\s*=\s*[\d.]+/([\d.]+)/[\d.]+/[\d.]+\s*ms',
            stdout,
        )
        if rtt_match:
            try:
                return float(rtt_match.group(1))
            except ValueError:
                pass

        logger.debug(f"Could not parse ping output for {ip}")
        return None

    # ------------------------------------------------------------------
    # ARP scan fallback
    # ------------------------------------------------------------------

    def _arp_scan_fallback(self, target: str) -> List[DeviceInfo]:
        """Discover devices using ARP when nmap is unavailable or fails.

        Tries ``arp-scan`` first, then falls back to reading the kernel
        ARP cache (``/proc/net/arp`` or ``arp -an``).

        Args:
            target: Target CIDR range (e.g. '192.168.1.0/24').

        Returns:
            List of DeviceInfo objects discovered via ARP.
        """
        devices: List[DeviceInfo] = []

        # --- Attempt 1: arp-scan ---
        cmd = ["sudo", "arp-scan", "--localnet"]
        if self.interface:
            cmd.extend(["--interface", self.interface])

        stdout, stderr, returncode = self._run_command(
            cmd, timeout=_ARP_SCAN_TIMEOUT
        )

        if returncode == 0 and stdout:
            seen_ips = set()
            for line in stdout.splitlines():
                match = re.match(
                    r'(\d+\.\d+\.\d+\.\d+)\s+'
                    r'([0-9a-fA-F:]{17})\s*(.*)',
                    line,
                )
                if match and match.group(1) not in seen_ips:
                    ip = match.group(1)
                    mac = match.group(2).upper()
                    vendor = match.group(3).strip() or None
                    seen_ips.add(ip)
                    devices.append(
                        DeviceInfo(ip=ip, mac=mac, vendor=vendor)
                    )
            if devices:
                logger.info(
                    f"ARP scan (arp-scan) found {len(devices)} devices"
                )
                return devices

        # --- Attempt 2: read kernel ARP cache via /proc/net/arp ---
        try:
            stdout, stderr, returncode = self._run_command(
                ["cat", "/proc/net/arp"], timeout=5
            )
            if returncode == 0 and stdout:
                try:
                    network = ipaddress.IPv4Network(target, strict=False)
                except ValueError:
                    network = None

                for line in stdout.splitlines()[1:]:  # skip header
                    parts = line.split()
                    if len(parts) >= 4:
                        ip = parts[0]
                        mac = parts[3].upper()
                        # Skip incomplete entries
                        if mac == "00:00:00:00:00:00":
                            continue
                        # Filter to target network if possible
                        if network is not None:
                            try:
                                if ipaddress.IPv4Address(ip) not in network:
                                    continue
                            except ValueError:
                                continue
                        devices.append(DeviceInfo(ip=ip, mac=mac))

                if devices:
                    logger.info(
                        f"ARP cache read found {len(devices)} devices"
                    )
                    return devices
        except Exception as e:
            logger.debug(f"ARP cache read failed: {e}")

        # --- Attempt 3: arp -an ---
        stdout, stderr, returncode = self._run_command(
            ["arp", "-an"], timeout=5
        )
        if returncode == 0 and stdout:
            try:
                network = ipaddress.IPv4Network(target, strict=False)
            except ValueError:
                network = None

            for line in stdout.splitlines():
                match = re.search(
                    r'\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:]{17})',
                    line,
                )
                if match:
                    ip = match.group(1)
                    mac = match.group(2).upper()
                    if network is not None:
                        try:
                            if ipaddress.IPv4Address(ip) not in network:
                                continue
                        except ValueError:
                            continue
                    devices.append(DeviceInfo(ip=ip, mac=mac))

            if devices:
                logger.info(
                    f"ARP table (arp -an) found {len(devices)} devices"
                )

        return devices

    # ------------------------------------------------------------------
    # Nmap XML parsing
    # ------------------------------------------------------------------

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

                # Attempt OS guess from nmap os detection elements
                os_guess = None
                os_elem = host.find('os')
                if os_elem is not None:
                    osmatch = os_elem.find('osmatch')
                    if osmatch is not None:
                        os_guess = osmatch.get('name')

                device = DeviceInfo(
                    ip=ip,
                    mac=mac,
                    hostname=hostname,
                    vendor=vendor,
                    open_ports=open_ports,
                    services=services,
                    os_guess=os_guess,
                )

                devices.append(device)
                logger.debug(f"Parsed device: {device}")

        except ET.ParseError as e:
            logger.error(f"Error parsing nmap XML: {e}")
        except Exception as e:
            logger.error(f"Unexpected error parsing nmap output: {e}")

        return devices

    # ------------------------------------------------------------------
    # Network scan (main entry point)
    # ------------------------------------------------------------------

    def scan_network(
        self,
        target: Optional[str] = None,
        service_detection: bool = False,
        measure_latency: bool = True,
    ) -> List[DeviceInfo]:
        """
        Scan network for devices.

        If nmap fails the scan falls back to ARP-based discovery.
        When *measure_latency* is True, each discovered device is
        pinged to record round-trip latency.

        Args:
            target: Target network/host (CIDR or IP). If None, auto-detect.
            service_detection: Perform service version detection
            measure_latency: Ping each device to measure latency

        Returns:
            List of discovered DeviceInfo objects
        """
        # Rate-limit check
        if self._is_scan_throttled():
            logger.info("Returning cached results due to rate limiting")
            return self.devices

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

        devices: List[DeviceInfo] = []

        if returncode != 0:
            logger.error(f"nmap scan failed: {stderr}")
            logger.info("Attempting ARP scan fallback")
            try:
                devices = self._arp_scan_fallback(target)
            except Exception as e:
                logger.error(f"ARP scan fallback also failed: {e}")
        else:
            # Parse nmap results
            devices = self._parse_nmap_xml(stdout)

        # Detect gateway and tag the device if present
        gateway_ip = self.get_gateway_ip()
        if gateway_ip:
            for device in devices:
                if device.ip == gateway_ip and not device.hostname:
                    device.hostname = "gateway"

        # Measure latency for each discovered device
        if measure_latency and devices:
            for device in devices:
                try:
                    latency = self.ping_host(device.ip, count=1, timeout=1)
                    device.latency_ms = latency
                except Exception as e:
                    logger.debug(
                        f"Latency measurement failed for {device.ip}: {e}"
                    )

        self.devices = devices
        self.last_scan_time = datetime.now()

        logger.info(f"Scan complete. Found {len(devices)} devices.")
        return devices

    # ------------------------------------------------------------------
    # WiFi metrics
    # ------------------------------------------------------------------

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
        stdout, stderr, returncode = self._run_command(
            ["iwconfig", interface], timeout=5
        )

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

        # Noise level
        noise_match = re.search(r'Noise level[=:](-?\d+)\s*dBm', stdout)
        if noise_match:
            noise_floor = int(noise_match.group(1))

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
        stdout, stderr, returncode = self._run_command(
            ["iw", "dev", interface, "link"], timeout=5
        )

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

        # Get bit rate and noise from station dump
        stdout2, _, returncode2 = self._run_command(
            ["iw", "dev", interface, "station", "dump"], timeout=5
        )
        bit_rate = None
        noise_floor = None
        if returncode2 == 0:
            bitrate_match = re.search(r'tx bitrate:\s*(\S+\s+\S+)', stdout2)
            if bitrate_match:
                bit_rate = bitrate_match.group(1)

        # Attempt to read noise from survey dump
        stdout3, _, returncode3 = self._run_command(
            ["iw", "dev", interface, "survey", "dump"], timeout=5
        )
        if returncode3 == 0:
            noise_match = re.search(r'noise:\s*(-?\d+)\s*dBm', stdout3)
            if noise_match:
                noise_floor = int(noise_match.group(1))

        return WiFiMetrics(
            interface=interface,
            ssid=ssid,
            signal_strength=signal_strength,
            noise_floor=noise_floor,
            bit_rate=bit_rate,
            frequency=frequency,
        )

    # ------------------------------------------------------------------
    # WiFi network scanning
    # ------------------------------------------------------------------

    def scan_wifi_networks(self, interface: Optional[str] = None) -> List[Dict]:
        """
        Scan for available WiFi networks.

        Each network dictionary may include ``channel_utilization``
        (estimated percentage of airtime used on that channel) and a
        ``band`` classification.

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
        stdout, stderr, returncode = self._run_command(
            ["sudo", "iw", "dev", iface, "scan"], timeout=30
        )

        if returncode != 0:
            logger.error(f"WiFi scan failed: {stderr}")
            return []

        # Parse scan results
        networks: List[Dict] = []
        current_network: Dict = {}

        for line in stdout.split('\n'):
            line = line.strip()

            # New BSS (network)
            if line.startswith('BSS '):
                if current_network:
                    self._enrich_wifi_network(current_network)
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
                signal_match = re.search(r'signal:\s*(-?\d+\.?\d*)\s*dBm', line)
                if signal_match:
                    current_network['signal'] = float(signal_match.group(1))

            # Frequency
            elif line.startswith('freq:'):
                freq = line.split(':', 1)[1].strip()
                try:
                    current_network['frequency'] = int(freq)
                except ValueError:
                    pass

            # Channel
            elif 'DS Parameter set: channel' in line:
                channel_match = re.search(r'channel\s*(\d+)', line)
                if channel_match:
                    current_network['channel'] = int(channel_match.group(1))

            # BSS Load / channel utilization (from 802.11e QoS)
            elif 'channel utilisation' in line.lower() or 'channel utilization' in line.lower():
                util_match = re.search(r'(\d+)/(\d+)', line)
                if util_match:
                    try:
                        numerator = int(util_match.group(1))
                        denominator = int(util_match.group(2))
                        if denominator > 0:
                            current_network['channel_utilization'] = round(
                                (numerator / denominator) * 100, 1
                            )
                    except (ValueError, ZeroDivisionError):
                        pass

            # Station count (BSS Load element)
            elif 'station count' in line.lower():
                count_match = re.search(r'(\d+)', line)
                if count_match:
                    current_network['station_count'] = int(count_match.group(1))

        # Add last network
        if current_network:
            self._enrich_wifi_network(current_network)
            networks.append(current_network)

        # Compute per-channel utilization estimate based on AP density
        self._estimate_channel_utilization(networks)

        logger.info(f"Found {len(networks)} WiFi networks")
        return networks

    @staticmethod
    def _enrich_wifi_network(network: Dict) -> None:
        """Add derived fields (band classification) to a network dict."""
        freq = network.get('frequency')
        if freq is not None:
            if 2400 <= freq < 2500:
                network['band'] = '2.4GHz'
            elif 5000 <= freq < 6000:
                network['band'] = '5GHz'
            elif 5925 <= freq <= 7125:
                network['band'] = '6GHz'
            else:
                network['band'] = 'Unknown'

    @staticmethod
    def _estimate_channel_utilization(networks: List[Dict]) -> None:
        """Estimate channel utilization from AP density when BSS Load
        is not available.

        For each channel, count how many APs are present. A rough
        heuristic assigns ~15% utilization per AP on the same channel
        (capped at 100%).  This estimate is only applied to networks
        that lack an explicit ``channel_utilization`` value.
        """
        channel_counts: Dict[int, int] = defaultdict(int)
        for net in networks:
            ch = net.get('channel')
            if ch is not None:
                channel_counts[ch] += 1

        for net in networks:
            if 'channel_utilization' not in net:
                ch = net.get('channel')
                if ch is not None and ch in channel_counts:
                    estimated = min(channel_counts[ch] * 15.0, 100.0)
                    net['channel_utilization_estimated'] = round(estimated, 1)

    # ------------------------------------------------------------------
    # Scan summaries
    # ------------------------------------------------------------------

    def get_scan_summary(self) -> Dict:
        """
        Get summary of last scan.

        Returns:
            Dictionary with scan summary information
        """
        return {
            "last_scan_time": (
                self.last_scan_time.isoformat() if self.last_scan_time else None
            ),
            "device_count": len(self.devices),
            "devices": [device.to_dict() for device in self.devices],
            "interface": self.interface,
        }

    def get_network_summary(self) -> Dict:
        """Return aggregated summary data about the most recent scan.

        Includes device counts broken down by reachability status,
        gateway information, and latency statistics.

        Returns:
            Dictionary with aggregated network summary.
        """
        total = len(self.devices)
        reachable = 0
        unreachable = 0
        latencies: List[float] = []

        for device in self.devices:
            if device.latency_ms is not None:
                reachable += 1
                latencies.append(device.latency_ms)
            else:
                unreachable += 1

        avg_latency = (
            round(sum(latencies) / len(latencies), 2) if latencies else None
        )
        min_latency = round(min(latencies), 2) if latencies else None
        max_latency = round(max(latencies), 2) if latencies else None

        gateway_ip = self.get_gateway_ip()
        gateway_device = None
        if gateway_ip:
            for device in self.devices:
                if device.ip == gateway_ip:
                    gateway_device = device.to_dict()
                    break

        return {
            "last_scan_time": (
                self.last_scan_time.isoformat() if self.last_scan_time else None
            ),
            "interface": self.interface,
            "device_count": total,
            "devices_by_status": {
                "reachable": reachable,
                "unreachable": unreachable,
            },
            "latency": {
                "average_ms": avg_latency,
                "min_ms": min_latency,
                "max_ms": max_latency,
            },
            "gateway": {
                "ip": gateway_ip,
                "device": gateway_device,
            },
        }


if __name__ == "__main__":
    # Test the scanner
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    scanner = NetworkScanner()

    # Detect gateway
    gw = scanner.get_gateway_ip()
    if gw:
        print(f"Default gateway: {gw}")
        latency = scanner.ping_host(gw)
        if latency is not None:
            print(f"  Gateway latency: {latency:.1f} ms")

    print("\nScanning network...")
    devices = scanner.scan_network()

    print(f"\nFound {len(devices)} devices:\n")
    for device in devices:
        print(f"IP: {device.ip}")
        print(f"  MAC: {device.mac or 'N/A'}")
        print(f"  Hostname: {device.hostname or 'Unknown'}")
        print(f"  Vendor: {device.vendor or 'Unknown'}")
        if device.latency_ms is not None:
            print(f"  Latency: {device.latency_ms:.1f} ms")
        if device.os_guess:
            print(f"  OS: {device.os_guess}")
        if device.open_ports:
            print(f"  Open Ports: {', '.join(map(str, device.open_ports))}")
        print()

    # Print network summary
    summary = scanner.get_network_summary()
    print("Network Summary:")
    print(f"  Total devices: {summary['device_count']}")
    print(f"  Reachable: {summary['devices_by_status']['reachable']}")
    print(f"  Unreachable: {summary['devices_by_status']['unreachable']}")
    if summary['latency']['average_ms'] is not None:
        print(f"  Avg latency: {summary['latency']['average_ms']} ms")
