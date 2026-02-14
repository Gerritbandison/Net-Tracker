"""
Network Scanner Module

Performs network device discovery and WiFi analysis with enhanced
ARP fallback scanning, ping latency measurement, gateway detection,
channel utilization tracking, SNR monitoring, scan rate limiting,
concurrent parallel scanning, scan profiles, service fingerprinting,
traceroute-based topology discovery, and bandwidth estimation.
"""

import logging
import subprocess
import re
import json
import time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Callable
from pathlib import Path
import ipaddress
from collections import defaultdict
from dataclasses import dataclass, field

from config import (
    NMAP_PING_SWEEP_ARGS,
    NMAP_SERVICE_DETECTION_ARGS,
    NMAP_TIMEOUT,
    SIGNAL_EXCELLENT,
    SIGNAL_GOOD,
    SIGNAL_FAIR,
    SIGNAL_POOR,
    SIGNAL_CRITICAL,
    SCAN_THREAD_POOL_SIZE,
)

logger = logging.getLogger(__name__)

# Scan rate limiting defaults
_MIN_SCAN_INTERVAL_SECONDS = 10
_DEFAULT_PING_TIMEOUT = 2
_DEFAULT_PING_COUNT = 3
_ARP_SCAN_TIMEOUT = 30

# Service fingerprint database for well-known ports
SERVICE_FINGERPRINTS: Dict[int, Dict[str, str]] = {
    20: {"name": "FTP-Data", "category": "file_transfer"},
    21: {"name": "FTP", "category": "file_transfer"},
    22: {"name": "SSH", "category": "remote_access"},
    23: {"name": "Telnet", "category": "remote_access"},
    25: {"name": "SMTP", "category": "email"},
    53: {"name": "DNS", "category": "infrastructure"},
    67: {"name": "DHCP-Server", "category": "infrastructure"},
    68: {"name": "DHCP-Client", "category": "infrastructure"},
    69: {"name": "TFTP", "category": "file_transfer"},
    80: {"name": "HTTP", "category": "web"},
    110: {"name": "POP3", "category": "email"},
    123: {"name": "NTP", "category": "infrastructure"},
    135: {"name": "MS-RPC", "category": "windows"},
    137: {"name": "NetBIOS-NS", "category": "windows"},
    138: {"name": "NetBIOS-DGM", "category": "windows"},
    139: {"name": "NetBIOS-SSN", "category": "windows"},
    143: {"name": "IMAP", "category": "email"},
    161: {"name": "SNMP", "category": "monitoring"},
    162: {"name": "SNMP-Trap", "category": "monitoring"},
    389: {"name": "LDAP", "category": "directory"},
    443: {"name": "HTTPS", "category": "web"},
    445: {"name": "SMB", "category": "file_sharing"},
    465: {"name": "SMTPS", "category": "email"},
    514: {"name": "Syslog", "category": "monitoring"},
    515: {"name": "LPD", "category": "printing"},
    548: {"name": "AFP", "category": "file_sharing"},
    554: {"name": "RTSP", "category": "streaming"},
    587: {"name": "SMTP-Submission", "category": "email"},
    631: {"name": "IPP", "category": "printing"},
    636: {"name": "LDAPS", "category": "directory"},
    993: {"name": "IMAPS", "category": "email"},
    995: {"name": "POP3S", "category": "email"},
    1080: {"name": "SOCKS", "category": "proxy"},
    1433: {"name": "MSSQL", "category": "database"},
    1521: {"name": "Oracle", "category": "database"},
    1883: {"name": "MQTT", "category": "iot"},
    2049: {"name": "NFS", "category": "file_sharing"},
    3306: {"name": "MySQL", "category": "database"},
    3389: {"name": "RDP", "category": "remote_access"},
    5060: {"name": "SIP", "category": "voip"},
    5222: {"name": "XMPP", "category": "messaging"},
    5353: {"name": "mDNS", "category": "infrastructure"},
    5432: {"name": "PostgreSQL", "category": "database"},
    5900: {"name": "VNC", "category": "remote_access"},
    5985: {"name": "WinRM", "category": "remote_access"},
    6379: {"name": "Redis", "category": "database"},
    8080: {"name": "HTTP-Alt", "category": "web"},
    8443: {"name": "HTTPS-Alt", "category": "web"},
    8883: {"name": "MQTT-TLS", "category": "iot"},
    8888: {"name": "HTTP-Alt2", "category": "web"},
    9100: {"name": "JetDirect", "category": "printing"},
    9200: {"name": "Elasticsearch", "category": "database"},
    27017: {"name": "MongoDB", "category": "database"},
    62078: {"name": "iDevice-Sync", "category": "mobile"},
}


# Scan profiles
@dataclass
class ScanProfile:
    """Configuration profile for network scanning."""
    name: str
    description: str
    nmap_args: List[str]
    service_detection: bool = False
    os_detection: bool = False
    measure_latency: bool = True
    parallel_pings: bool = True
    traceroute: bool = False
    timeout: int = NMAP_TIMEOUT
    ping_count: int = 1
    ping_timeout: int = 1


SCAN_PROFILES: Dict[str, ScanProfile] = {
    "quick": ScanProfile(
        name="quick",
        description="Fast ping sweep - discover online devices only",
        nmap_args=["-sn", "-T5", "--max-retries", "1"],
        service_detection=False,
        os_detection=False,
        measure_latency=True,
        parallel_pings=True,
        traceroute=False,
        timeout=60,
        ping_count=1,
        ping_timeout=1,
    ),
    "standard": ScanProfile(
        name="standard",
        description="Standard scan with service detection",
        nmap_args=["-sn", "-T4"],
        service_detection=False,
        os_detection=False,
        measure_latency=True,
        parallel_pings=True,
        traceroute=False,
        timeout=NMAP_TIMEOUT,
        ping_count=2,
        ping_timeout=2,
    ),
    "deep": ScanProfile(
        name="deep",
        description="Deep scan with service and OS detection",
        nmap_args=["-sV", "-O", "-T4", "--version-light"],
        service_detection=True,
        os_detection=True,
        measure_latency=True,
        parallel_pings=True,
        traceroute=True,
        timeout=600,
        ping_count=3,
        ping_timeout=2,
    ),
    "stealth": ScanProfile(
        name="stealth",
        description="Slow, stealthy scan to avoid detection",
        nmap_args=["-sS", "-T2", "--max-retries", "2"],
        service_detection=False,
        os_detection=False,
        measure_latency=False,
        parallel_pings=False,
        traceroute=False,
        timeout=900,
        ping_count=1,
        ping_timeout=3,
    ),
}


@dataclass
class NetworkLink:
    """Represents a network hop/link discovered via traceroute."""
    hop_number: int
    ip: str
    hostname: Optional[str] = None
    latency_ms: Optional[float] = None
    is_gateway: bool = False

    def to_dict(self) -> Dict:
        return {
            "hop": self.hop_number,
            "ip": self.ip,
            "hostname": self.hostname,
            "latency_ms": self.latency_ms,
            "is_gateway": self.is_gateway,
        }


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
        packet_loss: Optional[float] = None,
        jitter_ms: Optional[float] = None,
        ttl: Optional[int] = None,
        service_categories: Optional[Dict[str, int]] = None,
        traceroute_hops: Optional[List[NetworkLink]] = None,
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
        self.packet_loss = packet_loss
        self.jitter_ms = jitter_ms
        self.ttl = ttl
        self.service_categories = service_categories or {}
        self.traceroute_hops = traceroute_hops or []

    def get_service_fingerprints(self) -> Dict[int, Dict[str, str]]:
        """Get service fingerprint data for all open ports."""
        result = {}
        for port in self.open_ports:
            if port in SERVICE_FINGERPRINTS:
                result[port] = SERVICE_FINGERPRINTS[port]
            elif port in self.services:
                result[port] = {"name": self.services[port], "category": "unknown"}
        return result

    def compute_service_categories(self) -> Dict[str, int]:
        """Compute count of services by category."""
        categories: Dict[str, int] = defaultdict(int)
        for port in self.open_ports:
            fp = SERVICE_FINGERPRINTS.get(port)
            if fp:
                categories[fp["category"]] += 1
            else:
                categories["unknown"] += 1
        self.service_categories = dict(categories)
        return self.service_categories

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
            "packet_loss": self.packet_loss,
            "jitter_ms": self.jitter_ms,
            "ttl": self.ttl,
            "service_categories": self.service_categories,
            "service_fingerprints": self.get_service_fingerprints(),
            "traceroute_hops": [h.to_dict() for h in self.traceroute_hops],
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
        channel_width: Optional[str] = None,
        security: Optional[str] = None,
        bssid: Optional[str] = None,
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
        self.channel_width = channel_width
        self.security = security
        self.bssid = bssid

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

    def get_signal_percentage(self) -> Optional[int]:
        """Convert dBm to approximate percentage (0-100)."""
        if self.signal_strength is None:
            return None
        # Map -100 dBm = 0%, -30 dBm = 100%
        pct = max(0, min(100, 2 * (self.signal_strength + 100)))
        return pct

    def needs_attention(self) -> bool:
        """Check if signal strength requires attention."""
        if self.signal_strength is None:
            return False
        return self.signal_strength < SIGNAL_FAIR

    def get_health_indicators(self) -> Dict[str, str]:
        """Get detailed health indicators for the WiFi connection."""
        indicators = {}

        # Signal quality
        if self.signal_strength is not None:
            if self.signal_strength >= SIGNAL_EXCELLENT:
                indicators["signal"] = "excellent"
            elif self.signal_strength >= SIGNAL_GOOD:
                indicators["signal"] = "good"
            elif self.signal_strength >= SIGNAL_FAIR:
                indicators["signal"] = "fair"
            elif self.signal_strength >= SIGNAL_POOR:
                indicators["signal"] = "poor"
            else:
                indicators["signal"] = "critical"

        # SNR quality
        if self.snr is not None:
            if self.snr >= 40:
                indicators["snr"] = "excellent"
            elif self.snr >= 25:
                indicators["snr"] = "good"
            elif self.snr >= 15:
                indicators["snr"] = "fair"
            else:
                indicators["snr"] = "poor"

        # Channel utilization
        if self.channel_utilization is not None:
            if self.channel_utilization < 30:
                indicators["channel_load"] = "low"
            elif self.channel_utilization < 60:
                indicators["channel_load"] = "moderate"
            elif self.channel_utilization < 80:
                indicators["channel_load"] = "high"
            else:
                indicators["channel_load"] = "saturated"

        return indicators

    def to_dict(self) -> Dict:
        """Convert to dictionary representation."""
        return {
            "interface": self.interface,
            "ssid": self.ssid,
            "bssid": self.bssid,
            "signal_strength": self.signal_strength,
            "signal_quality": self.get_signal_quality(),
            "signal_percentage": self.get_signal_percentage(),
            "noise_floor": self.noise_floor,
            "snr": self.snr,
            "bit_rate": self.bit_rate,
            "frequency": self.frequency,
            "band": self.band,
            "channel": self.channel,
            "channel_width": self.channel_width,
            "link_quality": self.link_quality,
            "channel_utilization": self.channel_utilization,
            "security": self.security,
            "needs_attention": self.needs_attention(),
            "health_indicators": self.get_health_indicators(),
        }


class NetworkScanner:
    """Network scanner for device discovery and WiFi analysis."""

    def __init__(
        self,
        interface: Optional[str] = None,
        min_scan_interval: int = _MIN_SCAN_INTERVAL_SECONDS,
        thread_pool_size: int = SCAN_THREAD_POOL_SIZE,
    ):
        """
        Initialize network scanner.

        Args:
            interface: Network interface to use for scanning
            min_scan_interval: Minimum seconds between consecutive scans
            thread_pool_size: Number of threads for parallel operations
        """
        self.interface = interface
        self.last_scan_time: Optional[datetime] = None
        self.devices: List[DeviceInfo] = []
        self._min_scan_interval = min_scan_interval
        self._gateway_ip: Optional[str] = None
        self._thread_pool_size = thread_pool_size
        self._scan_history: List[Dict] = []
        self._max_scan_history = 100
        self._progress_callback: Optional[Callable[[str, float], None]] = None
        self._current_profile: str = "standard"
        self._topology_cache: Dict[str, List[NetworkLink]] = {}

    def set_progress_callback(self, callback: Callable[[str, float], None]):
        """Set a progress callback for scan status updates.

        Args:
            callback: Function(stage_name, progress_0_to_1)
        """
        self._progress_callback = callback

    def _report_progress(self, stage: str, progress: float):
        """Report scan progress to callback if set."""
        if self._progress_callback:
            try:
                self._progress_callback(stage, min(1.0, max(0.0, progress)))
            except Exception:
                pass

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
        """Check if scanning should be throttled based on rate limit."""
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
        """Get network CIDR range for scanning."""
        iface = interface or self.interface

        cmd = ["ip", "-o", "-f", "inet", "addr", "show"]
        if iface:
            cmd.append(iface)

        stdout, stderr, returncode = self._run_command(cmd, timeout=5)

        if returncode != 0:
            logger.error("Failed to get network range")
            return None

        match = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)', stdout)
        if match:
            ip_addr = match.group(1)
            prefix = match.group(2)
            network = ipaddress.IPv4Network(f"{ip_addr}/{prefix}", strict=False)
            cidr = str(network)
            logger.debug(f"Detected network range: {cidr}")
            return cidr

        logger.warning("Could not determine network range")
        return None

    def get_local_ip(self) -> Optional[str]:
        """Get the local IP address of the scanning interface."""
        iface = self.interface
        cmd = ["ip", "-o", "-f", "inet", "addr", "show"]
        if iface:
            cmd.append(iface)

        stdout, stderr, returncode = self._run_command(cmd, timeout=5)
        if returncode == 0:
            match = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)', stdout)
            if match:
                return match.group(1)
        return None

    # ------------------------------------------------------------------
    # Gateway detection
    # ------------------------------------------------------------------

    def get_gateway_ip(self) -> Optional[str]:
        """Detect the default gateway/router IP from the system routing table."""
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
    # Ping latency measurement (enhanced with jitter + packet loss)
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

    def ping_host_detailed(
        self,
        ip: str,
        count: int = _DEFAULT_PING_COUNT,
        timeout: int = _DEFAULT_PING_TIMEOUT,
    ) -> Dict:
        """Measure detailed ping statistics including jitter, packet loss, and TTL.

        Args:
            ip: Target IP address.
            count: Number of ping packets.
            timeout: Per-packet timeout in seconds.

        Returns:
            Dictionary with avg_ms, min_ms, max_ms, jitter_ms, packet_loss, ttl.
        """
        result = {
            "avg_ms": None,
            "min_ms": None,
            "max_ms": None,
            "jitter_ms": None,
            "packet_loss": None,
            "ttl": None,
        }

        cmd = ["ping", "-c", str(count), "-W", str(timeout), ip]
        stdout, stderr, returncode = self._run_command(
            cmd, timeout=count * timeout + 5
        )
        if returncode not in (0, 1):
            return result

        # Parse RTT stats
        rtt_match = re.search(
            r'rtt\s+min/avg/max/mdev\s*=\s*([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)\s*ms',
            stdout,
        )
        if rtt_match:
            try:
                result["min_ms"] = float(rtt_match.group(1))
                result["avg_ms"] = float(rtt_match.group(2))
                result["max_ms"] = float(rtt_match.group(3))
                result["jitter_ms"] = float(rtt_match.group(4))
            except ValueError:
                pass

        # Parse packet loss
        loss_match = re.search(r'(\d+)%\s+packet\s+loss', stdout)
        if loss_match:
            try:
                result["packet_loss"] = float(loss_match.group(1))
            except ValueError:
                pass

        # Parse TTL from first reply
        ttl_match = re.search(r'ttl=(\d+)', stdout)
        if ttl_match:
            try:
                result["ttl"] = int(ttl_match.group(1))
            except ValueError:
                pass

        return result

    # ------------------------------------------------------------------
    # Parallel ping for multiple hosts
    # ------------------------------------------------------------------

    def ping_hosts_parallel(
        self,
        ips: List[str],
        count: int = 1,
        timeout: int = 1,
        detailed: bool = False,
    ) -> Dict[str, Dict]:
        """Ping multiple hosts concurrently using a thread pool.

        Args:
            ips: List of IP addresses to ping.
            count: Number of ping packets per host.
            timeout: Per-packet timeout.
            detailed: If True, use ping_host_detailed for richer stats.

        Returns:
            Dictionary mapping IP to ping result.
        """
        results: Dict[str, Dict] = {}

        if not ips:
            return results

        def _ping_one(ip: str) -> Tuple[str, Dict]:
            if detailed:
                data = self.ping_host_detailed(ip, count=count, timeout=timeout)
                return ip, data
            else:
                latency = self.ping_host(ip, count=count, timeout=timeout)
                return ip, {"avg_ms": latency}

        with ThreadPoolExecutor(max_workers=self._thread_pool_size) as pool:
            futures = {pool.submit(_ping_one, ip): ip for ip in ips}
            completed = 0
            total = len(futures)
            for future in as_completed(futures):
                try:
                    ip, data = future.result()
                    results[ip] = data
                except Exception as e:
                    ip = futures[future]
                    results[ip] = {"avg_ms": None, "error": str(e)}
                    logger.debug(f"Parallel ping failed for {ip}: {e}")
                completed += 1
                self._report_progress("latency_measurement", completed / total)

        return results

    # ------------------------------------------------------------------
    # Traceroute for topology discovery
    # ------------------------------------------------------------------

    def traceroute_host(self, ip: str, max_hops: int = 15) -> List[NetworkLink]:
        """Run traceroute to discover network path to a host.

        Args:
            ip: Target IP address.
            max_hops: Maximum number of hops.

        Returns:
            List of NetworkLink objects representing the path.
        """
        hops: List[NetworkLink] = []
        gateway_ip = self.get_gateway_ip()

        cmd = ["traceroute", "-n", "-m", str(max_hops), "-w", "2", "-q", "1", ip]
        stdout, stderr, returncode = self._run_command(cmd, timeout=max_hops * 3 + 10)

        if returncode != 0:
            logger.debug(f"Traceroute to {ip} failed: {stderr}")
            return hops

        for line in stdout.splitlines()[1:]:  # Skip header
            parts = line.strip().split()
            if len(parts) < 2:
                continue

            try:
                hop_num = int(parts[0])
            except ValueError:
                continue

            hop_ip = parts[1] if parts[1] != "*" else None
            latency = None

            if hop_ip:
                # Try to parse latency
                for part in parts[2:]:
                    try:
                        latency = float(part.replace("ms", "").strip())
                        break
                    except ValueError:
                        continue

                hops.append(NetworkLink(
                    hop_number=hop_num,
                    ip=hop_ip,
                    latency_ms=latency,
                    is_gateway=(hop_ip == gateway_ip),
                ))

        return hops

    # ------------------------------------------------------------------
    # ARP scan fallback
    # ------------------------------------------------------------------

    def _arp_scan_fallback(self, target: str) -> List[DeviceInfo]:
        """Discover devices using ARP when nmap is unavailable or fails."""
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

                for line in stdout.splitlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 4:
                        ip = parts[0]
                        mac = parts[3].upper()
                        if mac == "00:00:00:00:00:00":
                            continue
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
        """Parse nmap XML output into DeviceInfo objects."""
        devices = []

        try:
            root = ET.fromstring(xml_output)

            for host in root.findall('host'):
                status = host.find('status')
                if status is None or status.get('state') != 'up':
                    continue

                address_elem = host.find("address[@addrtype='ipv4']")
                if address_elem is None:
                    continue

                ip = address_elem.get('addr')
                if not ip:
                    continue

                mac = None
                vendor = None
                mac_elem = host.find("address[@addrtype='mac']")
                if mac_elem is not None:
                    mac = mac_elem.get('addr')
                    vendor = mac_elem.get('vendor')

                hostname = None
                hostnames = host.find('hostnames')
                if hostnames is not None:
                    hostname_elem = hostnames.find('hostname')
                    if hostname_elem is not None:
                        hostname = hostname_elem.get('name')

                open_ports = []
                services = {}
                ports = host.find('ports')
                if ports is not None:
                    for port in ports.findall('port'):
                        port_state = port.find('state')
                        if port_state is not None and port_state.get('state') == 'open':
                            port_id = int(port.get('portid', 0))
                            open_ports.append(port_id)

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

                os_guess = None
                os_elem = host.find('os')
                if os_elem is not None:
                    osmatch = os_elem.find('osmatch')
                    if osmatch is not None:
                        os_guess = osmatch.get('name')

                # Parse traceroute if present
                trace_hops = []
                trace_elem = host.find('trace')
                if trace_elem is not None:
                    gateway_ip = self.get_gateway_ip()
                    for hop in trace_elem.findall('hop'):
                        hop_ip = hop.get('ipaddr')
                        if hop_ip:
                            try:
                                hop_num = int(hop.get('ttl', 0))
                            except (ValueError, TypeError):
                                hop_num = 0
                            try:
                                hop_rtt = float(hop.get('rtt', 0))
                            except (ValueError, TypeError):
                                hop_rtt = None
                            trace_hops.append(NetworkLink(
                                hop_number=hop_num,
                                ip=hop_ip,
                                hostname=hop.get('host'),
                                latency_ms=hop_rtt,
                                is_gateway=(hop_ip == gateway_ip),
                            ))

                device = DeviceInfo(
                    ip=ip,
                    mac=mac,
                    hostname=hostname,
                    vendor=vendor,
                    open_ports=open_ports,
                    services=services,
                    os_guess=os_guess,
                    traceroute_hops=trace_hops,
                )
                device.compute_service_categories()

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
        profile: Optional[str] = None,
    ) -> List[DeviceInfo]:
        """
        Scan network for devices.

        Args:
            target: Target network/host (CIDR or IP). If None, auto-detect.
            service_detection: Perform service version detection
            measure_latency: Ping each device to measure latency
            profile: Scan profile name (quick, standard, deep, stealth)

        Returns:
            List of discovered DeviceInfo objects
        """
        # Rate-limit check
        if self._is_scan_throttled():
            logger.info("Returning cached results due to rate limiting")
            return self.devices

        # Resolve profile
        scan_profile = None
        if profile and profile in SCAN_PROFILES:
            scan_profile = SCAN_PROFILES[profile]
            self._current_profile = profile
            logger.info(f"Using scan profile: {scan_profile.name} - {scan_profile.description}")

        scan_start = time.time()
        self._report_progress("initializing", 0.0)
        logger.info("Starting network scan")

        # Determine target
        if target is None:
            target = self._get_network_range(self.interface)
            if target is None:
                logger.error("Could not determine scan target")
                return []

        self._report_progress("scanning", 0.1)

        # Build nmap command
        cmd = ["nmap", "-oX", "-"]  # Output XML to stdout

        if scan_profile:
            cmd.extend(scan_profile.nmap_args)
            if scan_profile.traceroute:
                cmd.append("--traceroute")
        elif service_detection:
            cmd.extend(NMAP_SERVICE_DETECTION_ARGS)
        else:
            cmd.extend(NMAP_PING_SWEEP_ARGS)

        if self.interface:
            cmd.extend(["-e", self.interface])

        cmd.append(target)

        # Execute scan
        scan_timeout = scan_profile.timeout if scan_profile else NMAP_TIMEOUT
        logger.info(f"Scanning {target} with command: {' '.join(cmd)}")
        stdout, stderr, returncode = self._run_command(cmd, timeout=scan_timeout)

        self._report_progress("parsing", 0.5)

        devices: List[DeviceInfo] = []

        if returncode != 0:
            logger.error(f"nmap scan failed: {stderr}")
            logger.info("Attempting ARP scan fallback")
            try:
                devices = self._arp_scan_fallback(target)
            except Exception as e:
                logger.error(f"ARP scan fallback also failed: {e}")
        else:
            devices = self._parse_nmap_xml(stdout)

        self._report_progress("post_processing", 0.7)

        # Detect gateway and tag the device if present
        gateway_ip = self.get_gateway_ip()
        if gateway_ip:
            for device in devices:
                if device.ip == gateway_ip and not device.hostname:
                    device.hostname = "gateway"

        # Measure latency for each discovered device
        should_measure = measure_latency
        if scan_profile is not None:
            should_measure = scan_profile.measure_latency

        use_parallel = scan_profile.parallel_pings if scan_profile else True
        ping_count = scan_profile.ping_count if scan_profile else 1
        ping_timeout = scan_profile.ping_timeout if scan_profile else 1

        if should_measure and devices:
            self._report_progress("latency_measurement", 0.75)

            if use_parallel and len(devices) > 1:
                # Parallel ping
                ips = [d.ip for d in devices]
                ping_results = self.ping_hosts_parallel(
                    ips, count=ping_count, timeout=ping_timeout, detailed=True
                )
                for device in devices:
                    data = ping_results.get(device.ip, {})
                    device.latency_ms = data.get("avg_ms")
                    device.packet_loss = data.get("packet_loss")
                    device.jitter_ms = data.get("jitter_ms")
                    device.ttl = data.get("ttl")
            else:
                # Sequential ping
                for i, device in enumerate(devices):
                    try:
                        latency = self.ping_host(
                            device.ip, count=ping_count, timeout=ping_timeout
                        )
                        device.latency_ms = latency
                    except Exception as e:
                        logger.debug(
                            f"Latency measurement failed for {device.ip}: {e}"
                        )
                    self._report_progress(
                        "latency_measurement",
                        0.75 + 0.2 * ((i + 1) / len(devices))
                    )

        # Compute service categories for all devices
        for device in devices:
            device.compute_service_categories()

        self.devices = devices
        self.last_scan_time = datetime.now()

        scan_duration = time.time() - scan_start

        # Record in scan history
        self._scan_history.append({
            "timestamp": self.last_scan_time.isoformat(),
            "device_count": len(devices),
            "profile": self._current_profile,
            "duration_seconds": round(scan_duration, 2),
            "target": target,
        })
        if len(self._scan_history) > self._max_scan_history:
            self._scan_history = self._scan_history[-self._max_scan_history:]

        self._report_progress("complete", 1.0)
        logger.info(
            f"Scan complete. Found {len(devices)} devices in {scan_duration:.2f}s "
            f"(profile: {self._current_profile})"
        )
        return devices

    # ------------------------------------------------------------------
    # WiFi metrics
    # ------------------------------------------------------------------

    def get_wifi_metrics(self, interface: Optional[str] = None) -> Optional[WiFiMetrics]:
        """Get WiFi signal metrics for an interface."""
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

        ssid = None
        signal_strength = None
        noise_floor = None
        bit_rate = None
        frequency = None
        link_quality = None

        ssid_match = re.search(r'ESSID:"([^"]+)"', stdout)
        if ssid_match:
            ssid = ssid_match.group(1)

        bitrate_match = re.search(r'Bit Rate[=:](\S+\s+\S+)', stdout)
        if bitrate_match:
            bit_rate = bitrate_match.group(1)

        freq_match = re.search(r'Frequency:([\d.]+\s+GHz)', stdout)
        if freq_match:
            frequency = freq_match.group(1)

        signal_match = re.search(r'Signal level[=:](-?\d+)\s*dBm', stdout)
        if signal_match:
            signal_strength = int(signal_match.group(1))

        noise_match = re.search(r'Noise level[=:](-?\d+)\s*dBm', stdout)
        if noise_match:
            noise_floor = int(noise_match.group(1))

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

        ssid = None
        signal_strength = None
        frequency = None
        bssid = None

        ssid_match = re.search(r'SSID:\s*(.+)', stdout)
        if ssid_match:
            ssid = ssid_match.group(1).strip()

        freq_match = re.search(r'freq:\s*(\d+)', stdout)
        if freq_match:
            freq_mhz = int(freq_match.group(1))
            frequency = f"{freq_mhz / 1000:.1f} GHz"

        signal_match = re.search(r'signal:\s*(-?\d+)\s*dBm', stdout)
        if signal_match:
            signal_strength = int(signal_match.group(1))

        bssid_match = re.search(r'Connected to\s+([0-9a-f:]{17})', stdout, re.IGNORECASE)
        if bssid_match:
            bssid = bssid_match.group(1)

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
            bssid=bssid,
        )

    # ------------------------------------------------------------------
    # WiFi network scanning
    # ------------------------------------------------------------------

    def scan_wifi_networks(self, interface: Optional[str] = None) -> List[Dict]:
        """Scan for available WiFi networks."""
        iface = interface or self.interface

        if not iface:
            logger.error("No interface specified for WiFi scan")
            return []

        logger.info(f"Scanning for WiFi networks on {iface}")

        stdout, stderr, returncode = self._run_command(
            ["sudo", "iw", "dev", iface, "scan"], timeout=30
        )

        if returncode != 0:
            logger.error(f"WiFi scan failed: {stderr}")
            return []

        networks: List[Dict] = []
        current_network: Dict = {}

        for line in stdout.split('\n'):
            line = line.strip()

            if line.startswith('BSS '):
                if current_network:
                    self._enrich_wifi_network(current_network)
                    networks.append(current_network)
                mac_match = re.search(r'BSS ([0-9a-f:]+)', line)
                current_network = {
                    'bssid': mac_match.group(1) if mac_match else None,
                }

            elif line.startswith('SSID:'):
                current_network['ssid'] = line.split(':', 1)[1].strip()

            elif 'signal:' in line:
                signal_match = re.search(r'signal:\s*(-?\d+\.?\d*)\s*dBm', line)
                if signal_match:
                    current_network['signal'] = float(signal_match.group(1))

            elif line.startswith('freq:'):
                freq = line.split(':', 1)[1].strip()
                try:
                    current_network['frequency'] = int(freq)
                except ValueError:
                    pass

            elif 'DS Parameter set: channel' in line:
                channel_match = re.search(r'channel\s*(\d+)', line)
                if channel_match:
                    current_network['channel'] = int(channel_match.group(1))

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

            elif 'station count' in line.lower():
                count_match = re.search(r'(\d+)', line)
                if count_match:
                    current_network['station_count'] = int(count_match.group(1))

            # Security/encryption parsing
            elif 'WPA' in line or 'RSN' in line:
                current_network.setdefault('security', [])
                if 'WPA2' in line or 'RSN' in line:
                    if 'WPA2' not in current_network.get('security', []):
                        current_network['security'].append('WPA2')
                elif 'WPA' in line:
                    if 'WPA' not in current_network.get('security', []):
                        current_network['security'].append('WPA')

            elif 'WEP' in line:
                current_network.setdefault('security', [])
                if 'WEP' not in current_network.get('security', []):
                    current_network['security'].append('WEP')

        # Add last network
        if current_network:
            self._enrich_wifi_network(current_network)
            networks.append(current_network)

        # Compute per-channel utilization estimate based on AP density
        self._estimate_channel_utilization(networks)

        # Sort by signal strength (strongest first)
        networks.sort(key=lambda n: n.get('signal', -999), reverse=True)

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

        # Format security as string
        if 'security' in network and isinstance(network['security'], list):
            network['security_str'] = '/'.join(network['security']) or 'Open'
        else:
            network['security_str'] = 'Unknown'

    @staticmethod
    def _estimate_channel_utilization(networks: List[Dict]) -> None:
        """Estimate channel utilization from AP density when BSS Load
        is not available."""
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
    # Channel analysis
    # ------------------------------------------------------------------

    def get_channel_analysis(self, interface: Optional[str] = None) -> Dict:
        """Analyze WiFi channel usage and recommend the best channel.

        Returns:
            Dictionary with channel usage data and recommendations.
        """
        networks = self.scan_wifi_networks(interface)
        if not networks:
            return {"error": "No networks found", "networks": []}

        # Count APs per channel, per band
        channel_data_24: Dict[int, Dict] = {}
        channel_data_5: Dict[int, Dict] = {}

        for net in networks:
            ch = net.get('channel')
            band = net.get('band', '')
            if ch is None:
                continue

            if '2.4' in band:
                if ch not in channel_data_24:
                    channel_data_24[ch] = {"ap_count": 0, "avg_signal": 0, "signals": []}
                channel_data_24[ch]["ap_count"] += 1
                sig = net.get('signal')
                if sig is not None:
                    channel_data_24[ch]["signals"].append(sig)
            elif '5' in band:
                if ch not in channel_data_5:
                    channel_data_5[ch] = {"ap_count": 0, "avg_signal": 0, "signals": []}
                channel_data_5[ch]["ap_count"] += 1
                sig = net.get('signal')
                if sig is not None:
                    channel_data_5[ch]["signals"].append(sig)

        # Compute averages
        for ch_data in [channel_data_24, channel_data_5]:
            for ch, data in ch_data.items():
                sigs = data.pop("signals", [])
                data["avg_signal"] = round(sum(sigs) / len(sigs), 1) if sigs else None

        # Recommend best 2.4GHz channel (1, 6, or 11)
        non_overlapping_24 = [1, 6, 11]
        best_24 = None
        best_24_score = float('inf')
        for ch in non_overlapping_24:
            score = channel_data_24.get(ch, {}).get("ap_count", 0)
            if score < best_24_score:
                best_24_score = score
                best_24 = ch

        # Recommend best 5GHz channel
        best_5 = None
        best_5_score = float('inf')
        all_5_channels = [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112,
                          116, 120, 124, 128, 132, 136, 140, 149, 153, 157, 161, 165]
        for ch in all_5_channels:
            score = channel_data_5.get(ch, {}).get("ap_count", 0)
            if score < best_5_score:
                best_5_score = score
                best_5 = ch

        return {
            "total_networks": len(networks),
            "channel_data_24ghz": channel_data_24,
            "channel_data_5ghz": channel_data_5,
            "recommended_24ghz": best_24,
            "recommended_5ghz": best_5,
            "networks": networks,
        }

    # ------------------------------------------------------------------
    # Scan summaries
    # ------------------------------------------------------------------

    def get_scan_summary(self) -> Dict:
        """Get summary of last scan."""
        return {
            "last_scan_time": (
                self.last_scan_time.isoformat() if self.last_scan_time else None
            ),
            "device_count": len(self.devices),
            "devices": [device.to_dict() for device in self.devices],
            "interface": self.interface,
            "profile": self._current_profile,
        }

    def get_network_summary(self) -> Dict:
        """Return aggregated summary data about the most recent scan."""
        total = len(self.devices)
        reachable = 0
        unreachable = 0
        latencies: List[float] = []
        service_summary: Dict[str, int] = defaultdict(int)
        os_counts: Dict[str, int] = defaultdict(int)

        for device in self.devices:
            if device.latency_ms is not None:
                reachable += 1
                latencies.append(device.latency_ms)
            else:
                unreachable += 1

            # Aggregate service categories
            for cat, count in device.service_categories.items():
                service_summary[cat] += count

            # Aggregate OS guesses
            if device.os_guess:
                os_counts[device.os_guess] += 1

        avg_latency = (
            round(sum(latencies) / len(latencies), 2) if latencies else None
        )
        min_latency = round(min(latencies), 2) if latencies else None
        max_latency = round(max(latencies), 2) if latencies else None
        p95_latency = None
        if latencies:
            sorted_lat = sorted(latencies)
            p95_idx = int(len(sorted_lat) * 0.95)
            p95_latency = round(sorted_lat[min(p95_idx, len(sorted_lat) - 1)], 2)

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
            "profile": self._current_profile,
            "device_count": total,
            "devices_by_status": {
                "reachable": reachable,
                "unreachable": unreachable,
            },
            "latency": {
                "average_ms": avg_latency,
                "min_ms": min_latency,
                "max_ms": max_latency,
                "p95_ms": p95_latency,
            },
            "gateway": {
                "ip": gateway_ip,
                "device": gateway_device,
            },
            "service_categories": dict(service_summary),
            "os_distribution": dict(os_counts),
            "scan_history": self._scan_history[-10:],
        }

    def get_available_profiles(self) -> Dict[str, Dict]:
        """Get available scan profiles with descriptions."""
        return {
            name: {
                "name": profile.name,
                "description": profile.description,
                "service_detection": profile.service_detection,
                "os_detection": profile.os_detection,
                "traceroute": profile.traceroute,
            }
            for name, profile in SCAN_PROFILES.items()
        }


if __name__ == "__main__":
    # Test the scanner
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    scanner = NetworkScanner()

    # Show available profiles
    print("Available scan profiles:")
    for name, info in scanner.get_available_profiles().items():
        print(f"  {name}: {info['description']}")

    # Detect gateway
    gw = scanner.get_gateway_ip()
    if gw:
        print(f"\nDefault gateway: {gw}")
        details = scanner.ping_host_detailed(gw)
        print(f"  Latency: {details['avg_ms']}ms (min={details['min_ms']}, max={details['max_ms']})")
        print(f"  Jitter: {details['jitter_ms']}ms")
        print(f"  Packet loss: {details['packet_loss']}%")
        print(f"  TTL: {details['ttl']}")

    print("\nScanning network (quick profile)...")
    devices = scanner.scan_network(profile="quick")

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
        if device.service_categories:
            print(f"  Service Categories: {device.service_categories}")
        print()

    # Print network summary
    summary = scanner.get_network_summary()
    print("Network Summary:")
    print(f"  Total devices: {summary['device_count']}")
    print(f"  Reachable: {summary['devices_by_status']['reachable']}")
    print(f"  Unreachable: {summary['devices_by_status']['unreachable']}")
    if summary['latency']['average_ms'] is not None:
        print(f"  Avg latency: {summary['latency']['average_ms']} ms")
        print(f"  P95 latency: {summary['latency']['p95_ms']} ms")
