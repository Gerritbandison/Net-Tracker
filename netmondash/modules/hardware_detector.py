"""
Hardware Detector Module

Detects network interfaces and identifies the Netgear A9000 USB WiFi adapter.
"""

import logging
import subprocess
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import netifaces
import psutil

from config import (
    NETGEAR_VENDOR_ID,
    REALTEK_CHIPSET_IDS,
    A9000_INTERFACE_PATTERNS,
    WIFI_BANDS,
)

logger = logging.getLogger(__name__)


class InterfaceInfo:
    """Network interface information container."""

    def __init__(
        self,
        name: str,
        interface_type: str,
        mac: str,
        is_a9000: bool = False,
        supported_bands: Optional[List[str]] = None,
        ip_addresses: Optional[List[str]] = None,
        is_up: bool = False,
    ):
        self.name = name
        self.type = interface_type
        self.mac = mac
        self.is_a9000 = is_a9000
        self.supported_bands = supported_bands or []
        self.ip_addresses = ip_addresses or []
        self.is_up = is_up

    def to_dict(self) -> Dict:
        """Convert to dictionary representation."""
        return {
            "interface_name": self.name,
            "type": self.type,
            "mac": self.mac,
            "is_a9000": self.is_a9000,
            "supported_bands": self.supported_bands,
            "ip_addresses": self.ip_addresses,
            "is_up": self.is_up,
        }

    def __repr__(self) -> str:
        return f"<InterfaceInfo {self.name} ({self.type}) - A9000: {self.is_a9000}>"


def run_command(cmd: List[str], timeout: int = 5) -> Tuple[str, str, int]:
    """
    Execute a shell command and return stdout, stderr, and return code.

    Args:
        cmd: Command and arguments as list
        timeout: Command timeout in seconds

    Returns:
        Tuple of (stdout, stderr, return_code)
    """
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        logger.warning(f"Command timed out: {' '.join(cmd)}")
        return "", f"Command timed out after {timeout}s", -1
    except FileNotFoundError:
        logger.error(f"Command not found: {cmd[0]}")
        return "", f"Command not found: {cmd[0]}", -1
    except Exception as e:
        logger.error(f"Error running command {' '.join(cmd)}: {e}")
        return "", str(e), -1


def check_lsusb_for_a9000() -> bool:
    """
    Check if Netgear A9000 adapter is detected via lsusb.

    Returns:
        True if A9000 is detected, False otherwise
    """
    stdout, stderr, returncode = run_command(["lsusb"])

    if returncode != 0:
        logger.warning("lsusb command failed, cannot detect A9000 via USB")
        return False

    # Check for Netgear vendor ID
    if NETGEAR_VENDOR_ID.lower() in stdout.lower():
        logger.info(f"Detected Netgear device with vendor ID {NETGEAR_VENDOR_ID}")
        return True

    # Check for Realtek chipsets commonly used in A9000
    for chipset in REALTEK_CHIPSET_IDS:
        if chipset.lower() in stdout.lower():
            logger.info(f"Detected Realtek chipset: {chipset}")
            return True

    logger.debug("A9000 adapter not detected via lsusb")
    return False


def get_interface_driver(interface_name: str) -> Optional[str]:
    """
    Get the driver name for a network interface.

    Args:
        interface_name: Network interface name (e.g., 'wlan0')

    Returns:
        Driver name or None if not found
    """
    uevent_path = Path(f"/sys/class/net/{interface_name}/device/uevent")

    if not uevent_path.exists():
        return None

    try:
        content = uevent_path.read_text()
        for line in content.split('\n'):
            if line.startswith('DRIVER='):
                driver = line.split('=', 1)[1].strip()
                logger.debug(f"Interface {interface_name} uses driver: {driver}")
                return driver
    except Exception as e:
        logger.debug(f"Error reading driver info for {interface_name}: {e}")

    return None


def check_interface_is_a9000(interface_name: str, usb_detected: bool) -> bool:
    """
    Check if a specific interface is the A9000 adapter.

    Args:
        interface_name: Network interface name
        usb_detected: Whether A9000 was detected via lsusb

    Returns:
        True if interface is likely the A9000
    """
    if not usb_detected:
        return False

    # Check if interface name matches expected patterns
    if not any(interface_name.startswith(pattern) for pattern in A9000_INTERFACE_PATTERNS):
        return False

    # Check driver information
    driver = get_interface_driver(interface_name)
    if driver:
        # Common drivers for Realtek WiFi 7 adapters
        if any(chipset.lower() in driver.lower() for chipset in REALTEK_CHIPSET_IDS):
            logger.info(f"Interface {interface_name} identified as A9000 (driver: {driver})")
            return True

    # If USB was detected and this is a wireless interface, it's likely the A9000
    if interface_name.startswith('wl'):
        logger.info(f"Interface {interface_name} likely the A9000 (USB detected, wireless interface)")
        return True

    return False


def get_wireless_capabilities(interface_name: str) -> List[str]:
    """
    Detect supported WiFi bands for an interface.

    Args:
        interface_name: Network interface name

    Returns:
        List of supported bands (e.g., ['2.4GHz', '5GHz', '6GHz'])
    """
    supported_bands = []

    # Try using 'iw' to get interface capabilities
    stdout, stderr, returncode = run_command(["iw", "phy"], timeout=10)

    if returncode != 0:
        logger.debug("Could not query wireless capabilities with 'iw phy'")
        # Fallback: assume basic dual-band for wireless interfaces
        return ["2.4GHz", "5GHz"]

    # Parse frequency bands from iw output
    frequencies = re.findall(r'\* (\d+) MHz', stdout)

    for freq_str in frequencies:
        freq = int(freq_str)

        if 2400 <= freq <= 2500 and "2.4GHz" not in supported_bands:
            supported_bands.append("2.4GHz")
        elif 5000 <= freq <= 6000 and "5GHz" not in supported_bands:
            supported_bands.append("5GHz")
        elif 5925 <= freq <= 7125 and "6GHz" not in supported_bands:
            supported_bands.append("6GHz")

    logger.debug(f"Interface {interface_name} supports bands: {supported_bands}")
    return supported_bands


def get_interface_mac(interface_name: str) -> Optional[str]:
    """
    Get MAC address for a network interface.

    Args:
        interface_name: Network interface name

    Returns:
        MAC address or None if not available
    """
    try:
        addrs = netifaces.ifaddresses(interface_name)
        if netifaces.AF_LINK in addrs:
            mac = addrs[netifaces.AF_LINK][0].get('addr')
            return mac
    except (ValueError, KeyError, IndexError):
        pass

    # Fallback: read from sysfs
    mac_path = Path(f"/sys/class/net/{interface_name}/address")
    if mac_path.exists():
        try:
            return mac_path.read_text().strip()
        except Exception:
            pass

    return None


def get_interface_ip_addresses(interface_name: str) -> List[str]:
    """
    Get IP addresses assigned to an interface.

    Args:
        interface_name: Network interface name

    Returns:
        List of IP addresses
    """
    ip_addresses = []

    try:
        addrs = netifaces.ifaddresses(interface_name)

        # IPv4 addresses
        if netifaces.AF_INET in addrs:
            for addr_info in addrs[netifaces.AF_INET]:
                ip = addr_info.get('addr')
                if ip:
                    ip_addresses.append(ip)

        # IPv6 addresses
        if netifaces.AF_INET6 in addrs:
            for addr_info in addrs[netifaces.AF_INET6]:
                ip = addr_info.get('addr')
                if ip and not ip.startswith('fe80'):  # Exclude link-local
                    ip_addresses.append(ip)

    except (ValueError, KeyError):
        pass

    return ip_addresses


def is_interface_up(interface_name: str) -> bool:
    """
    Check if a network interface is up.

    Args:
        interface_name: Network interface name

    Returns:
        True if interface is up
    """
    try:
        stats = psutil.net_if_stats().get(interface_name)
        if stats:
            return stats.isup
    except Exception as e:
        logger.debug(f"Error checking if {interface_name} is up: {e}")

    return False


def determine_interface_type(interface_name: str) -> str:
    """
    Determine the type of network interface.

    Args:
        interface_name: Network interface name

    Returns:
        Interface type: 'wireless', 'ethernet', 'loopback', or 'other'
    """
    if interface_name == 'lo':
        return 'loopback'

    # Check if wireless directory exists
    wireless_path = Path(f"/sys/class/net/{interface_name}/wireless")
    if wireless_path.exists():
        return 'wireless'

    # Check interface name patterns
    if interface_name.startswith(('wl', 'wlan')):
        return 'wireless'
    elif interface_name.startswith(('eth', 'en')):
        return 'ethernet'

    return 'other'


def get_interface_info(interface_name: str, a9000_detected: bool = False) -> Optional[InterfaceInfo]:
    """
    Get detailed information about a network interface.

    Args:
        interface_name: Network interface name
        a9000_detected: Whether A9000 was detected via USB scan

    Returns:
        InterfaceInfo object or None if interface cannot be queried
    """
    try:
        interface_type = determine_interface_type(interface_name)
        mac = get_interface_mac(interface_name)

        if not mac:
            logger.debug(f"Skipping interface {interface_name} (no MAC address)")
            return None

        is_a9000 = False
        supported_bands = []

        if interface_type == 'wireless':
            is_a9000 = check_interface_is_a9000(interface_name, a9000_detected)
            supported_bands = get_wireless_capabilities(interface_name)

        ip_addresses = get_interface_ip_addresses(interface_name)
        is_up = is_interface_up(interface_name)

        return InterfaceInfo(
            name=interface_name,
            interface_type=interface_type,
            mac=mac,
            is_a9000=is_a9000,
            supported_bands=supported_bands,
            ip_addresses=ip_addresses,
            is_up=is_up,
        )

    except Exception as e:
        logger.error(f"Error getting info for interface {interface_name}: {e}")
        return None


def detect_network_interfaces() -> List[InterfaceInfo]:
    """
    Detect all network interfaces and identify the A9000 adapter.

    Returns:
        List of InterfaceInfo objects for all detected interfaces
    """
    logger.info("Starting network interface detection")

    # First check if A9000 is connected via USB
    a9000_detected = check_lsusb_for_a9000()

    if a9000_detected:
        logger.info("Netgear A9000 adapter detected via USB")
    else:
        logger.warning("Netgear A9000 adapter not detected via USB")

    # Get all network interfaces
    all_interfaces = netifaces.interfaces()
    logger.debug(f"Found {len(all_interfaces)} network interfaces: {all_interfaces}")

    interfaces = []

    for iface_name in all_interfaces:
        # Skip loopback
        if iface_name == 'lo':
            continue

        info = get_interface_info(iface_name, a9000_detected)
        if info:
            interfaces.append(info)
            logger.info(f"Detected interface: {info}")

    # Sort interfaces: A9000 first, then wireless, then ethernet
    def sort_key(info: InterfaceInfo) -> Tuple[int, str]:
        if info.is_a9000:
            return (0, info.name)
        elif info.type == 'wireless':
            return (1, info.name)
        elif info.type == 'ethernet':
            return (2, info.name)
        else:
            return (3, info.name)

    interfaces.sort(key=sort_key)

    logger.info(f"Detected {len(interfaces)} usable network interfaces")
    return interfaces


def get_preferred_interface() -> Optional[InterfaceInfo]:
    """
    Get the preferred network interface for scanning.

    Priority:
    1. A9000 adapter (if detected and up)
    2. Any wireless interface (if up)
    3. Any ethernet interface (if up)
    4. First available interface

    Returns:
        InterfaceInfo for preferred interface or None if none available
    """
    interfaces = detect_network_interfaces()

    if not interfaces:
        logger.error("No network interfaces detected")
        return None

    # Try to find A9000 that is up
    for iface in interfaces:
        if iface.is_a9000 and iface.is_up:
            logger.info(f"Using A9000 adapter: {iface.name}")
            return iface

    # Try to find any wireless interface that is up
    for iface in interfaces:
        if iface.type == 'wireless' and iface.is_up:
            logger.info(f"Using wireless interface: {iface.name}")
            if not iface.is_a9000:
                logger.warning("A9000 not detected, using standard wireless interface")
            return iface

    # Try to find any ethernet interface that is up
    for iface in interfaces:
        if iface.type == 'ethernet' and iface.is_up:
            logger.info(f"Using ethernet interface: {iface.name}")
            logger.warning("No wireless interface available, using wired connection")
            return iface

    # Fallback to first available interface
    first_iface = interfaces[0]
    logger.warning(f"No interfaces are up, defaulting to: {first_iface.name}")
    return first_iface


if __name__ == "__main__":
    # Test the hardware detector
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    print("Detecting network interfaces...\n")
    interfaces = detect_network_interfaces()

    for iface in interfaces:
        print(f"Interface: {iface.name}")
        print(f"  Type: {iface.type}")
        print(f"  MAC: {iface.mac}")
        print(f"  Is A9000: {iface.is_a9000}")
        print(f"  Bands: {', '.join(iface.supported_bands) or 'N/A'}")
        print(f"  IPs: {', '.join(iface.ip_addresses) or 'None'}")
        print(f"  Status: {'UP' if iface.is_up else 'DOWN'}")
        print()

    print("\nPreferred interface:")
    preferred = get_preferred_interface()
    if preferred:
        print(f"  {preferred.name} ({preferred.type})")
    else:
        print("  None available")
