"""
NetMonDash Modules Package

Core functionality modules for network monitoring and analysis.
"""

from .hardware_detector import detect_network_interfaces, get_preferred_interface
from .scanner import (
    NetworkScanner, DeviceInfo, WiFiMetrics,
    ScanProfile, SCAN_PROFILES, NetworkLink,
    SERVICE_FINGERPRINTS,
)
from .ai_analyzer import AIAnalyzer, AIRecommendation
from .database import (
    init_database, DatabaseManager,
    Device, Scan, Alert, NetworkEvent, BandwidthSample,
    DeviceChange, UptimeRecord,
    DEVICE_CATEGORIES, guess_device_category,
)
from .notifier import (
    Notifier, NotifierBackend, DesktopBackend,
    WebhookBackend, EmailBackend,
)
from .discovery import (
    DiscoveryEngine, DeviceRegistry, DiscoveredDevice,
    ActiveARPScanner, PassiveARPListener, EventBatcher,
    lookup_vendor, SCAPY_AVAILABLE, MAC_VENDOR_AVAILABLE,
)

__all__ = [
    "detect_network_interfaces",
    "get_preferred_interface",
    "NetworkScanner",
    "DeviceInfo",
    "WiFiMetrics",
    "ScanProfile",
    "SCAN_PROFILES",
    "NetworkLink",
    "SERVICE_FINGERPRINTS",
    "AIAnalyzer",
    "AIRecommendation",
    "init_database",
    "DatabaseManager",
    "Device",
    "Scan",
    "Alert",
    "NetworkEvent",
    "BandwidthSample",
    "DeviceChange",
    "UptimeRecord",
    "DEVICE_CATEGORIES",
    "guess_device_category",
    "Notifier",
    "NotifierBackend",
    "DesktopBackend",
    "WebhookBackend",
    "EmailBackend",
    "DiscoveryEngine",
    "DeviceRegistry",
    "DiscoveredDevice",
    "ActiveARPScanner",
    "PassiveARPListener",
    "EventBatcher",
    "lookup_vendor",
    "SCAPY_AVAILABLE",
    "MAC_VENDOR_AVAILABLE",
]
