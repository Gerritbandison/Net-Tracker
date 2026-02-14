"""
NetMonDash Modules Package

Core functionality modules for network monitoring and analysis.
"""

from .hardware_detector import detect_network_interfaces, get_preferred_interface
from .scanner import NetworkScanner, DeviceInfo, WiFiMetrics
from .ai_analyzer import AIAnalyzer, AIRecommendation
from .database import (
    init_database, DatabaseManager,
    Device, Scan, Alert, NetworkEvent, BandwidthSample,
    DEVICE_CATEGORIES, guess_device_category,
)
from .notifier import Notifier

__all__ = [
    "detect_network_interfaces",
    "get_preferred_interface",
    "NetworkScanner",
    "DeviceInfo",
    "WiFiMetrics",
    "AIAnalyzer",
    "AIRecommendation",
    "init_database",
    "DatabaseManager",
    "Device",
    "Scan",
    "Alert",
    "NetworkEvent",
    "BandwidthSample",
    "DEVICE_CATEGORIES",
    "guess_device_category",
    "Notifier",
]
