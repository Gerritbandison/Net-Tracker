"""
NetMonDash Configuration Module

Contains all configuration constants and default values for the application.
"""

import os
from pathlib import Path
from typing import Dict, List

# Project Paths
PROJECT_ROOT = Path(__file__).parent
LOGS_DIR = PROJECT_ROOT / "logs"
DB_DIR = PROJECT_ROOT / "data"
STATIC_DIR = PROJECT_ROOT / "static"
TEMPLATES_DIR = PROJECT_ROOT / "dashboard" / "templates"

# Ensure directories exist
LOGS_DIR.mkdir(exist_ok=True)
DB_DIR.mkdir(exist_ok=True)

# Database Configuration
DATABASE_URL = f"sqlite:///{DB_DIR}/netmondash.db"
DB_ECHO = False  # Set to True for SQL query debugging

# Web Server Configuration
DEFAULT_WEB_PORT = 5000
DEFAULT_HOST = "0.0.0.0"
WEBSOCKET_HEARTBEAT_INTERVAL = 30  # seconds

# Network Scanning Configuration
DEFAULT_SCAN_INTERVAL = 30  # seconds
NMAP_PING_SWEEP_ARGS = ["-sn", "-T4"]
NMAP_SERVICE_DETECTION_ARGS = ["-sV", "-T4", "--version-light"]
NMAP_TIMEOUT = 300  # seconds
SCAN_THREAD_POOL_SIZE = 4

# Lightweight Discovery Configuration (ARP-based)
DISCOVERY_ACTIVE_INTERVAL = 15  # seconds between active ARP sweeps
DISCOVERY_STALE_TIMEOUT = 120   # seconds before marking a device offline
DISCOVERY_BATCH_INTERVAL = 1.0  # seconds to coalesce events before flushing
DEEP_SCAN_INTERVAL = 1800       # seconds between full nmap re-scans (30 min)
DEEP_SCAN_NEW_DEVICE_DELAY = 5  # seconds to wait before deep-scanning a new device

# WiFi Signal Thresholds (dBm)
SIGNAL_EXCELLENT = -50
SIGNAL_GOOD = -60
SIGNAL_FAIR = -70
SIGNAL_POOR = -80
SIGNAL_CRITICAL = -90

# A9000 Adapter Detection
NETGEAR_VENDOR_ID = "0846"
REALTEK_CHIPSET_IDS = ["RTL8852BE", "RTL8852CE"]
A9000_INTERFACE_PATTERNS = ["wlan", "wlp"]

# Supported WiFi Bands
WIFI_BANDS: Dict[str, Dict[str, List[int]]] = {
    "2.4GHz": {
        "frequency_range": [2400, 2500],
        "channels": list(range(1, 14))
    },
    "5GHz": {
        "frequency_range": [5000, 6000],
        "channels": [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165]
    },
    "6GHz": {
        "frequency_range": [5925, 7125],
        "channels": list(range(1, 234, 4))  # 6GHz channels
    }
}

# AI Configuration
OLLAMA_API_URL = "http://localhost:11434"
OLLAMA_MODEL = "llama3.1:8b"
OLLAMA_TIMEOUT = 10  # seconds
OLLAMA_MAX_RETRIES = 3
OLLAMA_RETRY_DELAY = 2  # seconds

# AI Analysis Prompts
AI_SYSTEM_PROMPT = """You are a network security and optimization expert.
Analyze the provided network scan data and provide actionable insights.
Focus on security threats, performance issues, and optimization opportunities.
Keep recommendations concise and practical."""

AI_SECURITY_ANALYSIS_PROMPT = """Analyze this network scan data for security issues:
{scan_data}

Identify:
1. Unknown or suspicious devices
2. Unusual open ports or services
3. Potential security vulnerabilities
4. Recommended security actions

Provide response in JSON format:
{{
  "findings": [
    {{"severity": "critical|warning|info", "description": "...", "recommendation": "...", "command": "..."}}
  ]
}}"""

AI_NETWORK_HEALTH_PROMPT = """Analyze this network scan data for health and performance:
{scan_data}

Identify:
1. Devices with connectivity issues
2. Bandwidth or performance concerns
3. Network congestion indicators
4. Optimization opportunities

Provide response in JSON format:
{{
  "findings": [
    {{"severity": "critical|warning|info", "description": "...", "recommendation": "...", "command": "..."}}
  ]
}}"""

AI_WIFI_OPTIMIZATION_PROMPT = """Analyze this WiFi scan data for optimization:
{scan_data}

Identify:
1. Signal strength issues
2. Channel interference
3. Band switching opportunities
4. Coverage gaps

Provide response in JSON format:
{{
  "findings": [
    {{"severity": "critical|warning|info", "description": "...", "recommendation": "...", "command": "..."}}
  ]
}}"""

# Alert Severity Levels
SEVERITY_CRITICAL = "critical"
SEVERITY_WARNING = "warning"
SEVERITY_INFO = "info"

# Notification Configuration
ENABLE_DESKTOP_NOTIFICATIONS = True
NOTIFICATION_TIMEOUT = 5000  # milliseconds
NOTIFY_ON_NEW_DEVICE = True
NOTIFY_ON_CRITICAL_ALERT = True

# Logging Configuration
LOG_FILE = LOGS_DIR / "netmondash.log"
LOG_MAX_BYTES = 10 * 1024 * 1024  # 10MB
LOG_BACKUP_COUNT = 5
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

# Security Configuration
REQUIRE_SUDO_CONFIRMATION = True
ALLOWED_SUDO_COMMANDS = ["nmap", "iw", "nmcli", "iwconfig"]
MAX_COMMAND_LENGTH = 500

# Export Configuration
EXPORT_FORMATS = ["json", "csv"]
MAX_EXPORT_RECORDS = 10000

# UI Configuration
ITEMS_PER_PAGE = 50
REFRESH_INTERVAL_MS = 30000  # 30 seconds
CHART_UPDATE_INTERVAL_MS = 5000  # 5 seconds

# Device Tracking
DEVICE_OFFLINE_THRESHOLD = 300  # seconds (5 minutes)
DEVICE_HISTORY_RETENTION_DAYS = 30

# Data Cleanup
CLEANUP_INTERVAL_HOURS = 6  # Run cleanup every 6 hours

# Dangerous Ports for Security Analysis
DANGEROUS_PORTS = {
    21: "FTP - unencrypted file transfer",
    23: "Telnet - unencrypted remote access",
    25: "SMTP - mail relay (potential spam relay)",
    135: "MSRPC - Windows RPC",
    137: "NetBIOS Name Service",
    138: "NetBIOS Datagram",
    139: "NetBIOS Session",
    445: "SMB - file sharing (ransomware target)",
    1433: "MSSQL - database",
    1434: "MSSQL Browser",
    3306: "MySQL - database",
    3389: "RDP - remote desktop",
    5432: "PostgreSQL - database",
    5900: "VNC - remote desktop",
    5901: "VNC - remote desktop",
    6379: "Redis - in-memory database",
    8080: "HTTP Proxy - alternate web",
    8443: "HTTPS Alternate",
    9200: "Elasticsearch",
    27017: "MongoDB - database",
}

# MAC Vendor Lookup
MAC_VENDOR_CACHE_HOURS = 24
ENABLE_MAC_VENDOR_LOOKUP = True

# Version
APP_VERSION = "2.0.0"

# Environment Variable Overrides
def get_env_int(key: str, default: int) -> int:
    """Get integer from environment variable with fallback to default."""
    try:
        return int(os.getenv(key, default))
    except (ValueError, TypeError):
        return default

def get_env_bool(key: str, default: bool) -> bool:
    """Get boolean from environment variable with fallback to default."""
    value = os.getenv(key, str(default)).lower()
    return value in ("true", "1", "yes", "on")

# Apply environment overrides
WEB_PORT = get_env_int("NETMONDASH_PORT", DEFAULT_WEB_PORT)
SCAN_INTERVAL = get_env_int("NETMONDASH_SCAN_INTERVAL", DEFAULT_SCAN_INTERVAL)
ENABLE_AI = get_env_bool("NETMONDASH_ENABLE_AI", True)
DEBUG_MODE = get_env_bool("NETMONDASH_DEBUG", False)
