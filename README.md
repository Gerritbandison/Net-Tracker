# Net-Tracker (NetMonDash v2.0.0)

AI-Powered Network Device Monitor Dashboard with real-time scanning, device categorization, security analysis, and WiFi optimization.

## Features

- **Real-time Network Scanning** - Automatic device discovery using nmap with ARP fallback
- **Device Categorization** - Auto-classify devices as routers, phones, IoT, servers, etc.
- **Security Analysis** - AI-powered and rule-based security vulnerability detection
- **WiFi Monitoring** - Signal strength tracking, band analysis, channel optimization
- **Dark Mode Dashboard** - Modern responsive web UI with dark/light theme
- **WebSocket Updates** - Real-time push notifications via WebSocket
- **Network Timeline** - Track device joins, leaves, port changes, and events
- **Latency Monitoring** - Ping-based latency measurement for all devices
- **Data Export** - Export device data and scan results as CSV/JSON
- **Desktop Notifications** - System notifications for critical events

## Quick Start

```bash
cd netmondash
pip install -r requirements.txt
python main.py
```

Dashboard available at `http://localhost:5000`

See [netmondash/README.md](netmondash/README.md) for detailed documentation.