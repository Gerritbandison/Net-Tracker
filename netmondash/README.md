# NetMonDash - AI-Powered Network Device Monitor Dashboard

![Python Version](https://img.shields.io/badge/python-3.10+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Status](https://img.shields.io/badge/status-production--ready-brightgreen.svg)

NetMonDash is a comprehensive network monitoring dashboard that combines powerful network scanning capabilities with AI-driven security analysis. Built specifically to leverage the Netgear Nighthawk A9000 USB WiFi adapter's WiFi 7 tri-band capabilities, it provides real-time monitoring, device discovery, and intelligent recommendations for network optimization and security.

## Features

### Network Monitoring
- **Automatic Device Discovery**: Scan and track all devices on your network
- **Real-time Updates**: WebSocket-based live dashboard updates
- **Service Detection**: Identify running services and open ports
- **Device History**: Track when devices join and leave the network
- **MAC Vendor Lookup**: Automatic identification of device manufacturers

### WiFi Analysis
- **WiFi 7 Tri-band Support**: 2.4GHz, 5GHz, and 6GHz band analysis
- **Signal Strength Monitoring**: Real-time signal quality tracking
- **Channel Interference Detection**: Identify congested channels
- **Band Optimization**: AI-powered recommendations for optimal band selection
- **A9000 Adapter Detection**: Automatic detection and configuration

### AI-Powered Insights
- **Security Analysis**: Identify suspicious devices and unusual network activity
- **Network Health Monitoring**: Detect performance issues and bottlenecks
- **WiFi Optimization**: Recommendations for improving wireless performance
- **Actionable Commands**: Copy-paste ready terminal commands for security actions

### User Interface
- **Modern Dashboard**: Clean, responsive design with Tailwind CSS
- **Interactive Charts**: Plotly.js visualizations for network trends
- **Real-time Alerts**: Desktop notifications for critical events
- **Data Export**: CSV and JSON export capabilities
- **Device Management**: Add notes and track device information

## Screenshots

*[Placeholder for dashboard screenshots]*

## Prerequisites

### System Requirements
- **OS**: Ubuntu 22.04+, Linux Mint 21+, or compatible Linux distribution
- **Python**: 3.10 or higher
- **RAM**: Minimum 2GB (4GB recommended)
- **Network**: Active network interface (wired or wireless)

### Required Software

```bash
# System packages
sudo apt update
sudo apt install -y \
    nmap \
    wireless-tools \
    net-tools \
    libnotify-bin \
    python3 \
    python3-pip \
    python3-venv

# For Netgear A9000 WiFi adapter (if using)
sudo apt install -y firmware-realtek
```

### Optional: Ollama for AI Analysis

NetMonDash uses [Ollama](https://ollama.ai/) for local AI analysis.

```bash
# Install Ollama
curl -fsSL https://ollama.ai/install.sh | sh

# Pull the default model
ollama pull llama3.1:8b

# Start Ollama service
ollama serve
```

## Netgear A9000 Setup Guide

The Netgear Nighthawk A9000 is a WiFi 7 tri-band USB adapter that provides cutting-edge wireless capabilities.

### Driver Installation

1. **Check if adapter is detected:**
```bash
lsusb | grep -i netgear
# or
lsusb | grep -i realtek
```

2. **Install Realtek drivers:**
```bash
sudo apt install firmware-realtek
# or for newer kernels
sudo apt install rtl8852be-dkms
```

3. **Verify interface detection:**
```bash
iwconfig
# Look for wlan0, wlp*, or similar wireless interface
```

### Troubleshooting A9000

If the adapter is not detected:

1. **Check USB connection:**
```bash
dmesg | tail -30
# Look for USB device connection messages
```

2. **Reload wireless drivers:**
```bash
sudo modprobe -r rtl8852be
sudo modprobe rtl8852be
```

3. **Check kernel version:**
```bash
uname -r
# WiFi 7 support requires kernel 5.19+
```

4. **Manual driver compilation** (if needed):
```bash
git clone https://github.com/lwfinger/rtl8852be.git
cd rtl8852be
make
sudo make install
sudo modprobe rtl8852be
```

### Verifying Tri-Band Support

```bash
# Check supported frequencies
iw list | grep -A 20 "Frequencies"

# Should show:
# - 2.4 GHz band (2412-2484 MHz)
# - 5 GHz band (5170-5835 MHz)
# - 6 GHz band (5935-7115 MHz)
```

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/netmondash.git
cd netmondash
```

### 2. Create Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Python Dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### 4. Grant nmap Capabilities (Recommended)

To run nmap without sudo:

```bash
sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip $(which nmap)
```

### 5. Initialize Database

The database will be created automatically on first run, but you can verify:

```bash
python3 main.py --help
```

## Usage

### Basic Usage

```bash
# Run with auto-detected network interface
python3 main.py

# Specify network interface
python3 main.py --interface wlan0

# Custom port
python3 main.py --port 8080

# Adjust scan interval (seconds)
python3 main.py --scan-interval 60

# Disable AI analysis
python3 main.py --no-ai

# Verbose logging
python3 main.py --verbose
```

### Access the Dashboard

Once running, open your browser to:
```
http://localhost:5000
```

### Expected Output

```
================================================================
NetMonDash - AI-Powered Network Monitor
================================================================
INFO - Detecting network interfaces...
INFO - Using interface: wlan0 (wireless)
INFO - Netgear A9000 adapter detected!
INFO - Supported bands: 2.4GHz, 5GHz, 6GHz
INFO - Database initialized
INFO - Scanner initialized (interval: 30s)
INFO - AI analyzer initialized
INFO - Starting web server on 127.0.0.1:5000
INFO - Dashboard URL: http://localhost:5000
```

## Configuration

### Environment Variables

Create a `.env` file in the project root:

```bash
# Web Server
NETMONDASH_HOST=127.0.0.1
NETMONDASH_PORT=5000
NETMONDASH_ALLOWED_ORIGINS=http://localhost:5000,http://127.0.0.1:5000
NETMONDASH_ALLOW_CREDENTIALS=false

# Scanning
NETMONDASH_SCAN_INTERVAL=30

# AI Analysis
NETMONDASH_ENABLE_AI=true
OLLAMA_API_URL=http://localhost:11434
OLLAMA_MODEL=llama3.1:8b

# Logging
NETMONDASH_DEBUG=false
```

To expose the dashboard on your LAN, set `NETMONDASH_HOST=0.0.0.0` and update
`NETMONDASH_ALLOWED_ORIGINS` to the exact origin(s) you will access from.

### Configuration File

Edit `config.py` to customize:

- Scan intervals and timeouts
- WiFi signal thresholds
- Alert severity levels
- Database retention periods
- Notification preferences

## API Documentation

### REST API Endpoints

#### Devices
- `GET /api/devices` - List all devices
- `GET /api/devices/{mac}` - Get device details
- `POST /api/devices/{mac}/notes` - Update device notes

#### Scans
- `GET /api/scans/recent` - Recent scans
- `GET /api/scans/history?hours=24` - Scan history
- `POST /api/scan/trigger` - Trigger manual scan

#### WiFi
- `GET /api/wifi/metrics` - Current WiFi metrics
- `GET /api/wifi/networks` - Scan available networks

#### Alerts
- `GET /api/alerts` - Get alerts
- `POST /api/alerts/{id}/acknowledge` - Acknowledge alert

#### AI Analysis
- `GET /api/insights` - Quick insights
- `POST /api/analyze/security` - Run security analysis
- `POST /api/analyze/health` - Run health analysis

#### Export
- `GET /api/export?data_type=devices&format=json` - Export data
- `GET /api/export?data_type=devices&format=csv` - Export as CSV

#### Statistics
- `GET /api/stats` - Dashboard statistics
- `GET /health` - Health check

### WebSocket API

Connect to `ws://localhost:5000/ws` for real-time updates.

**Client Messages:**
```json
{"type": "ping"}
{"type": "subscribe", "channel": "all"}
{"type": "get_stats"}
```

**Server Messages:**
```json
{"type": "scan_update", "data": {...}}
{"type": "device_update", "event": "new", "data": {...}}
{"type": "alert", "data": {...}}
{"type": "stats", "data": {...}}
```

## Systemd Service Setup

### 1. Create Service File

```bash
sudo cp systemd/netmondash.service /etc/systemd/system/
```

### 2. Edit Service File

```bash
sudo nano /etc/systemd/system/netmondash.service
```

Update paths to match your installation:
```ini
ExecStart=/home/YOUR_USER/netmondash/venv/bin/python main.py
WorkingDirectory=/home/YOUR_USER/netmondash
User=YOUR_USER
```

### 3. Enable and Start Service

```bash
# Reload systemd
sudo systemctl daemon-reload

# Enable service to start on boot
sudo systemctl enable netmondash

# Start service
sudo systemctl start netmondash

# Check status
sudo systemctl status netmondash

# View logs
sudo journalctl -u netmondash -f
```

## Development

### Running Tests

```bash
# Install test dependencies
pip install pytest pytest-asyncio pytest-cov

# Run tests
pytest tests/

# With coverage
pytest --cov=modules --cov=dashboard tests/
```

### Project Structure

```
netmondash/
├── main.py                 # Application entry point
├── config.py              # Configuration constants
├── requirements.txt       # Python dependencies
├── modules/              # Core modules
│   ├── __init__.py
│   ├── hardware_detector.py
│   ├── scanner.py
│   ├── ai_analyzer.py
│   ├── database.py
│   └── notifier.py
├── dashboard/            # Web dashboard
│   ├── __init__.py
│   ├── app.py
│   ├── routes.py
│   ├── websocket.py
│   └── templates/       # Jinja2 templates
├── static/              # Static assets
│   ├── css/
│   └── js/
├── tests/               # Unit tests
├── logs/                # Application logs
├── data/                # SQLite database
└── systemd/             # Service configuration
```

## Security Considerations

### Running as Non-Root

NetMonDash is designed to run as a non-root user. Use `setcap` for nmap:

```bash
sudo setcap cap_net_raw+ep $(which nmap)
```

### Firewall Configuration

```bash
# Allow NetMonDash web interface
sudo ufw allow 5000/tcp

# Block external access (optional)
sudo ufw allow from 192.168.1.0/24 to any port 5000
```

### Data Privacy

- All data is stored locally in SQLite
- No external services are contacted (except Ollama API)
- Network scans are performed only on local subnet
- MAC addresses are hashed before display (optional feature)

## Troubleshooting

### Common Issues

**1. "nmap: command not found"**
```bash
sudo apt install nmap
```

**2. "Permission denied" when scanning**
```bash
sudo setcap cap_net_raw+ep $(which nmap)
```

**3. "Cannot connect to Ollama"**
```bash
# Check if Ollama is running
curl http://localhost:11434/api/tags

# Start Ollama
ollama serve
```

**4. "No network interface detected"**
```bash
# List interfaces
ip addr show

# Check wireless interfaces
iwconfig

# Restart NetworkManager
sudo systemctl restart NetworkManager
```

**5. WiFi adapter not detected**
```bash
# Check USB devices
lsusb

# Check kernel modules
lsmod | grep rtl

# Check dmesg for errors
dmesg | grep -i firmware
```

### Logs

Check application logs:
```bash
tail -f logs/netmondash.log
```

## Contributing

Contributions are welcome! Please follow these guidelines:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Code Style

- Follow PEP 8 for Python code
- Use type hints for all functions
- Add docstrings for public functions
- Write tests for new features

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [FastAPI](https://fastapi.tiangolo.com/) - Modern web framework
- [Ollama](https://ollama.ai/) - Local AI inference
- [Nmap](https://nmap.org/) - Network scanning
- [Plotly](https://plotly.com/) - Interactive charts
- [Tailwind CSS](https://tailwindcss.com/) - UI styling

## Support

- **Issues**: [GitHub Issues](https://github.com/yourusername/netmondash/issues)
- **Documentation**: [Wiki](https://github.com/yourusername/netmondash/wiki)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/netmondash/discussions)

## Roadmap

- [ ] Mobile app support
- [ ] Email alerts
- [ ] Bandwidth monitoring
- [ ] Port scanning scheduler
- [ ] Multi-network support
- [ ] Custom AI model training
- [ ] Dark mode UI
- [ ] Network topology visualization

---

**Made with ❤️ for network enthusiasts and security professionals**
