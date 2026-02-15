# Net-Tracker (NetMonDash v2.1.0)

AI-Powered Network Device Monitor Dashboard with real-time ARP-based discovery, deep nmap scanning, device categorization, security analysis, and WiFi optimization.

## Quick Start

```bash
git clone https://github.com/Gerritbandison/Net-Tracker.git
cd Net-Tracker
./setup.sh      # creates venv, installs deps (one time)
./run.sh         # starts the dashboard
```

Dashboard opens at **http://localhost:5000**

### Options

```bash
./run.sh -p 8080          # custom port
./run.sh -i eth0          # specific network interface
./run.sh -i wlan0         # use WiFi interface
./run.sh --no-ai          # disable Ollama AI analysis
./run.sh -v               # verbose logging
./run.sh --help           # all options
```

### Manual Setup (if you prefer)

```bash
cd Net-Tracker
python3 -m venv venv
source venv/bin/activate
pip install -r netmondash/requirements.txt
cd netmondash
python main.py
```

## How It Works

### Two-Tier Discovery

| Tier | Method | Interval | CPU Cost | What it finds |
|------|--------|----------|----------|---------------|
| **1. ARP Discovery** (always-on) | Passive sniffing + active ARP sweep | 15 sec | Near zero | IP, MAC, vendor (OUI) |
| **2. Deep nmap Scan** (on-demand) | Full service/OS detection | 30 min or new device | Moderate | Ports, services, OS, hostname |

- **Passive ARP listener** sees devices the moment they send any traffic — zero extra bandwidth.
- **Active ARP sweep** pings every IP in your subnet in < 1 second.
- **nmap is optional** — the dashboard works fine without it using ARP-only discovery.

### Features

- **Real-time Device Discovery** — ARP-based, works on ethernet and WiFi
- **Device Categorization** — auto-classify via MAC OUI + port signatures
- **Security Analysis** — AI-powered (Ollama) and rule-based vulnerability detection
- **WiFi Monitoring** — signal strength, band analysis, channel optimization
- **Dark Mode Dashboard** — responsive web UI with keyboard shortcuts
- **WebSocket Updates** — batched real-time push notifications
- **Network Timeline** — track joins, leaves, port changes, IP changes
- **Latency Monitoring** — per-device ping latency, jitter, packet loss
- **Pluggable Alerts** — desktop, Slack, Discord, Teams, email (SMTP)
- **Data Export** — CSV/JSON export of devices, scans, events
- **Per-Device Deep Scan** — on-demand nmap scan from the dashboard

## Requirements

- **Python 3.10+**
- **nmap** (optional, for deep scans): `sudo apt install nmap`
- **Ollama** (optional, for AI): [ollama.com](https://ollama.com)

## Project Structure

```
Net-Tracker/
├── setup.sh              # One-command setup
├── run.sh                # One-command launcher
└── netmondash/
    ├── main.py           # App entry point + discovery/scan orchestration
    ├── config.py          # All configuration constants
    ├── requirements.txt
    ├── modules/
    │   ├── discovery.py       # ARP-based device discovery engine
    │   ├── scanner.py         # nmap deep scanning + WiFi metrics
    │   ├── database.py        # SQLAlchemy models + queries
    │   ├── ai_analyzer.py     # Ollama AI security/health analysis
    │   ├── notifier.py        # Desktop/Webhook/Email notifications
    │   └── hardware_detector.py
    ├── dashboard/
    │   ├── app.py             # FastAPI factory
    │   ├── routes.py          # REST API endpoints
    │   ├── websocket.py       # WebSocket manager
    │   └── templates/         # Jinja2 HTML templates
    ├── static/
    │   ├── css/style.css
    │   └── js/dashboard.js
    ├── tests/                 # 490 pytest tests
    └── systemd/               # Systemd service file
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/devices` | GET | List all devices (paginated, filterable) |
| `/api/devices/{mac}` | GET | Single device details |
| `/api/devices/{mac}/scan` | POST | Trigger deep scan for one device |
| `/api/discovery/stats` | GET | Live ARP discovery engine stats |
| `/api/discovery/devices` | GET | In-memory device registry snapshot |
| `/api/scan/trigger` | POST | Trigger network-wide scan |
| `/api/alerts` | GET | Active alerts |
| `/api/wifi/metrics` | GET | WiFi signal/noise/SNR |
| `/api/analyze/security` | GET | AI security analysis |
| `/api/analyze/health` | GET | Network health report |

See `netmondash/dashboard/routes.py` for the full API.

## Running as a Service

```bash
sudo cp netmondash/systemd/netmondash.service /etc/systemd/system/
sudo systemctl edit netmondash  # set your username and paths
sudo systemctl enable --now netmondash
```

## License

MIT
