"""
Comprehensive tests for FastAPI routes in NetMonDash dashboard.

Tests all HTML page routes, REST API endpoints, error handling,
and edge cases using FastAPI's TestClient with mocked dependencies.
"""

import sys
import os
import asyncio
import json
from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest

# Ensure the netmondash directory is on sys.path so imports work
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fastapi.testclient import TestClient
from dashboard.app import create_app
from modules.database import DEVICE_CATEGORIES


# ---------------------------------------------------------------------------
# Mock Data Helpers
# ---------------------------------------------------------------------------

def make_mock_device(
    mac="00:11:22:33:44:55",
    ip="192.168.1.1",
    hostname="test-host",
    vendor="TestVendor",
    is_online=True,
    category="computer",
    is_trusted=False,
    is_blocked=False,
    custom_name=None,
    notes=None,
    open_ports=None,
    services=None,
):
    """Create a mock device object with a to_dict method."""
    device = MagicMock()
    device.mac = mac
    device.ip = ip
    device.hostname = hostname
    device.vendor = vendor
    device.is_online = is_online
    device.category = category
    device.is_trusted = is_trusted
    device.is_blocked = is_blocked
    device.custom_name = custom_name
    device.notes = notes
    device.to_dict.return_value = {
        "mac": mac,
        "ip": ip,
        "hostname": hostname,
        "vendor": vendor,
        "first_seen": "2025-01-01T00:00:00",
        "last_seen": "2025-01-02T00:00:00",
        "is_online": is_online,
        "open_ports": open_ports or [],
        "services": services or {},
        "notes": notes,
        "category": category,
        "is_trusted": is_trusted,
        "is_blocked": is_blocked,
        "custom_name": custom_name,
        "display_name": custom_name or hostname or ip,
        "last_port_change": None,
        "avg_latency_ms": None,
        "os_guess": None,
        "scan_count": 1,
    }
    return device


def make_mock_scan(scan_id=1, device_count=5, new_device_count=1,
                   scan_type="network", raw_data=None):
    """Create a mock scan object with a to_dict method."""
    scan = MagicMock()
    scan.id = scan_id
    scan.device_count = device_count
    scan.to_dict.return_value = {
        "id": scan_id,
        "timestamp": "2025-01-02T00:00:00",
        "interface": "eth0",
        "device_count": device_count,
        "new_device_count": new_device_count,
        "offline_device_count": 0,
        "scan_type": scan_type,
        "duration_seconds": 10.5,
        "raw_data": raw_data or {"devices": []},
        "network_range": "192.168.1.0/24",
        "error_message": None,
    }
    return scan


def make_mock_alert(alert_id=1, severity="warning", title="Test Alert",
                    message="Test message", acknowledged=False):
    """Create a mock alert object with a to_dict method."""
    alert = MagicMock()
    alert.id = alert_id
    alert.severity = severity
    alert.acknowledged = acknowledged
    alert.to_dict.return_value = {
        "id": alert_id,
        "timestamp": "2025-01-02T00:00:00",
        "severity": severity,
        "category": "security",
        "title": title,
        "message": message,
        "source_ip": None,
        "source_mac": None,
        "command": None,
        "acknowledged": acknowledged,
        "acknowledged_at": None,
        "auto_generated": False,
    }
    return alert


def make_mock_event(event_id=1, event_type="device_joined",
                    description="Device joined",
                    device_mac="00:11:22:33:44:55"):
    """Create a mock network event with a to_dict method."""
    event = MagicMock()
    event.id = event_id
    event.event_type = event_type
    event.to_dict.return_value = {
        "id": event_id,
        "timestamp": "2025-01-02T00:00:00",
        "event_type": event_type,
        "device_mac": device_mac,
        "device_ip": "192.168.1.1",
        "description": description,
        "details": None,
    }
    return event


def make_mock_bandwidth_sample(sample_id=1, latency_ms=5.2,
                               device_mac="00:11:22:33:44:55"):
    """Create a mock bandwidth sample with a to_dict method."""
    sample = MagicMock()
    sample.id = sample_id
    sample.to_dict.return_value = {
        "id": sample_id,
        "timestamp": "2025-01-02T00:00:00",
        "device_mac": device_mac,
        "latency_ms": latency_ms,
        "packet_loss_pct": 0.0,
        "interface": "eth0",
    }
    return sample


def make_mock_recommendation(severity="warning",
                             description="Test recommendation"):
    """Create a mock AI recommendation with a to_dict method."""
    rec = MagicMock()
    rec.to_dict.return_value = {
        "severity": severity,
        "description": description,
        "recommendation": "Do something",
        "command": None,
    }
    return rec


def make_mock_wifi_metrics():
    """Create a mock WiFi metrics object with a to_dict method."""
    metrics = MagicMock()
    metrics.to_dict.return_value = {
        "ssid": "TestNetwork",
        "signal_dbm": -55,
        "frequency": 5180,
        "channel": 36,
        "band": "5GHz",
        "link_speed_mbps": 866,
        "noise_dbm": -90,
        "signal_quality": 78,
    }
    return metrics


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_db():
    """Create a mock database manager with all expected methods."""
    db = MagicMock()

    # Device operations
    db.get_all_devices.return_value = [
        make_mock_device(mac="00:11:22:33:44:55", ip="192.168.1.1",
                         hostname="router"),
        make_mock_device(mac="AA:BB:CC:DD:EE:FF", ip="192.168.1.100",
                         hostname="laptop"),
    ]
    db.get_device.return_value = make_mock_device()
    db.search_devices.return_value = [make_mock_device()]
    db.update_device_field.return_value = True
    db.delete_device.return_value = True
    db.get_device_count_by_category.return_value = {
        "computer": 2, "router": 1, "unknown": 0,
    }

    # Scan operations
    db.get_recent_scans.return_value = [make_mock_scan()]
    db.get_scan_history.return_value = [
        make_mock_scan(), make_mock_scan(scan_id=2),
    ]

    # Alert operations
    db.get_recent_alerts.return_value = [make_mock_alert()]
    db.get_unacknowledged_alerts.return_value = [make_mock_alert()]
    db.acknowledge_alert.return_value = True
    db.acknowledge_all_alerts.return_value = 3
    db.get_alert_summary.return_value = {
        "critical": 1, "warning": 2, "info": 0, "total": 3,
    }

    # Event operations
    db.get_recent_events.return_value = [make_mock_event()]
    db.get_device_events.return_value = [make_mock_event()]

    # Latency
    db.get_latency_history.return_value = [make_mock_bandwidth_sample()]

    # Stats / Admin
    db.get_dashboard_stats.return_value = {
        "total_devices": 5,
        "online_devices": 3,
        "offline_devices": 2,
        "trusted_devices": 1,
        "unacknowledged_alerts": 2,
        "critical_alerts": 1,
        "warning_alerts": 1,
        "scans_24h": 10,
        "last_scan": "2025-01-02T00:00:00",
        "avg_scan_duration": 12.5,
        "categories": {"computer": 2, "router": 1},
        "top_vendors": [{"vendor": "Dell", "count": 2}],
        "new_devices_24h": 1,
    }
    db.get_database_info.return_value = {
        "devices": 5,
        "scans": 100,
        "alerts": 25,
        "events": 200,
        "bandwidth_samples": 1000,
    }
    db.cleanup_old_data.return_value = {
        "scans_deleted": 10,
        "alerts_deleted": 5,
        "events_deleted": 20,
        "bandwidth_samples_deleted": 50,
    }

    return db


@pytest.fixture
def mock_scanner():
    """Create a mock network scanner."""
    scanner = MagicMock()
    scanner.get_scan_summary.return_value = {"status": "idle"}
    scanner.get_wifi_metrics.return_value = make_mock_wifi_metrics()
    scanner.scan_wifi_networks.return_value = [
        {"ssid": "TestNetwork", "signal": -55, "channel": 36},
        {"ssid": "Neighbor", "signal": -72, "channel": 6},
    ]
    scanner.get_network_summary.return_value = {
        "gateway": "192.168.1.1", "subnet": "192.168.1.0/24",
    }
    return scanner


@pytest.fixture
def mock_ai():
    """Create a mock AI analyzer."""
    ai = MagicMock()
    ai.get_quick_insights.return_value = {
        "summary": "Network looks healthy",
        "device_count": 5,
        "alerts": [],
    }
    ai.analyze_security.return_value = [
        make_mock_recommendation("critical", "Open port found"),
    ]
    ai.analyze_network_health.return_value = [
        make_mock_recommendation("warning", "High latency"),
    ]
    ai.analyze_wifi_optimization.return_value = [
        make_mock_recommendation("info", "Consider 5GHz"),
    ]
    return ai


@pytest.fixture
def mock_notifier():
    """Create a mock notifier."""
    return MagicMock()


@pytest.fixture
def app(mock_db, mock_scanner, mock_ai, mock_notifier):
    """Create a FastAPI app with all mocked dependencies."""
    return create_app(
        db_manager=mock_db,
        scanner=mock_scanner,
        ai_analyzer=mock_ai,
        notifier=mock_notifier,
        lifespan=None,
    )


@pytest.fixture
def client(app):
    """Create a TestClient for the fully configured app."""
    return TestClient(app)


@pytest.fixture
def client_no_db(mock_scanner, mock_ai, mock_notifier):
    """TestClient with no database manager (tests 503 responses)."""
    application = create_app(
        db_manager=None,
        scanner=mock_scanner,
        ai_analyzer=mock_ai,
        notifier=mock_notifier,
        lifespan=None,
    )
    return TestClient(application)


@pytest.fixture
def client_no_scanner(mock_db, mock_ai, mock_notifier):
    """TestClient with no scanner."""
    application = create_app(
        db_manager=mock_db,
        scanner=None,
        ai_analyzer=mock_ai,
        notifier=mock_notifier,
        lifespan=None,
    )
    return TestClient(application)


@pytest.fixture
def client_no_ai(mock_db, mock_scanner, mock_notifier):
    """TestClient with no AI analyzer."""
    application = create_app(
        db_manager=mock_db,
        scanner=mock_scanner,
        ai_analyzer=None,
        notifier=mock_notifier,
        lifespan=None,
    )
    return TestClient(application)


@pytest.fixture
def client_minimal():
    """TestClient with no dependencies at all."""
    application = create_app(
        db_manager=None,
        scanner=None,
        ai_analyzer=None,
        notifier=None,
        lifespan=None,
    )
    return TestClient(application)


# ---------------------------------------------------------------------------
# HTML Page Route Tests
# ---------------------------------------------------------------------------

class TestHTMLPages:
    """Tests for HTML page routes that render Jinja2 templates."""

    def test_root_overview_page(self, client):
        """GET / returns the overview dashboard HTML page."""
        response = client.get("/")
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]

    def test_devices_page(self, client):
        """GET /devices returns the devices HTML page."""
        response = client.get("/devices")
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]

    def test_wifi_page(self, client):
        """GET /wifi returns the WiFi analysis HTML page."""
        response = client.get("/wifi")
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]

    def test_insights_page(self, client):
        """GET /insights returns the AI insights HTML page."""
        response = client.get("/insights")
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]

    def test_settings_page(self, client):
        """GET /settings returns the settings HTML page."""
        response = client.get("/settings")
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]

    def test_response_time_header_present(self, client):
        """All responses include the X-Response-Time timing header."""
        response = client.get("/")
        assert "X-Response-Time" in response.headers
        assert response.headers["X-Response-Time"].endswith("s")


# ---------------------------------------------------------------------------
# Health Check Tests
# ---------------------------------------------------------------------------

class TestHealthCheck:
    """Tests for the /health endpoint."""

    def test_health_check_all_components(self, client, mock_db):
        """GET /health returns healthy when all components are available."""
        response = client.get("/health")
        assert response.status_code == 200

        data = response.json()
        assert data["status"] == "healthy"
        assert "version" in data
        assert data["components"]["database"]["available"] is True
        assert data["components"]["scanner"]["available"] is True
        assert data["components"]["ai_analyzer"]["available"] is True
        assert data["components"]["notifier"]["available"] is True
        mock_db.get_database_info.assert_called()

    def test_health_check_degraded_no_scanner(self, client_no_scanner):
        """GET /health returns degraded when scanner is unavailable."""
        response = client_no_scanner.get("/health")
        assert response.status_code == 200

        data = response.json()
        assert data["status"] == "degraded"
        assert data["components"]["scanner"]["available"] is False

    def test_health_check_degraded_no_db(self, client_no_db):
        """GET /health returns degraded when database is unavailable."""
        response = client_no_db.get("/health")
        assert response.status_code == 200

        data = response.json()
        assert data["status"] == "degraded"
        assert data["components"]["database"]["available"] is False
        assert data["components"]["database"]["info"] is None

    def test_health_check_no_components(self, client_minimal):
        """GET /health returns degraded when all components are missing."""
        response = client_minimal.get("/health")
        assert response.status_code == 200

        data = response.json()
        assert data["status"] == "degraded"
        assert data["components"]["database"]["available"] is False
        assert data["components"]["scanner"]["available"] is False
        assert data["components"]["ai_analyzer"]["available"] is False

    def test_health_check_db_info_failure(self, client, mock_db):
        """GET /health handles database info query failure gracefully."""
        mock_db.get_database_info.side_effect = Exception("DB error")

        response = client.get("/health")
        assert response.status_code == 200

        data = response.json()
        assert data["components"]["database"]["info"] == {
            "error": "Failed to query database",
        }


# ---------------------------------------------------------------------------
# Device API Tests
# ---------------------------------------------------------------------------

class TestDeviceAPI:
    """Tests for device-related API endpoints."""

    # -- GET /api/devices --

    def test_get_devices(self, client, mock_db):
        """GET /api/devices returns all devices."""
        response = client.get("/api/devices")
        assert response.status_code == 200

        data = response.json()
        assert data["count"] == 2
        assert len(data["devices"]) == 2
        mock_db.get_all_devices.assert_called_once_with(
            online_only=False, category=None,
        )

    def test_get_devices_online_only(self, client, mock_db):
        """GET /api/devices?online_only=true filters to online devices."""
        mock_db.get_all_devices.return_value = [
            make_mock_device(is_online=True),
        ]

        response = client.get("/api/devices?online_only=true")
        assert response.status_code == 200
        assert response.json()["count"] == 1
        mock_db.get_all_devices.assert_called_with(
            online_only=True, category=None,
        )

    def test_get_devices_by_category(self, client, mock_db):
        """GET /api/devices?category=router filters by category."""
        mock_db.get_all_devices.return_value = [
            make_mock_device(category="router"),
        ]

        response = client.get("/api/devices?category=router")
        assert response.status_code == 200
        assert response.json()["count"] == 1
        mock_db.get_all_devices.assert_called_with(
            online_only=False, category="router",
        )

    def test_get_devices_combined_filters(self, client, mock_db):
        """GET /api/devices with both online_only and category filters."""
        mock_db.get_all_devices.return_value = []

        response = client.get("/api/devices?online_only=true&category=phone")
        assert response.status_code == 200

        data = response.json()
        assert data["count"] == 0
        assert data["devices"] == []
        mock_db.get_all_devices.assert_called_with(
            online_only=True, category="phone",
        )

    def test_get_devices_db_unavailable(self, client_no_db):
        """GET /api/devices returns 503 when database is not available."""
        response = client_no_db.get("/api/devices")
        assert response.status_code == 503

    def test_get_devices_db_error(self, client, mock_db):
        """GET /api/devices returns 500 on database error."""
        mock_db.get_all_devices.side_effect = Exception("DB connection lost")

        response = client.get("/api/devices")
        assert response.status_code == 500

    # -- GET /api/devices/search --

    def test_search_devices(self, client, mock_db):
        """GET /api/devices/search?q=test finds matching devices."""
        mock_db.search_devices.return_value = [
            make_mock_device(hostname="test-host"),
        ]

        response = client.get("/api/devices/search?q=test")
        assert response.status_code == 200

        data = response.json()
        assert data["query"] == "test"
        assert data["count"] == 1
        assert len(data["devices"]) == 1
        mock_db.search_devices.assert_called_once_with("test")

    def test_search_devices_no_results(self, client, mock_db):
        """GET /api/devices/search?q=nonexistent returns empty results."""
        mock_db.search_devices.return_value = []

        response = client.get("/api/devices/search?q=nonexistent")
        assert response.status_code == 200

        data = response.json()
        assert data["count"] == 0
        assert data["devices"] == []

    def test_search_devices_missing_query(self, client):
        """GET /api/devices/search without q parameter returns 422."""
        response = client.get("/api/devices/search")
        assert response.status_code == 422

    def test_search_devices_db_unavailable(self, client_no_db):
        """GET /api/devices/search returns 503 when db is not available."""
        response = client_no_db.get("/api/devices/search?q=test")
        assert response.status_code == 503

    # -- GET /api/devices/{mac} --

    def test_get_device_by_mac(self, client, mock_db):
        """GET /api/devices/{mac} returns a specific device."""
        device = make_mock_device(mac="00:11:22:33:44:55")
        mock_db.get_device.return_value = device

        response = client.get("/api/devices/00:11:22:33:44:55")
        assert response.status_code == 200
        assert response.json()["mac"] == "00:11:22:33:44:55"

    def test_get_device_not_found(self, client, mock_db):
        """GET /api/devices/{mac} returns 404 for unknown device."""
        mock_db.get_device.return_value = None

        response = client.get("/api/devices/FF:FF:FF:FF:FF:FF")
        assert response.status_code == 404

    def test_get_device_db_unavailable(self, client_no_db):
        """GET /api/devices/{mac} returns 503 when db is not available."""
        response = client_no_db.get("/api/devices/00:11:22:33:44:55")
        assert response.status_code == 503

    # -- PUT /api/devices/{mac} --

    def test_update_device(self, client, mock_db):
        """PUT /api/devices/{mac} updates allowed fields."""
        device = make_mock_device(mac="00:11:22:33:44:55",
                                  custom_name="Updated Name")
        mock_db.get_device.return_value = device
        mock_db.update_device_field.return_value = True

        response = client.put(
            "/api/devices/00:11:22:33:44:55",
            json={"custom_name": "Updated Name", "is_trusted": True},
        )
        assert response.status_code == 200

        data = response.json()
        assert data["success"] is True
        assert "custom_name" in data["updated_fields"]
        assert "is_trusted" in data["updated_fields"]

    def test_update_device_not_found(self, client, mock_db):
        """PUT /api/devices/{mac} returns 404 for unknown device."""
        mock_db.get_device.return_value = None

        response = client.put(
            "/api/devices/FF:FF:FF:FF:FF:FF",
            json={"custom_name": "Ghost"},
        )
        assert response.status_code == 404

    def test_update_device_no_valid_fields(self, client, mock_db):
        """PUT /api/devices/{mac} with only invalid fields returns 400."""
        mock_db.get_device.return_value = make_mock_device()

        response = client.put(
            "/api/devices/00:11:22:33:44:55",
            json={"invalid_field": "value"},
        )
        assert response.status_code == 400

    def test_update_device_empty_body(self, client, mock_db):
        """PUT /api/devices/{mac} with empty body returns 400."""
        mock_db.get_device.return_value = make_mock_device()

        response = client.put(
            "/api/devices/00:11:22:33:44:55",
            json={},
        )
        assert response.status_code == 400

    def test_update_device_invalid_category(self, client, mock_db):
        """PUT /api/devices/{mac} with invalid category returns 400."""
        mock_db.get_device.return_value = make_mock_device()

        response = client.put(
            "/api/devices/00:11:22:33:44:55",
            json={"category": "nonexistent_category"},
        )
        assert response.status_code == 400

    def test_update_device_valid_category(self, client, mock_db):
        """PUT /api/devices/{mac} with valid category succeeds."""
        device = make_mock_device(mac="00:11:22:33:44:55", category="server")
        mock_db.get_device.return_value = device
        mock_db.update_device_field.return_value = True

        response = client.put(
            "/api/devices/00:11:22:33:44:55",
            json={"category": "server"},
        )
        assert response.status_code == 200

    def test_update_device_field_failure(self, client, mock_db):
        """PUT /api/devices/{mac} returns 500 if update_device_field fails."""
        mock_db.get_device.return_value = make_mock_device()
        mock_db.update_device_field.return_value = False

        response = client.put(
            "/api/devices/00:11:22:33:44:55",
            json={"custom_name": "Fail"},
        )
        assert response.status_code == 500

    def test_update_device_all_allowed_fields(self, client, mock_db):
        """PUT /api/devices/{mac} accepts all five allowed fields at once."""
        mock_db.get_device.return_value = make_mock_device()
        mock_db.update_device_field.return_value = True

        response = client.put(
            "/api/devices/00:11:22:33:44:55",
            json={
                "category": "computer",
                "custom_name": "My Device",
                "is_trusted": True,
                "is_blocked": False,
                "notes": "A note",
            },
        )
        assert response.status_code == 200

        data = response.json()
        assert len(data["updated_fields"]) == 5

    # -- DELETE /api/devices/{mac} --

    def test_delete_device(self, client, mock_db):
        """DELETE /api/devices/{mac} deletes a device."""
        mock_db.get_device.return_value = make_mock_device(
            mac="AA:BB:CC:DD:EE:FF",
        )
        mock_db.delete_device.return_value = True

        response = client.delete("/api/devices/AA:BB:CC:DD:EE:FF")
        assert response.status_code == 200

        data = response.json()
        assert data["success"] is True
        assert data["mac"] == "AA:BB:CC:DD:EE:FF"

    def test_delete_device_not_found(self, client, mock_db):
        """DELETE /api/devices/{mac} returns 404 for unknown device."""
        mock_db.get_device.return_value = None

        response = client.delete("/api/devices/FF:FF:FF:FF:FF:FF")
        assert response.status_code == 404

    def test_delete_device_failure(self, client, mock_db):
        """DELETE /api/devices/{mac} returns 500 if delete fails."""
        mock_db.get_device.return_value = make_mock_device()
        mock_db.delete_device.return_value = False

        response = client.delete("/api/devices/00:11:22:33:44:55")
        assert response.status_code == 500

    # -- POST /api/devices/{mac}/notes --

    def test_update_device_notes(self, client, mock_db):
        """POST /api/devices/{mac}/notes updates device notes."""
        mock_db.get_device.return_value = make_mock_device()
        mock_db.update_device_field.return_value = True

        response = client.post(
            "/api/devices/00:11:22:33:44:55/notes",
            json={"notes": "This is a test note"},
        )
        assert response.status_code == 200

        data = response.json()
        assert data["success"] is True
        assert data["notes"] == "This is a test note"

    def test_update_device_notes_not_found(self, client, mock_db):
        """POST /api/devices/{mac}/notes returns 404 for unknown device."""
        mock_db.get_device.return_value = None

        response = client.post(
            "/api/devices/FF:FF:FF:FF:FF:FF/notes",
            json={"notes": "Ghost notes"},
        )
        assert response.status_code == 404

    def test_update_device_notes_failure(self, client, mock_db):
        """POST /api/devices/{mac}/notes returns 500 if update fails."""
        mock_db.get_device.return_value = make_mock_device()
        mock_db.update_device_field.return_value = False

        response = client.post(
            "/api/devices/00:11:22:33:44:55/notes",
            json={"notes": "Failing notes"},
        )
        assert response.status_code == 500

    def test_update_device_notes_empty_string(self, client, mock_db):
        """POST /api/devices/{mac}/notes with empty string clears notes."""
        mock_db.get_device.return_value = make_mock_device()
        mock_db.update_device_field.return_value = True

        response = client.post(
            "/api/devices/00:11:22:33:44:55/notes",
            json={"notes": ""},
        )
        assert response.status_code == 200
        assert response.json()["notes"] == ""

    def test_update_device_notes_missing_key(self, client, mock_db):
        """POST /api/devices/{mac}/notes defaults to empty when key absent."""
        mock_db.get_device.return_value = make_mock_device()
        mock_db.update_device_field.return_value = True

        response = client.post(
            "/api/devices/00:11:22:33:44:55/notes",
            json={},
        )
        assert response.status_code == 200
        assert response.json()["notes"] == ""


# ---------------------------------------------------------------------------
# Scan API Tests
# ---------------------------------------------------------------------------

class TestScanAPI:
    """Tests for scan-related API endpoints."""

    def test_get_recent_scans(self, client, mock_db):
        """GET /api/scans/recent returns recent scans."""
        response = client.get("/api/scans/recent")
        assert response.status_code == 200

        data = response.json()
        assert "count" in data
        assert "scans" in data
        assert data["count"] == 1
        mock_db.get_recent_scans.assert_called_once_with(limit=10)

    def test_get_recent_scans_custom_limit(self, client, mock_db):
        """GET /api/scans/recent?limit=5 respects the limit parameter."""
        mock_db.get_recent_scans.return_value = [
            make_mock_scan(scan_id=i) for i in range(5)
        ]

        response = client.get("/api/scans/recent?limit=5")
        assert response.status_code == 200
        assert response.json()["count"] == 5
        mock_db.get_recent_scans.assert_called_once_with(limit=5)

    def test_get_recent_scans_invalid_limit_low(self, client):
        """GET /api/scans/recent with limit below minimum returns 422."""
        response = client.get("/api/scans/recent?limit=0")
        assert response.status_code == 422

    def test_get_recent_scans_invalid_limit_high(self, client):
        """GET /api/scans/recent with limit above maximum returns 422."""
        response = client.get("/api/scans/recent?limit=200")
        assert response.status_code == 422

    def test_get_scan_history(self, client, mock_db):
        """GET /api/scans/history returns scan history."""
        response = client.get("/api/scans/history")
        assert response.status_code == 200

        data = response.json()
        assert "count" in data
        assert "scans" in data
        mock_db.get_scan_history.assert_called_once_with(hours=24)

    def test_get_scan_history_custom_hours(self, client, mock_db):
        """GET /api/scans/history?hours=48 respects the hours parameter."""
        response = client.get("/api/scans/history?hours=48")
        assert response.status_code == 200
        mock_db.get_scan_history.assert_called_once_with(hours=48)

    def test_trigger_scan_with_event(self, client, app):
        """POST /api/scan/trigger triggers scan via asyncio event flag."""
        scan_event = asyncio.Event()
        app.state.scan_event = scan_event

        response = client.post("/api/scan/trigger")
        assert response.status_code == 200

        data = response.json()
        assert data["success"] is True
        assert "Scan triggered" in data["message"]
        assert scan_event.is_set()

    def test_trigger_scan_fallback(self, client, mock_scanner):
        """POST /api/scan/trigger falls back to scanner summary."""
        response = client.post("/api/scan/trigger")
        assert response.status_code == 200

        data = response.json()
        assert data["success"] is True

    def test_trigger_scan_no_scanner(self, client_no_scanner):
        """POST /api/scan/trigger returns 503 when scanner unavailable."""
        response = client_no_scanner.post("/api/scan/trigger")
        assert response.status_code == 503

    def test_get_recent_scans_db_unavailable(self, client_no_db):
        """GET /api/scans/recent returns 503 when db is not available."""
        response = client_no_db.get("/api/scans/recent")
        assert response.status_code == 503

    def test_get_scan_history_db_unavailable(self, client_no_db):
        """GET /api/scans/history returns 503 when db is not available."""
        response = client_no_db.get("/api/scans/history")
        assert response.status_code == 503


# ---------------------------------------------------------------------------
# WiFi API Tests
# ---------------------------------------------------------------------------

class TestWiFiAPI:
    """Tests for WiFi-related API endpoints."""

    def test_get_wifi_metrics(self, client, mock_scanner):
        """GET /api/wifi/metrics returns current WiFi metrics."""
        response = client.get("/api/wifi/metrics")
        assert response.status_code == 200

        data = response.json()
        assert data["available"] is True
        assert "metrics" in data
        assert data["metrics"]["ssid"] == "TestNetwork"

    def test_get_wifi_metrics_unavailable(self, client, mock_scanner):
        """GET /api/wifi/metrics returns available=false when no metrics."""
        mock_scanner.get_wifi_metrics.return_value = None

        response = client.get("/api/wifi/metrics")
        assert response.status_code == 200
        assert response.json()["available"] is False

    def test_get_wifi_metrics_no_scanner(self, client_no_scanner):
        """GET /api/wifi/metrics returns 503 when scanner unavailable."""
        response = client_no_scanner.get("/api/wifi/metrics")
        assert response.status_code == 503

    def test_get_wifi_metrics_error(self, client, mock_scanner):
        """GET /api/wifi/metrics returns 500 on scanner error."""
        mock_scanner.get_wifi_metrics.side_effect = Exception("WiFi error")

        response = client.get("/api/wifi/metrics")
        assert response.status_code == 500

    def test_get_wifi_networks(self, client, mock_scanner):
        """GET /api/wifi/networks returns list of available networks."""
        response = client.get("/api/wifi/networks")
        assert response.status_code == 200

        data = response.json()
        assert data["count"] == 2
        assert len(data["networks"]) == 2

    def test_get_wifi_networks_no_scanner(self, client_no_scanner):
        """GET /api/wifi/networks returns 503 when scanner unavailable."""
        response = client_no_scanner.get("/api/wifi/networks")
        assert response.status_code == 503


# ---------------------------------------------------------------------------
# Alert API Tests
# ---------------------------------------------------------------------------

class TestAlertAPI:
    """Tests for alert-related API endpoints."""

    def test_get_alerts(self, client, mock_db):
        """GET /api/alerts returns recent alerts."""
        response = client.get("/api/alerts")
        assert response.status_code == 200

        data = response.json()
        assert "count" in data
        assert "alerts" in data
        assert data["count"] == 1
        mock_db.get_recent_alerts.assert_called_once_with(limit=50)

    def test_get_alerts_custom_limit(self, client, mock_db):
        """GET /api/alerts?limit=10 respects the limit parameter."""
        response = client.get("/api/alerts?limit=10")
        assert response.status_code == 200
        mock_db.get_recent_alerts.assert_called_with(limit=10)

    def test_get_alerts_unacknowledged_only(self, client, mock_db):
        """GET /api/alerts?unacknowledged_only=true filters correctly."""
        mock_db.get_unacknowledged_alerts.return_value = [
            make_mock_alert(alert_id=1, acknowledged=False),
            make_mock_alert(alert_id=2, acknowledged=False),
        ]

        response = client.get("/api/alerts?unacknowledged_only=true")
        assert response.status_code == 200
        assert response.json()["count"] == 2
        mock_db.get_unacknowledged_alerts.assert_called_once()

    def test_acknowledge_alert(self, client, mock_db):
        """POST /api/alerts/{id}/acknowledge acknowledges an alert."""
        mock_db.acknowledge_alert.return_value = True

        response = client.post("/api/alerts/1/acknowledge")
        assert response.status_code == 200

        data = response.json()
        assert data["success"] is True
        assert data["alert_id"] == 1
        mock_db.acknowledge_alert.assert_called_once_with(1)

    def test_acknowledge_alert_not_found(self, client, mock_db):
        """POST /api/alerts/{id}/acknowledge returns 404 if not found."""
        mock_db.acknowledge_alert.return_value = False

        response = client.post("/api/alerts/99999/acknowledge")
        assert response.status_code == 404

    def test_acknowledge_all_alerts(self, client, mock_db):
        """POST /api/alerts/acknowledge-all acknowledges all alerts."""
        mock_db.acknowledge_all_alerts.return_value = 3

        response = client.post("/api/alerts/acknowledge-all")
        assert response.status_code == 200

        data = response.json()
        assert data["success"] is True
        assert data["acknowledged_count"] == 3
        assert "3" in data["message"]

    def test_acknowledge_all_alerts_none_pending(self, client, mock_db):
        """POST /api/alerts/acknowledge-all with no pending returns 0."""
        mock_db.acknowledge_all_alerts.return_value = 0

        response = client.post("/api/alerts/acknowledge-all")
        assert response.status_code == 200
        assert response.json()["acknowledged_count"] == 0

    def test_get_alerts_db_unavailable(self, client_no_db):
        """GET /api/alerts returns 503 when db is not available."""
        response = client_no_db.get("/api/alerts")
        assert response.status_code == 503

    def test_acknowledge_alert_db_unavailable(self, client_no_db):
        """POST /api/alerts/{id}/acknowledge returns 503 when db missing."""
        response = client_no_db.post("/api/alerts/1/acknowledge")
        assert response.status_code == 503

    def test_acknowledge_all_db_unavailable(self, client_no_db):
        """POST /api/alerts/acknowledge-all returns 503 when db missing."""
        response = client_no_db.post("/api/alerts/acknowledge-all")
        assert response.status_code == 503

    def test_get_alerts_db_error(self, client, mock_db):
        """GET /api/alerts returns 500 on database exception."""
        mock_db.get_recent_alerts.side_effect = Exception("Connection failed")

        response = client.get("/api/alerts")
        assert response.status_code == 500

    def test_acknowledge_alert_db_error(self, client, mock_db):
        """POST /api/alerts/{id}/acknowledge returns 500 on DB error."""
        mock_db.acknowledge_alert.side_effect = Exception("DB error")

        response = client.post("/api/alerts/1/acknowledge")
        assert response.status_code == 500


# ---------------------------------------------------------------------------
# Events API Tests
# ---------------------------------------------------------------------------

class TestEventsAPI:
    """Tests for network events API endpoints."""

    def test_get_events(self, client, mock_db):
        """GET /api/events returns network events."""
        response = client.get("/api/events")
        assert response.status_code == 200

        data = response.json()
        assert "count" in data
        assert "events" in data
        assert data["count"] == 1
        mock_db.get_recent_events.assert_called_once_with(
            limit=50, event_type=None,
        )

    def test_get_events_custom_limit(self, client, mock_db):
        """GET /api/events?limit=10 respects the limit parameter."""
        response = client.get("/api/events?limit=10")
        assert response.status_code == 200
        mock_db.get_recent_events.assert_called_with(
            limit=10, event_type=None,
        )

    def test_get_events_by_type(self, client, mock_db):
        """GET /api/events?event_type=device_joined filters by type."""
        response = client.get("/api/events?event_type=device_joined")
        assert response.status_code == 200
        mock_db.get_recent_events.assert_called_with(
            limit=50, event_type="device_joined",
        )

    def test_get_events_with_limit_and_type(self, client, mock_db):
        """GET /api/events with both limit and event_type."""
        response = client.get("/api/events?limit=5&event_type=port_change")
        assert response.status_code == 200
        mock_db.get_recent_events.assert_called_with(
            limit=5, event_type="port_change",
        )

    def test_get_device_events(self, client, mock_db):
        """GET /api/events/{device_mac} returns device-specific events."""
        response = client.get("/api/events/00:11:22:33:44:55")
        assert response.status_code == 200

        data = response.json()
        assert data["device_mac"] == "00:11:22:33:44:55"
        assert "count" in data
        assert "events" in data
        mock_db.get_device_events.assert_called_once_with(
            "00:11:22:33:44:55", limit=20,
        )

    def test_get_device_events_custom_limit(self, client, mock_db):
        """GET /api/events/{mac}?limit=5 respects the limit parameter."""
        response = client.get("/api/events/00:11:22:33:44:55?limit=5")
        assert response.status_code == 200
        mock_db.get_device_events.assert_called_once_with(
            "00:11:22:33:44:55", limit=5,
        )

    def test_get_events_db_unavailable(self, client_no_db):
        """GET /api/events returns 503 when db is not available."""
        response = client_no_db.get("/api/events")
        assert response.status_code == 503

    def test_get_device_events_db_unavailable(self, client_no_db):
        """GET /api/events/{mac} returns 503 when db is not available."""
        response = client_no_db.get("/api/events/00:11:22:33:44:55")
        assert response.status_code == 503


# ---------------------------------------------------------------------------
# Latency API Tests
# ---------------------------------------------------------------------------

class TestLatencyAPI:
    """Tests for latency history API endpoint."""

    def test_get_latency_history(self, client, mock_db):
        """GET /api/latency returns latency history."""
        response = client.get("/api/latency")
        assert response.status_code == 200

        data = response.json()
        assert data["hours"] == 24
        assert data["device_mac"] is None
        assert "count" in data
        assert "samples" in data
        mock_db.get_latency_history.assert_called_once_with(
            hours=24, device_mac=None,
        )

    def test_get_latency_history_custom_hours(self, client, mock_db):
        """GET /api/latency?hours=48 respects the hours parameter."""
        response = client.get("/api/latency?hours=48")
        assert response.status_code == 200
        mock_db.get_latency_history.assert_called_once_with(
            hours=48, device_mac=None,
        )

    def test_get_latency_history_by_device(self, client, mock_db):
        """GET /api/latency?device_mac=... filters by device."""
        response = client.get(
            "/api/latency?device_mac=00:11:22:33:44:55",
        )
        assert response.status_code == 200

        data = response.json()
        assert data["device_mac"] == "00:11:22:33:44:55"
        mock_db.get_latency_history.assert_called_once_with(
            hours=24, device_mac="00:11:22:33:44:55",
        )

    def test_get_latency_db_unavailable(self, client_no_db):
        """GET /api/latency returns 503 when db is not available."""
        response = client_no_db.get("/api/latency")
        assert response.status_code == 503


# ---------------------------------------------------------------------------
# Insights & Analysis API Tests
# ---------------------------------------------------------------------------

class TestInsightsAPI:
    """Tests for AI insights and analysis endpoints."""

    # -- GET /api/insights --

    def test_get_insights(self, client, mock_db, mock_ai):
        """GET /api/insights returns AI-generated insights."""
        response = client.get("/api/insights")
        assert response.status_code == 200

        data = response.json()
        assert data["available"] is True
        assert "insights" in data
        assert "timestamp" in data

    def test_get_insights_no_ai(self, client_no_ai):
        """GET /api/insights returns available=false when AI unavailable."""
        response = client_no_ai.get("/api/insights")
        assert response.status_code == 200

        data = response.json()
        assert data["available"] is False
        assert "message" in data

    def test_get_insights_no_scans(self, client, mock_db):
        """GET /api/insights with no scan data returns available=false."""
        mock_db.get_recent_scans.return_value = []

        response = client.get("/api/insights")
        assert response.status_code == 200
        assert response.json()["available"] is False

    def test_get_insights_ai_error(self, client):
        """GET /api/insights returns 500 when AI throws exception."""
        client.app.state.ai_analyzer.get_quick_insights.side_effect = (
            Exception("AI model error")
        )

        response = client.get("/api/insights")
        assert response.status_code == 500

    # -- POST /api/analyze/security --

    def test_analyze_security(self, client, mock_db, mock_ai):
        """POST /api/analyze/security returns security recommendations."""
        response = client.post("/api/analyze/security")
        assert response.status_code == 200

        data = response.json()
        assert "count" in data
        assert "recommendations" in data
        assert "timestamp" in data
        assert data["count"] == 1

    def test_analyze_security_no_scans(self, client, mock_db):
        """POST /api/analyze/security returns 404 when no scan data."""
        mock_db.get_recent_scans.return_value = []

        response = client.post("/api/analyze/security")
        assert response.status_code == 404

    def test_analyze_security_no_ai(self, client_no_ai):
        """POST /api/analyze/security returns 503 when AI unavailable."""
        response = client_no_ai.post("/api/analyze/security")
        assert response.status_code == 503

    # -- POST /api/analyze/health --

    def test_analyze_health(self, client, mock_db, mock_ai):
        """POST /api/analyze/health returns health recommendations."""
        response = client.post("/api/analyze/health")
        assert response.status_code == 200

        data = response.json()
        assert "count" in data
        assert "recommendations" in data
        assert data["count"] == 1

    def test_analyze_health_no_scans(self, client, mock_db):
        """POST /api/analyze/health returns 404 when no scan data."""
        mock_db.get_recent_scans.return_value = []

        response = client.post("/api/analyze/health")
        assert response.status_code == 404

    def test_analyze_health_no_ai(self, client_no_ai):
        """POST /api/analyze/health returns 503 when AI unavailable."""
        response = client_no_ai.post("/api/analyze/health")
        assert response.status_code == 503

    # -- POST /api/analyze/wifi --

    def test_analyze_wifi(self, client, mock_scanner, mock_ai):
        """POST /api/analyze/wifi returns WiFi recommendations."""
        response = client.post("/api/analyze/wifi")
        assert response.status_code == 200

        data = response.json()
        assert "count" in data
        assert "recommendations" in data
        assert data["count"] == 1

    def test_analyze_wifi_no_data(self, client, mock_scanner):
        """POST /api/analyze/wifi returns 404 when no WiFi data."""
        mock_scanner.get_wifi_metrics.return_value = None
        mock_scanner.scan_wifi_networks.return_value = []

        response = client.post("/api/analyze/wifi")
        assert response.status_code == 404

    def test_analyze_wifi_no_scanner(self, client_no_scanner):
        """POST /api/analyze/wifi returns 503 when scanner unavailable."""
        response = client_no_scanner.post("/api/analyze/wifi")
        assert response.status_code == 503

    def test_analyze_wifi_no_ai(self, client_no_ai):
        """POST /api/analyze/wifi returns 503 when AI unavailable."""
        response = client_no_ai.post("/api/analyze/wifi")
        assert response.status_code == 503

    def test_analyze_wifi_metrics_only(self, client, mock_scanner):
        """POST /api/analyze/wifi works with metrics but no networks."""
        mock_scanner.scan_wifi_networks.return_value = []

        response = client.post("/api/analyze/wifi")
        assert response.status_code == 200

    def test_analyze_wifi_networks_only(self, client, mock_scanner):
        """POST /api/analyze/wifi works with networks but no metrics."""
        mock_scanner.get_wifi_metrics.return_value = None

        response = client.post("/api/analyze/wifi")
        assert response.status_code == 200


# ---------------------------------------------------------------------------
# Statistics API Tests
# ---------------------------------------------------------------------------

class TestStatisticsAPI:
    """Tests for dashboard statistics endpoint."""

    def test_get_stats(self, client, mock_db):
        """GET /api/stats returns dashboard statistics."""
        response = client.get("/api/stats")
        assert response.status_code == 200

        data = response.json()
        assert data["total_devices"] == 5
        assert data["online_devices"] == 3
        assert data["offline_devices"] == 2
        assert "categories" in data
        assert "top_vendors" in data
        mock_db.get_dashboard_stats.assert_called_once()

    def test_get_stats_db_unavailable(self, client_no_db):
        """GET /api/stats returns 503 when db is not available."""
        response = client_no_db.get("/api/stats")
        assert response.status_code == 503

    def test_get_stats_db_error(self, client, mock_db):
        """GET /api/stats returns 500 on database error."""
        mock_db.get_dashboard_stats.side_effect = Exception("Stats error")

        response = client.get("/api/stats")
        assert response.status_code == 500


# ---------------------------------------------------------------------------
# Network Summary API Tests
# ---------------------------------------------------------------------------

class TestNetworkSummaryAPI:
    """Tests for network summary endpoint."""

    def test_get_network_summary(self, client, mock_db, mock_scanner):
        """GET /api/network/summary returns full network summary."""
        response = client.get("/api/network/summary")
        assert response.status_code == 200

        data = response.json()
        assert "stats" in data
        assert "alert_summary" in data
        assert "scanner_summary" in data
        assert "timestamp" in data
        mock_db.get_dashboard_stats.assert_called()
        mock_db.get_alert_summary.assert_called()

    def test_get_network_summary_no_scanner(self, client_no_scanner):
        """GET /api/network/summary works without scanner."""
        response = client_no_scanner.get("/api/network/summary")
        assert response.status_code == 200
        assert response.json()["scanner_summary"] is None

    def test_get_network_summary_scanner_error(self, client, mock_scanner):
        """GET /api/network/summary handles scanner error gracefully."""
        mock_scanner.get_network_summary.side_effect = Exception(
            "Scanner error",
        )

        response = client.get("/api/network/summary")
        assert response.status_code == 200
        assert response.json()["scanner_summary"] is None

    def test_get_network_summary_db_unavailable(self, client_no_db):
        """GET /api/network/summary returns 503 when db is missing."""
        response = client_no_db.get("/api/network/summary")
        assert response.status_code == 503


# ---------------------------------------------------------------------------
# Categories API Tests
# ---------------------------------------------------------------------------

class TestCategoriesAPI:
    """Tests for device categories endpoint."""

    def test_get_categories(self, client, mock_db):
        """GET /api/categories returns all categories with counts."""
        response = client.get("/api/categories")
        assert response.status_code == 200

        data = response.json()
        assert "count" in data
        assert "categories" in data
        assert "total_devices" in data
        assert data["count"] == len(DEVICE_CATEGORIES)

        # Verify each category has the expected structure
        for cat in data["categories"]:
            assert "key" in cat
            assert "label" in cat
            assert "icon" in cat
            assert "count" in cat

    def test_get_categories_db_unavailable(self, client_no_db):
        """GET /api/categories returns 503 when db is not available."""
        response = client_no_db.get("/api/categories")
        assert response.status_code == 503


# ---------------------------------------------------------------------------
# Export API Tests
# ---------------------------------------------------------------------------

class TestExportAPI:
    """Tests for data export endpoints."""

    def test_export_devices_json(self, client, mock_db):
        """GET /api/export?format=json&data_type=devices exports as JSON."""
        response = client.get("/api/export?format=json&data_type=devices")
        assert response.status_code == 200

        data = response.json()
        assert data["data_type"] == "devices"
        assert "count" in data
        assert "data" in data
        assert "exported_at" in data

    def test_export_scans_json(self, client, mock_db):
        """GET /api/export?format=json&data_type=scans exports scans."""
        response = client.get("/api/export?format=json&data_type=scans")
        assert response.status_code == 200
        assert response.json()["data_type"] == "scans"

    def test_export_alerts_json(self, client, mock_db):
        """GET /api/export?format=json&data_type=alerts exports alerts."""
        response = client.get("/api/export?format=json&data_type=alerts")
        assert response.status_code == 200
        assert response.json()["data_type"] == "alerts"

    def test_export_devices_csv(self, client, mock_db):
        """GET /api/export?format=csv&data_type=devices exports as CSV."""
        response = client.get("/api/export?format=csv&data_type=devices")
        assert response.status_code == 200
        assert "text/csv" in response.headers["content-type"]
        assert "attachment" in response.headers.get(
            "content-disposition", "",
        )

        # Verify CSV content is parseable
        lines = response.text.strip().split("\n")
        assert len(lines) >= 2  # header + at least 1 data row

    def test_export_csv_empty_data(self, client, mock_db):
        """GET /api/export?format=csv returns 404 when no data to export."""
        mock_db.get_all_devices.return_value = []

        response = client.get("/api/export?format=csv&data_type=devices")
        assert response.status_code == 404

    def test_export_db_unavailable(self, client_no_db):
        """GET /api/export returns 503 when db is not available."""
        response = client_no_db.get(
            "/api/export?format=json&data_type=devices",
        )
        assert response.status_code == 503

    def test_export_db_error(self, client, mock_db):
        """GET /api/export returns 500 on database error."""
        mock_db.get_all_devices.side_effect = Exception("Export failed")

        response = client.get("/api/export?format=json&data_type=devices")
        assert response.status_code == 500


# ---------------------------------------------------------------------------
# Database Admin API Tests
# ---------------------------------------------------------------------------

class TestDatabaseAdminAPI:
    """Tests for database administration endpoints."""

    def test_get_database_info(self, client, mock_db):
        """GET /api/database/info returns database record counts."""
        response = client.get("/api/database/info")
        assert response.status_code == 200

        data = response.json()
        assert "tables" in data
        assert "total_records" in data
        assert "timestamp" in data
        assert data["tables"]["devices"] == 5
        assert data["total_records"] == sum(data["tables"].values())

    def test_get_database_info_db_unavailable(self, client_no_db):
        """GET /api/database/info returns 503 when db is not available."""
        response = client_no_db.get("/api/database/info")
        assert response.status_code == 503

    def test_cleanup_database(self, client, mock_db):
        """POST /api/database/cleanup triggers data cleanup."""
        response = client.post("/api/database/cleanup")
        assert response.status_code == 200

        data = response.json()
        assert data["success"] is True
        assert data["days_threshold"] == 30
        assert "deleted" in data
        assert "total_deleted" in data
        assert data["total_deleted"] == 85  # 10 + 5 + 20 + 50
        mock_db.cleanup_old_data.assert_called_once_with(days=30)

    def test_cleanup_database_custom_days(self, client, mock_db):
        """POST /api/database/cleanup?days=7 respects the days parameter."""
        response = client.post("/api/database/cleanup?days=7")
        assert response.status_code == 200
        mock_db.cleanup_old_data.assert_called_once_with(days=7)

    def test_cleanup_database_db_unavailable(self, client_no_db):
        """POST /api/database/cleanup returns 503 when db missing."""
        response = client_no_db.post("/api/database/cleanup")
        assert response.status_code == 503

    def test_cleanup_database_error(self, client, mock_db):
        """POST /api/database/cleanup returns 500 on database error."""
        mock_db.cleanup_old_data.side_effect = Exception("Cleanup failed")

        response = client.post("/api/database/cleanup")
        assert response.status_code == 500


# ---------------------------------------------------------------------------
# Settings API Tests
# ---------------------------------------------------------------------------

class TestSettingsAPI:
    """Tests for settings endpoint."""

    def test_get_current_settings(self, client):
        """GET /api/settings/current returns runtime settings."""
        response = client.get("/api/settings/current")
        assert response.status_code == 200

        data = response.json()
        assert "scan_interval" in data
        assert "web_port" in data
        assert "ai_enabled" in data
        assert "debug_mode" in data
        assert "retention_days" in data
        assert "ollama_model" in data
        assert "ollama_url" in data
        assert "components" in data
        assert "timestamp" in data

        # Verify component statuses reflect the mock setup
        components = data["components"]
        assert components["database"] is True
        assert components["scanner"] is True
        assert components["ai_analyzer"] is True

    def test_get_current_settings_minimal(self, client_minimal):
        """GET /api/settings/current reports all components unavailable."""
        response = client_minimal.get("/api/settings/current")
        assert response.status_code == 200

        components = response.json()["components"]
        assert components["database"] is False
        assert components["scanner"] is False
        assert components["ai_analyzer"] is False


# ---------------------------------------------------------------------------
# Edge Cases and General Error Handling Tests
# ---------------------------------------------------------------------------

class TestEdgeCases:
    """Tests for edge cases and general error handling."""

    def test_nonexistent_route_returns_404(self, client):
        """Requesting a non-existent route returns 404."""
        response = client.get("/api/nonexistent")
        assert response.status_code == 404

    def test_method_not_allowed(self, client):
        """Using wrong HTTP method returns 405."""
        response = client.post("/api/devices")
        assert response.status_code == 405

    def test_response_time_header_on_api(self, client):
        """API responses include X-Response-Time header."""
        response = client.get("/api/stats")
        assert "X-Response-Time" in response.headers

    def test_cors_preflight(self, client):
        """CORS preflight OPTIONS request succeeds."""
        response = client.options(
            "/api/devices",
            headers={
                "Origin": "http://localhost:3000",
                "Access-Control-Request-Method": "GET",
            },
        )
        assert response.status_code == 200

    def test_trigger_scan_scanner_error(self, client, mock_scanner):
        """POST /api/scan/trigger returns 500 on scanner error."""
        mock_scanner.get_scan_summary.side_effect = Exception("Scanner error")

        response = client.post("/api/scan/trigger")
        assert response.status_code == 500

    def test_get_device_db_error(self, client, mock_db):
        """GET /api/devices/{mac} returns 500 on database exception."""
        mock_db.get_device.side_effect = Exception("Connection lost")

        response = client.get("/api/devices/00:11:22:33:44:55")
        assert response.status_code == 500

    def test_search_devices_db_error(self, client, mock_db):
        """GET /api/devices/search returns 500 on database exception."""
        mock_db.search_devices.side_effect = Exception("Search failed")

        response = client.get("/api/devices/search?q=test")
        assert response.status_code == 500

    def test_delete_device_db_error(self, client, mock_db):
        """DELETE /api/devices/{mac} returns 500 on database exception."""
        mock_db.get_device.return_value = make_mock_device()
        mock_db.delete_device.side_effect = Exception("Delete failed")

        response = client.delete("/api/devices/00:11:22:33:44:55")
        assert response.status_code == 500

    def test_wifi_networks_scanner_error(self, client, mock_scanner):
        """GET /api/wifi/networks returns 500 on scanner error."""
        mock_scanner.scan_wifi_networks.side_effect = Exception("Scan error")

        response = client.get("/api/wifi/networks")
        assert response.status_code == 500

    def test_get_events_db_error(self, client, mock_db):
        """GET /api/events returns 500 on database exception."""
        mock_db.get_recent_events.side_effect = Exception("Events error")

        response = client.get("/api/events")
        assert response.status_code == 500

    def test_get_device_events_db_error(self, client, mock_db):
        """GET /api/events/{mac} returns 500 on database exception."""
        mock_db.get_device_events.side_effect = Exception("Events error")

        response = client.get("/api/events/00:11:22:33:44:55")
        assert response.status_code == 500

    def test_get_latency_db_error(self, client, mock_db):
        """GET /api/latency returns 500 on database exception."""
        mock_db.get_latency_history.side_effect = Exception("Latency error")

        response = client.get("/api/latency")
        assert response.status_code == 500

    def test_database_info_db_error(self, client, mock_db):
        """GET /api/database/info returns 500 on database exception."""
        mock_db.get_database_info.side_effect = Exception("Info error")

        response = client.get("/api/database/info")
        assert response.status_code == 500

    def test_categories_db_error(self, client, mock_db):
        """GET /api/categories returns 500 on database exception."""
        mock_db.get_device_count_by_category.side_effect = Exception("Error")

        response = client.get("/api/categories")
        assert response.status_code == 500

    def test_network_summary_db_error(self, client, mock_db):
        """GET /api/network/summary returns 500 on database exception."""
        mock_db.get_dashboard_stats.side_effect = Exception("Stats error")

        response = client.get("/api/network/summary")
        assert response.status_code == 500

    def test_acknowledge_all_db_error(self, client, mock_db):
        """POST /api/alerts/acknowledge-all returns 500 on DB error."""
        mock_db.acknowledge_all_alerts.side_effect = Exception("DB error")

        response = client.post("/api/alerts/acknowledge-all")
        assert response.status_code == 500

    def test_scan_history_db_error(self, client, mock_db):
        """GET /api/scans/history returns 500 on database exception."""
        mock_db.get_scan_history.side_effect = Exception("History error")

        response = client.get("/api/scans/history")
        assert response.status_code == 500

    def test_recent_scans_db_error(self, client, mock_db):
        """GET /api/scans/recent returns 500 on database exception."""
        mock_db.get_recent_scans.side_effect = Exception("Scans error")

        response = client.get("/api/scans/recent")
        assert response.status_code == 500


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
