"""
Unit tests for the database module.
"""

import pytest
import json
from datetime import datetime, timedelta
from unittest.mock import patch

from modules.database import (
    DatabaseManager,
    Device,
    Scan,
    Alert,
    NetworkEvent,
    BandwidthSample,
    guess_device_category,
    init_database,
)


# ─── Fixtures ────────────────────────────────────────────────────────────────


@pytest.fixture
def db():
    """Create a fresh in-memory database manager for each test."""
    manager = DatabaseManager("sqlite:///:memory:", echo=False)
    return manager


@pytest.fixture
def db_with_devices(db):
    """Database pre-populated with a few devices."""
    db.add_or_update_device(
        mac="00:11:22:33:44:55",
        ip="192.168.1.1",
        hostname="router.local",
        vendor="Netgear",
        open_ports=[80, 443, 53],
    )
    db.add_or_update_device(
        mac="AA:BB:CC:DD:EE:FF",
        ip="192.168.1.100",
        hostname="laptop.local",
        vendor="Dell",
        open_ports=[22],
    )
    db.add_or_update_device(
        mac="11:22:33:44:55:66",
        ip="192.168.1.200",
        hostname="phone.local",
        vendor="Apple",
    )
    return db


# ─── Device Model Tests ─────────────────────────────────────────────────────


class TestDevice:
    """Tests for the Device SQLAlchemy model."""

    def test_device_creation(self, db):
        """Test creating a device via the database manager."""
        device = db.add_or_update_device(
            mac="00:11:22:33:44:55",
            ip="192.168.1.1",
            hostname="test-host",
            vendor="TestVendor",
            open_ports=[80, 443],
            services={80: "http", 443: "https"},
        )

        assert device.mac == "00:11:22:33:44:55"
        assert device.ip == "192.168.1.1"
        assert device.hostname == "test-host"
        assert device.vendor == "TestVendor"
        assert device.is_online is True
        assert device.scan_count == 1

    def test_device_to_dict(self, db):
        """Test Device.to_dict() returns all expected fields."""
        device = db.add_or_update_device(
            mac="00:11:22:33:44:55",
            ip="192.168.1.1",
            hostname="test-host",
            vendor="TestVendor",
            open_ports=[80],
        )

        d = device.to_dict()

        assert isinstance(d, dict)
        assert d["mac"] == "00:11:22:33:44:55"
        assert d["ip"] == "192.168.1.1"
        assert d["hostname"] == "test-host"
        assert d["vendor"] == "TestVendor"
        assert d["is_online"] is True
        assert d["open_ports"] == [80]
        assert "first_seen" in d
        assert "last_seen" in d
        assert "display_name" in d
        assert d["display_name"] == "test-host"

    def test_device_category_auto_detection_router(self, db):
        """Test that a device with router-like vendor/ports gets categorized."""
        device = db.add_or_update_device(
            mac="00:11:22:33:44:55",
            ip="192.168.1.1",
            vendor="Netgear",
            open_ports=[80, 443, 53],
        )

        assert device.category == "router"

    def test_device_category_auto_detection_phone(self, db):
        """Test that a device with phone-like vendor is categorized as phone."""
        device = db.add_or_update_device(
            mac="AA:BB:CC:DD:EE:FF",
            ip="192.168.1.50",
            vendor="Apple",
        )

        assert device.category == "phone"

    def test_device_category_unknown(self, db):
        """Test that a device with no identifiable traits stays unknown."""
        device = db.add_or_update_device(
            mac="FF:FF:FF:FF:FF:01",
            ip="192.168.1.99",
        )

        assert device.category == "unknown"


# ─── DatabaseManager Tests ───────────────────────────────────────────────────


class TestDatabaseManager:
    """Tests for DatabaseManager operations."""

    # -- Device CRUD --

    def test_add_device(self, db):
        """Test adding a new device."""
        device = db.add_or_update_device(
            mac="00:11:22:33:44:55",
            ip="192.168.1.10",
            hostname="new-device",
        )

        assert device.mac == "00:11:22:33:44:55"
        assert device.ip == "192.168.1.10"
        assert device.scan_count == 1

    def test_update_device(self, db):
        """Test updating an existing device bumps scan_count and updates fields."""
        db.add_or_update_device(
            mac="00:11:22:33:44:55",
            ip="192.168.1.10",
            hostname="original",
        )

        device = db.add_or_update_device(
            mac="00:11:22:33:44:55",
            ip="192.168.1.11",
            hostname="updated-name",
        )

        assert device.ip == "192.168.1.11"
        assert device.hostname == "updated-name"
        assert device.scan_count == 2

    def test_get_device(self, db):
        """Test retrieving a device by MAC address."""
        db.add_or_update_device(
            mac="00:11:22:33:44:55",
            ip="192.168.1.10",
        )

        device = db.get_device("00:11:22:33:44:55")

        assert device is not None
        assert device.mac == "00:11:22:33:44:55"

    def test_get_device_not_found(self, db):
        """Test that get_device returns None for unknown MAC."""
        device = db.get_device("FF:FF:FF:FF:FF:FF")
        assert device is None

    def test_get_all_devices(self, db_with_devices):
        """Test getting all devices."""
        devices = db_with_devices.get_all_devices()

        assert len(devices) == 3

    def test_get_all_devices_online_only(self, db_with_devices):
        """Test filtering to online-only devices."""
        # Mark one device offline
        db_with_devices.mark_devices_offline(["00:11:22:33:44:55", "AA:BB:CC:DD:EE:FF"])

        all_devices = db_with_devices.get_all_devices(online_only=False)
        online_devices = db_with_devices.get_all_devices(online_only=True)

        assert len(all_devices) == 3
        assert len(online_devices) == 2

    def test_get_all_devices_by_category(self, db_with_devices):
        """Test filtering devices by category."""
        # router.local should be 'router', phone.local should be 'phone'
        routers = db_with_devices.get_all_devices(category="router")
        phones = db_with_devices.get_all_devices(category="phone")

        assert len(routers) >= 1
        assert len(phones) >= 1

    def test_search_devices(self, db_with_devices):
        """Test searching devices by IP, hostname, MAC, and vendor."""
        results = db_with_devices.search_devices("router")
        assert len(results) >= 1

        results = db_with_devices.search_devices("192.168.1.1")
        assert len(results) >= 1

        results = db_with_devices.search_devices("Dell")
        assert len(results) >= 1

        results = db_with_devices.search_devices("nonexistent_xyz")
        assert len(results) == 0

    def test_mark_devices_offline(self, db_with_devices):
        """Test marking devices offline returns count and list of dicts."""
        # Only the router stays online; the other two should go offline
        count, offline_list = db_with_devices.mark_devices_offline(["00:11:22:33:44:55"])

        assert count == 2
        assert isinstance(offline_list, list)
        assert len(offline_list) == 2

        offline_macs = [d["mac"] for d in offline_list]
        assert "AA:BB:CC:DD:EE:FF" in offline_macs
        assert "11:22:33:44:55:66" in offline_macs

    def test_delete_device(self, db_with_devices):
        """Test deleting a device by MAC address."""
        success = db_with_devices.delete_device("AA:BB:CC:DD:EE:FF")
        assert success is True

        device = db_with_devices.get_device("AA:BB:CC:DD:EE:FF")
        assert device is None

        # Deleting non-existent device returns False
        assert db_with_devices.delete_device("FF:FF:FF:FF:FF:FF") is False

    def test_update_device_field(self, db_with_devices):
        """Test updating individual fields on a device."""
        success = db_with_devices.update_device_field(
            "00:11:22:33:44:55",
            custom_name="My Router",
            is_trusted=True,
        )
        assert success is True

        device = db_with_devices.get_device("00:11:22:33:44:55")
        assert device.custom_name == "My Router"
        assert device.is_trusted is True

    def test_update_device_field_not_found(self, db):
        """Test updating a non-existent device returns False."""
        success = db.update_device_field(
            "FF:FF:FF:FF:FF:FF",
            custom_name="Ghost",
        )
        assert success is False

    # -- Scan Operations --

    def test_add_scan(self, db):
        """Test recording a scan."""
        scan = db.add_scan(
            interface="eth0",
            device_count=5,
            scan_type="network",
            duration_seconds=12.5,
            new_device_count=2,
            network_range="192.168.1.0/24",
        )

        assert scan.id is not None
        assert scan.device_count == 5
        assert scan.new_device_count == 2
        assert scan.duration_seconds == 12.5
        assert scan.scan_type == "network"

    def test_get_recent_scans(self, db):
        """Test getting recent scans ordered by timestamp descending."""
        db.add_scan(interface="eth0", device_count=3, scan_type="network")
        db.add_scan(interface="eth0", device_count=5, scan_type="network")
        db.add_scan(interface="eth0", device_count=7, scan_type="service")

        scans = db.get_recent_scans(limit=2)

        assert len(scans) == 2
        # Most recent first
        assert scans[0].device_count == 7

    def test_get_scan_history(self, db):
        """Test getting scan history within a time window."""
        db.add_scan(interface="eth0", device_count=5, scan_type="network")

        scans = db.get_scan_history(hours=24)

        assert len(scans) >= 1

    def test_get_scan_stats(self, db):
        """Test aggregated scan statistics."""
        db.add_scan(
            interface="eth0", device_count=5,
            scan_type="network", duration_seconds=10.0,
        )
        db.add_scan(
            interface="eth0", device_count=10,
            scan_type="network", duration_seconds=20.0,
            new_device_count=3,
        )

        stats = db.get_scan_stats(hours=24)

        assert stats["total_scans"] == 2
        assert stats["avg_duration"] == 15.0
        assert stats["avg_devices"] == 7.5
        assert stats["max_devices"] == 10
        assert stats["total_new_devices"] == 3
        assert stats["error_count"] == 0

    def test_get_scan_stats_empty(self, db):
        """Test scan stats when there are no scans."""
        stats = db.get_scan_stats(hours=24)

        assert stats["total_scans"] == 0
        assert stats["avg_duration"] == 0

    # -- Alert Operations --

    def test_add_alert(self, db):
        """Test creating an alert."""
        alert = db.add_alert(
            severity="critical",
            title="Unknown device",
            message="Unrecognized device on network",
            category="security",
            source_ip="192.168.1.99",
        )

        assert alert.id is not None
        assert alert.severity == "critical"
        assert alert.title == "Unknown device"
        assert alert.acknowledged is False

    def test_acknowledge_alert(self, db):
        """Test acknowledging an alert."""
        alert = db.add_alert(
            severity="warning",
            title="Test alert",
            message="Test",
        )

        success = db.acknowledge_alert(alert.id)
        assert success is True

        # Verify it's acknowledged
        alerts = db.get_unacknowledged_alerts()
        assert all(a.id != alert.id for a in alerts)

    def test_acknowledge_alert_not_found(self, db):
        """Test acknowledging a non-existent alert returns False."""
        assert db.acknowledge_alert(99999) is False

    def test_acknowledge_all_alerts(self, db):
        """Test acknowledging all unacknowledged alerts."""
        db.add_alert(severity="info", title="Alert 1", message="Msg 1")
        db.add_alert(severity="warning", title="Alert 2", message="Msg 2")
        db.add_alert(severity="critical", title="Alert 3", message="Msg 3")

        count = db.acknowledge_all_alerts()

        assert count == 3

        remaining = db.get_unacknowledged_alerts()
        assert len(remaining) == 0

    def test_get_alert_summary(self, db):
        """Test alert summary counts by severity."""
        db.add_alert(severity="critical", title="C1", message="m")
        db.add_alert(severity="critical", title="C2", message="m")
        db.add_alert(severity="warning", title="W1", message="m")
        db.add_alert(severity="info", title="I1", message="m")

        summary = db.get_alert_summary()

        assert summary["critical"] == 2
        assert summary["warning"] == 1
        assert summary["info"] == 1
        assert summary["total"] == 4

    def test_get_alert_summary_excludes_acknowledged(self, db):
        """Test alert summary only counts unacknowledged alerts."""
        a1 = db.add_alert(severity="critical", title="C1", message="m")
        db.add_alert(severity="warning", title="W1", message="m")
        db.acknowledge_alert(a1.id)

        summary = db.get_alert_summary()

        assert summary["critical"] == 0
        assert summary["warning"] == 1
        assert summary["total"] == 1

    # -- Event Operations --

    def test_add_event(self, db):
        """Test adding a network event."""
        event = db.add_event(
            event_type="device_joined",
            description="New device appeared",
            device_mac="00:11:22:33:44:55",
            device_ip="192.168.1.50",
            details={"vendor": "TestCo"},
        )

        assert event.id is not None
        assert event.event_type == "device_joined"
        assert event.device_mac == "00:11:22:33:44:55"

    def test_get_recent_events(self, db):
        """Test getting recent events."""
        db.add_event(event_type="device_joined", description="Device joined")
        db.add_event(event_type="device_left", description="Device left")
        db.add_event(event_type="device_joined", description="Another joined")

        all_events = db.get_recent_events(limit=50)
        assert len(all_events) == 3

        join_events = db.get_recent_events(limit=50, event_type="device_joined")
        assert len(join_events) == 2

    def test_get_device_events(self, db):
        """Test getting events for a specific device."""
        db.add_event(
            event_type="device_joined",
            description="Device joined",
            device_mac="AA:BB:CC:DD:EE:FF",
        )
        db.add_event(
            event_type="port_change",
            description="Port opened",
            device_mac="AA:BB:CC:DD:EE:FF",
        )
        db.add_event(
            event_type="device_joined",
            description="Other device",
            device_mac="11:22:33:44:55:66",
        )

        events = db.get_device_events("AA:BB:CC:DD:EE:FF")

        assert len(events) == 2
        assert all(e.device_mac == "AA:BB:CC:DD:EE:FF" for e in events)

    # -- Bandwidth / Latency Operations --

    def test_add_bandwidth_sample(self, db):
        """Test adding a bandwidth/latency sample."""
        sample = db.add_bandwidth_sample(
            latency_ms=5.2,
            packet_loss_pct=0.0,
            device_mac="00:11:22:33:44:55",
            interface="eth0",
        )

        assert sample.id is not None
        assert sample.latency_ms == 5.2
        assert sample.packet_loss_pct == 0.0

    def test_get_latency_history(self, db):
        """Test getting latency history."""
        db.add_bandwidth_sample(latency_ms=5.0, device_mac="AA:BB:CC:DD:EE:FF")
        db.add_bandwidth_sample(latency_ms=10.0, device_mac="AA:BB:CC:DD:EE:FF")
        db.add_bandwidth_sample(latency_ms=3.0, device_mac="00:11:22:33:44:55")

        # All samples
        all_samples = db.get_latency_history(hours=24)
        assert len(all_samples) == 3

        # Filtered by device
        device_samples = db.get_latency_history(
            hours=24, device_mac="AA:BB:CC:DD:EE:FF"
        )
        assert len(device_samples) == 2

    # -- Analytics --

    def test_get_dashboard_stats(self, db_with_devices):
        """Test comprehensive dashboard stats."""
        # Add an alert and a scan
        db_with_devices.add_alert(
            severity="critical", title="Test", message="Msg"
        )
        db_with_devices.add_scan(
            interface="eth0", device_count=3, scan_type="network",
            duration_seconds=5.0,
        )

        stats = db_with_devices.get_dashboard_stats()

        assert stats["total_devices"] == 3
        assert stats["online_devices"] == 3
        assert stats["offline_devices"] == 0
        assert stats["unacknowledged_alerts"] == 1
        assert stats["critical_alerts"] == 1
        assert stats["scans_24h"] >= 1
        assert "categories" in stats
        assert "top_vendors" in stats

    def test_get_dashboard_stats_empty(self, db):
        """Test dashboard stats on an empty database."""
        stats = db.get_dashboard_stats()

        assert stats["total_devices"] == 0
        assert stats["online_devices"] == 0
        assert stats["unacknowledged_alerts"] == 0

    # -- Maintenance --

    def test_cleanup_old_data(self, db):
        """Test cleanup removes old data and returns deletion counts."""
        # Add data and manually set old timestamps via raw session
        db.add_scan(interface="eth0", device_count=1, scan_type="network")
        alert = db.add_alert(
            severity="info", title="Old", message="old alert"
        )
        db.acknowledge_alert(alert.id)
        db.add_event(event_type="test", description="test event")
        db.add_bandwidth_sample(latency_ms=5.0)

        # With days=0 everything should be considered old
        # But the data was just inserted (now), so with days=0 data
        # older than 0 days = anything before now should be deleted.
        # Actually let's use a large retention to verify nothing is deleted,
        # then a small one to delete everything.

        # With a long retention, nothing should be deleted
        result = db.cleanup_old_data(days=365)
        assert result["scans_deleted"] == 0

        # Force-update timestamps to the past via session
        session = db.get_session()
        try:
            old_date = datetime.now() - timedelta(days=60)
            session.query(Scan).update({"timestamp": old_date})
            session.query(Alert).update({"timestamp": old_date})
            session.query(NetworkEvent).update({"timestamp": old_date})
            session.query(BandwidthSample).update({"timestamp": old_date})
            session.commit()
        finally:
            session.close()

        result = db.cleanup_old_data(days=30)

        assert result["scans_deleted"] >= 1
        assert result["alerts_deleted"] >= 1
        assert result["events_deleted"] >= 1
        assert result["bandwidth_samples_deleted"] >= 1

    # -- Database Info --

    def test_get_database_info(self, db_with_devices):
        """Test database record count info."""
        db_with_devices.add_scan(
            interface="eth0", device_count=3, scan_type="network"
        )
        db_with_devices.add_alert(
            severity="info", title="T", message="m"
        )

        info = db_with_devices.get_database_info()

        assert info["devices"] == 3
        assert info["scans"] >= 1
        assert info["alerts"] >= 1
        assert "events" in info
        assert "bandwidth_samples" in info

    def test_get_database_info_empty(self, db):
        """Test database info on an empty database."""
        info = db.get_database_info()

        assert info["devices"] == 0
        assert info["scans"] == 0
        assert info["alerts"] == 0


# ─── Device Category Guessing Tests ─────────────────────────────────────────


class TestDeviceCategory:
    """Tests for guess_device_category function."""

    def test_router_by_vendor_and_ports(self):
        """Test router detection via vendor keywords and router ports."""
        assert guess_device_category("Netgear", None, [80, 443, 53]) == "router"
        assert guess_device_category("TP-Link", None, [80]) == "router"
        assert guess_device_category("Cisco Systems", None, [443]) == "router"
        assert guess_device_category("Ubiquiti", None, [80, 53]) == "router"

    def test_network_equipment_vendor_no_router_ports(self):
        """Test that a networking vendor without router ports -> network."""
        assert guess_device_category("Netgear", None, [22]) == "network"

    def test_phone_by_vendor(self):
        """Test phone detection by vendor."""
        assert guess_device_category("Apple", None, []) == "phone"
        assert guess_device_category("Samsung Electronics", None, []) == "phone"
        assert guess_device_category("Huawei", None, []) == "phone"
        assert guess_device_category("Xiaomi", None, []) == "phone"

    def test_printer_by_vendor(self):
        """Test printer detection by vendor."""
        assert guess_device_category("HP Inc", None, []) == "printer"
        assert guess_device_category("Canon", None, []) == "printer"
        assert guess_device_category("Epson", None, []) == "printer"
        assert guess_device_category("Brother Industries", None, []) == "printer"

    def test_printer_by_ports(self):
        """Test printer detection by print-related ports."""
        assert guess_device_category(None, None, [9100]) == "printer"
        assert guess_device_category(None, None, [631]) == "printer"

    def test_camera_by_vendor(self):
        """Test camera detection by vendor."""
        assert guess_device_category("Hikvision", None, []) == "camera"
        assert guess_device_category("Dahua", None, []) == "camera"

    def test_camera_by_rtsp_port(self):
        """Test camera detection by RTSP port 554."""
        assert guess_device_category(None, None, [554]) == "camera"

    def test_server_by_many_ports(self):
        """Test server detection when 3+ server-like ports are open."""
        assert guess_device_category(None, None, [22, 80, 443, 3306]) == "server"

    def test_media_device_by_vendor(self):
        """Test media device detection by vendor."""
        assert guess_device_category("Sonos", None, []) == "media"
        assert guess_device_category("Roku", None, []) == "media"

    def test_gaming_by_vendor(self):
        """Test gaming device detection by vendor."""
        assert guess_device_category("Sony", None, []) == "gaming"
        assert guess_device_category("Nintendo", None, []) == "gaming"

    def test_iot_by_vendor(self):
        """Test IoT device detection by vendor."""
        assert guess_device_category("Espressif", None, []) == "iot"
        assert guess_device_category("Tuya", None, []) == "iot"
        assert guess_device_category("Shelly", None, []) == "iot"

    def test_storage_by_vendor(self):
        """Test NAS/storage detection by vendor."""
        assert guess_device_category("Synology", None, []) == "storage"
        assert guess_device_category("QNAP", None, []) == "storage"

    def test_storage_by_ports(self):
        """Test NAS/storage detection by file-sharing ports."""
        assert guess_device_category(None, None, [445]) == "storage"
        assert guess_device_category(None, None, [2049]) == "storage"

    def test_computer_by_hostname(self):
        """Test computer detection by hostname keywords."""
        assert guess_device_category(None, "my-desktop", []) == "computer"
        assert guess_device_category(None, "johns-laptop", []) == "computer"
        assert guess_device_category(None, "office-pc", []) == "computer"
        assert guess_device_category(None, "macbook-pro", []) == "computer"

    def test_computer_by_remote_access_ports(self):
        """Test computer detection by remote access ports."""
        assert guess_device_category(None, None, [3389]) == "computer"
        assert guess_device_category(None, None, [5900]) == "computer"

    def test_unknown_fallback(self):
        """Test that unrecognized inputs return 'unknown'."""
        assert guess_device_category(None, None, None) == "unknown"
        assert guess_device_category("", "", []) == "unknown"
        assert guess_device_category("MysteryVendor", "host123", [12345]) == "unknown"


# ─── init_database Tests ─────────────────────────────────────────────────────


class TestInitDatabase:
    """Test the init_database helper function."""

    def test_init_database_returns_manager(self):
        """Test that init_database returns a working DatabaseManager."""
        manager = init_database("sqlite:///:memory:")

        assert isinstance(manager, DatabaseManager)
        info = manager.get_database_info()
        assert info["devices"] == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
