"""
Unit tests for the lightweight discovery module.

Tests cover:
    - DeviceRegistry (in-memory store with TTL)
    - DiscoveredDevice data class
    - ActiveARPScanner (with mocked scapy / fallback)
    - PassiveARPListener lifecycle
    - EventBatcher (debouncing)
    - DiscoveryEngine orchestration
    - MAC vendor lookup
"""

import time
import threading
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, MagicMock

import pytest

from modules.discovery import (
    DiscoveredDevice,
    DeviceRegistry,
    ActiveARPScanner,
    PassiveARPListener,
    EventBatcher,
    DiscoveryEngine,
    lookup_vendor,
    SCAPY_AVAILABLE,
    MAC_VENDOR_AVAILABLE,
)


# ─── DiscoveredDevice Tests ──────────────────────────────────────────────────


class TestDiscoveredDevice:
    """Tests for the DiscoveredDevice dataclass."""

    def test_creation(self):
        dev = DiscoveredDevice(mac="AA:BB:CC:DD:EE:FF", ip="192.168.1.10")
        assert dev.mac == "AA:BB:CC:DD:EE:FF"
        assert dev.ip == "192.168.1.10"
        assert dev.vendor is None
        assert dev.is_online is True
        assert dev.source == "arp"

    def test_to_dict(self):
        dev = DiscoveredDevice(
            mac="AA:BB:CC:DD:EE:FF",
            ip="192.168.1.10",
            vendor="TestVendor",
        )
        d = dev.to_dict()
        assert isinstance(d, dict)
        assert d["mac"] == "AA:BB:CC:DD:EE:FF"
        assert d["ip"] == "192.168.1.10"
        assert d["vendor"] == "TestVendor"
        assert d["is_online"] is True
        assert "first_seen" in d
        assert "last_seen" in d

    def test_defaults(self):
        dev = DiscoveredDevice(mac="00:00:00:00:00:01", ip="10.0.0.1")
        assert dev.first_seen is not None
        assert dev.last_seen is not None
        assert dev.source == "arp"


# ─── DeviceRegistry Tests ────────────────────────────────────────────────────


class TestDeviceRegistry:
    """Tests for the in-memory DeviceRegistry with TTL."""

    def test_empty_registry(self):
        reg = DeviceRegistry(stale_timeout=60)
        assert reg.device_count == 0
        assert reg.online_count == 0
        assert reg.get_all() == []
        assert reg.get_online() == []

    def test_upsert_new_device(self):
        reg = DeviceRegistry(stale_timeout=60)
        is_new, ip_changed = reg.upsert("AA:BB:CC:DD:EE:01", "192.168.1.1")
        assert is_new is True
        assert ip_changed is False
        assert reg.device_count == 1
        assert reg.online_count == 1

    def test_upsert_existing_device_same_ip(self):
        reg = DeviceRegistry(stale_timeout=60)
        reg.upsert("AA:BB:CC:DD:EE:01", "192.168.1.1")
        is_new, ip_changed = reg.upsert("AA:BB:CC:DD:EE:01", "192.168.1.1")
        assert is_new is False
        assert ip_changed is False
        assert reg.device_count == 1

    def test_upsert_existing_device_changed_ip(self):
        reg = DeviceRegistry(stale_timeout=60)
        reg.upsert("AA:BB:CC:DD:EE:01", "192.168.1.1")
        is_new, ip_changed = reg.upsert("AA:BB:CC:DD:EE:01", "192.168.1.99")
        assert is_new is False
        assert ip_changed is True

        dev = reg.get("AA:BB:CC:DD:EE:01")
        assert dev.ip == "192.168.1.99"

    def test_upsert_normalizes_mac_to_upper(self):
        reg = DeviceRegistry(stale_timeout=60)
        reg.upsert("aa:bb:cc:dd:ee:01", "192.168.1.1")
        dev = reg.get("AA:BB:CC:DD:EE:01")
        assert dev is not None
        assert dev.mac == "AA:BB:CC:DD:EE:01"

    def test_upsert_with_vendor(self):
        reg = DeviceRegistry(stale_timeout=60)
        reg.upsert("AA:BB:CC:DD:EE:01", "192.168.1.1", vendor="TestVendor")
        dev = reg.get("AA:BB:CC:DD:EE:01")
        assert dev.vendor == "TestVendor"

    def test_get_nonexistent(self):
        reg = DeviceRegistry(stale_timeout=60)
        assert reg.get("FF:FF:FF:FF:FF:FF") is None

    def test_get_all_macs(self):
        reg = DeviceRegistry(stale_timeout=60)
        reg.upsert("AA:BB:CC:DD:EE:01", "192.168.1.1")
        reg.upsert("AA:BB:CC:DD:EE:02", "192.168.1.2")
        macs = reg.get_all_macs()
        assert len(macs) == 2
        assert "AA:BB:CC:DD:EE:01" in macs
        assert "AA:BB:CC:DD:EE:02" in macs

    def test_get_online_macs(self):
        reg = DeviceRegistry(stale_timeout=60)
        reg.upsert("AA:BB:CC:DD:EE:01", "192.168.1.1")
        reg.upsert("AA:BB:CC:DD:EE:02", "192.168.1.2")

        # Manually mark one offline
        dev = reg.get("AA:BB:CC:DD:EE:02")
        dev.is_online = False

        online = reg.get_online_macs()
        assert len(online) == 1
        assert "AA:BB:CC:DD:EE:01" in online

    def test_sweep_stale_marks_offline(self):
        reg = DeviceRegistry(stale_timeout=1)  # 1 second timeout
        reg.upsert("AA:BB:CC:DD:EE:01", "192.168.1.1")

        # Manually set last_seen to the past
        dev = reg.get("AA:BB:CC:DD:EE:01")
        dev.last_seen = datetime.now() - timedelta(seconds=5)

        offline = reg.sweep_stale()
        assert len(offline) == 1
        assert offline[0].mac == "AA:BB:CC:DD:EE:01"
        assert not offline[0].is_online

    def test_sweep_stale_does_not_mark_recent(self):
        reg = DeviceRegistry(stale_timeout=60)
        reg.upsert("AA:BB:CC:DD:EE:01", "192.168.1.1")

        offline = reg.sweep_stale()
        assert len(offline) == 0
        assert reg.online_count == 1

    def test_sweep_stale_does_not_double_mark(self):
        reg = DeviceRegistry(stale_timeout=1)
        reg.upsert("AA:BB:CC:DD:EE:01", "192.168.1.1")

        dev = reg.get("AA:BB:CC:DD:EE:01")
        dev.last_seen = datetime.now() - timedelta(seconds=5)

        # First sweep marks it offline
        offline1 = reg.sweep_stale()
        assert len(offline1) == 1

        # Second sweep should not return it again
        offline2 = reg.sweep_stale()
        assert len(offline2) == 0

    def test_upsert_brings_back_online(self):
        reg = DeviceRegistry(stale_timeout=1)
        reg.upsert("AA:BB:CC:DD:EE:01", "192.168.1.1")

        dev = reg.get("AA:BB:CC:DD:EE:01")
        dev.last_seen = datetime.now() - timedelta(seconds=5)
        reg.sweep_stale()
        assert not dev.is_online

        # Re-see the device
        is_new, _ = reg.upsert("AA:BB:CC:DD:EE:01", "192.168.1.1")
        assert is_new is False
        assert dev.is_online is True

    def test_clear(self):
        reg = DeviceRegistry(stale_timeout=60)
        reg.upsert("AA:BB:CC:DD:EE:01", "192.168.1.1")
        reg.upsert("AA:BB:CC:DD:EE:02", "192.168.1.2")
        assert reg.device_count == 2

        reg.clear()
        assert reg.device_count == 0

    def test_snapshot(self):
        reg = DeviceRegistry(stale_timeout=60)
        reg.upsert("AA:BB:CC:DD:EE:01", "192.168.1.1", vendor="V1")
        reg.upsert("AA:BB:CC:DD:EE:02", "192.168.1.2", vendor="V2")

        snap = reg.snapshot()
        assert len(snap) == 2
        assert "AA:BB:CC:DD:EE:01" in snap
        assert snap["AA:BB:CC:DD:EE:01"]["vendor"] == "V1"

    def test_multiple_devices(self):
        reg = DeviceRegistry(stale_timeout=60)
        for i in range(20):
            mac = f"AA:BB:CC:DD:EE:{i:02X}"
            ip = f"192.168.1.{i + 1}"
            reg.upsert(mac, ip)

        assert reg.device_count == 20
        assert reg.online_count == 20

    def test_thread_safety(self):
        """Verify registry is safe to use from multiple threads."""
        reg = DeviceRegistry(stale_timeout=60)
        errors = []

        def writer(start):
            try:
                for i in range(50):
                    mac = f"AA:BB:CC:00:{start:02X}:{i:02X}"
                    reg.upsert(mac, f"10.0.{start}.{i}")
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=writer, args=(t,)) for t in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        assert reg.device_count == 200  # 4 threads * 50 devices


# ─── ActiveARPScanner Tests ──────────────────────────────────────────────────


class TestActiveARPScanner:
    """Tests for the active ARP scanner."""

    def test_init(self):
        scanner = ActiveARPScanner(interface="eth0", timeout=3.0)
        assert scanner.interface == "eth0"
        assert scanner.timeout == 3.0

    def test_fallback_arp_cache(self):
        """Test the /proc/net/arp fallback parser."""
        arp_content = (
            "IP address       HW type     Flags       HW address            Mask     Device\n"
            "192.168.1.1      0x1         0x2         AA:BB:CC:DD:EE:01     *        eth0\n"
            "192.168.1.2      0x1         0x2         AA:BB:CC:DD:EE:02     *        eth0\n"
            "10.0.0.1         0x1         0x2         FF:FF:FF:FF:FF:01     *        eth1\n"
            "192.168.1.3      0x1         0x2         00:00:00:00:00:00     *        eth0\n"
        )

        mock_open = MagicMock()
        mock_open.return_value.__enter__ = Mock(return_value=MagicMock(
            readlines=Mock(return_value=arp_content.splitlines(keepends=True))
        ))
        mock_open.return_value.__exit__ = Mock(return_value=False)

        with patch("builtins.open", mock_open):
            results = ActiveARPScanner._fallback_arp_cache("192.168.1.0/24")

        # Should find 2 devices in 192.168.1.0/24 (not 10.0.0.1, not 00:00:00:00:00:00)
        assert len(results) == 2
        ips = [r[0] for r in results]
        assert "192.168.1.1" in ips
        assert "192.168.1.2" in ips
        assert "10.0.0.1" not in ips

    def test_fallback_arp_cache_file_not_found(self):
        """Test graceful handling when /proc/net/arp is missing."""
        with patch("builtins.open", side_effect=OSError("No such file")):
            results = ActiveARPScanner._fallback_arp_cache("192.168.1.0/24")
        assert results == []

    def test_fallback_arp_cache_invalid_cidr(self):
        """Test with invalid CIDR returns empty."""
        results = ActiveARPScanner._fallback_arp_cache("not-a-cidr")
        assert results == []

    @patch("modules.discovery.SCAPY_AVAILABLE", False)
    def test_scan_without_scapy_uses_fallback(self):
        """When scapy is not available, scan falls back to ARP cache."""
        scanner = ActiveARPScanner()
        with patch.object(
            ActiveARPScanner, "_fallback_arp_cache", return_value=[("192.168.1.1", "AA:BB:CC:DD:EE:01")]
        ) as mock_fb:
            results = scanner.scan("192.168.1.0/24")
            mock_fb.assert_called_once_with("192.168.1.0/24")
            assert len(results) == 1


# ─── PassiveARPListener Tests ────────────────────────────────────────────────


class TestPassiveARPListener:
    """Tests for the passive ARP listener."""

    def test_init(self):
        cb = Mock()
        listener = PassiveARPListener(interface="eth0", callback=cb)
        assert listener.interface == "eth0"
        assert listener.callback is cb
        assert not listener.is_running

    @patch("modules.discovery.SCAPY_AVAILABLE", False)
    def test_start_without_scapy_is_noop(self):
        """Starting without scapy should not crash."""
        listener = PassiveARPListener(interface="eth0")
        listener.start()
        assert not listener.is_running

    def test_stop_when_not_running(self):
        """Stopping when not running should be safe."""
        listener = PassiveARPListener()
        listener.stop()  # Should not raise
        assert not listener.is_running


# ─── EventBatcher Tests ──────────────────────────────────────────────────────


class TestEventBatcher:
    """Tests for the event batcher (debounce / coalesce)."""

    def test_flush_now(self):
        """Test immediate flush delivers all accumulated events."""
        received = []

        def callback(event_type, devices):
            received.append((event_type, devices))

        batcher = EventBatcher(flush_callback=callback, flush_interval=10.0)

        dev1 = DiscoveredDevice(mac="AA:BB:CC:DD:EE:01", ip="192.168.1.1")
        dev2 = DiscoveredDevice(mac="AA:BB:CC:DD:EE:02", ip="192.168.1.2")

        batcher.add("device_joined", dev1)
        batcher.add("device_joined", dev2)
        batcher.flush_now()

        assert len(received) == 1
        assert received[0][0] == "device_joined"
        assert len(received[0][1]) == 2

    def test_different_event_types_batched_separately(self):
        received = []

        def callback(event_type, devices):
            received.append((event_type, len(devices)))

        batcher = EventBatcher(flush_callback=callback, flush_interval=10.0)

        dev1 = DiscoveredDevice(mac="AA:BB:CC:DD:EE:01", ip="192.168.1.1")
        dev2 = DiscoveredDevice(mac="AA:BB:CC:DD:EE:02", ip="192.168.1.2")

        batcher.add("device_joined", dev1)
        batcher.add("device_left", dev2)
        batcher.flush_now()

        event_types = {r[0] for r in received}
        assert "device_joined" in event_types
        assert "device_left" in event_types

    def test_auto_flush_after_interval(self):
        """Test that the batcher auto-flushes after the interval."""
        received = []

        def callback(event_type, devices):
            received.append((event_type, devices))

        batcher = EventBatcher(flush_callback=callback, flush_interval=0.1)

        dev = DiscoveredDevice(mac="AA:BB:CC:DD:EE:01", ip="192.168.1.1")
        batcher.add("device_joined", dev)

        # Wait for auto-flush
        time.sleep(0.3)

        assert len(received) == 1
        batcher.stop()

    def test_stop_flushes_remaining(self):
        received = []

        def callback(event_type, devices):
            received.append((event_type, devices))

        batcher = EventBatcher(flush_callback=callback, flush_interval=60.0)

        dev = DiscoveredDevice(mac="AA:BB:CC:DD:EE:01", ip="192.168.1.1")
        batcher.add("device_joined", dev)
        batcher.stop()

        assert len(received) == 1

    def test_no_events_no_flush(self):
        received = []

        def callback(event_type, devices):
            received.append((event_type, devices))

        batcher = EventBatcher(flush_callback=callback, flush_interval=10.0)
        batcher.flush_now()

        assert len(received) == 0

    def test_callback_error_does_not_crash(self):
        def bad_callback(event_type, devices):
            raise RuntimeError("Boom!")

        batcher = EventBatcher(flush_callback=bad_callback, flush_interval=10.0)
        dev = DiscoveredDevice(mac="AA:BB:CC:DD:EE:01", ip="192.168.1.1")
        batcher.add("device_joined", dev)
        batcher.flush_now()  # Should not raise


# ─── DiscoveryEngine Tests ───────────────────────────────────────────────────


class TestDiscoveryEngine:
    """Tests for the high-level DiscoveryEngine."""

    def test_init(self):
        engine = DiscoveryEngine(
            interface="eth0",
            network_cidr="192.168.1.0/24",
        )
        assert engine.interface == "eth0"
        assert not engine.is_running

    def test_get_stats(self):
        engine = DiscoveryEngine(
            interface="eth0",
            network_cidr="192.168.1.0/24",
        )
        stats = engine.get_stats()
        assert "active_scans" in stats
        assert "passive_packets" in stats
        assert "registry_total" in stats
        assert "scapy_available" in stats
        assert stats["registry_total"] == 0

    def test_get_network_cidr_explicit(self):
        engine = DiscoveryEngine(network_cidr="10.0.0.0/16")
        assert engine.get_network_cidr() == "10.0.0.0/16"

    def test_get_network_cidr_auto_detect(self):
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "2: eth0    inet 192.168.1.100/24 brd 192.168.1.255"

        import subprocess as _subprocess
        with patch.object(_subprocess, "run", return_value=mock_result):
            engine = DiscoveryEngine(interface="eth0")
            cidr = engine.get_network_cidr()
            assert cidr == "192.168.1.0/24"

    def test_registry_accessible(self):
        engine = DiscoveryEngine(network_cidr="192.168.1.0/24")
        assert engine.registry is not None
        assert engine.registry.device_count == 0

    def test_process_single_new_device(self):
        events = []

        def callback(event_type, devices):
            events.append((event_type, devices))

        engine = DiscoveryEngine(
            network_cidr="192.168.1.0/24",
            event_callback=callback,
        )

        # Simulate processing a single ARP result
        with patch("modules.discovery.lookup_vendor", return_value="TestVendor"):
            engine._process_single("192.168.1.1", "AA:BB:CC:DD:EE:01", "arp_active")

        # Should be in registry
        dev = engine.registry.get("AA:BB:CC:DD:EE:01")
        assert dev is not None
        assert dev.ip == "192.168.1.1"

        # Flush the batcher to get events
        engine._batcher.flush_now()
        assert len(events) == 1
        assert events[0][0] == "device_joined"

    def test_process_single_existing_device(self):
        events = []

        def callback(event_type, devices):
            events.append((event_type, devices))

        engine = DiscoveryEngine(
            network_cidr="192.168.1.0/24",
            event_callback=callback,
        )

        with patch("modules.discovery.lookup_vendor", return_value=None):
            # First time: new device
            engine._process_single("192.168.1.1", "AA:BB:CC:DD:EE:01", "arp_active")
            engine._batcher.flush_now()

            # Second time: same device same IP — not new, no ip change
            events.clear()
            engine._process_single("192.168.1.1", "AA:BB:CC:DD:EE:01", "arp_active")
            engine._batcher.flush_now()

        # No new events should have been generated
        assert len(events) == 0

    def test_process_single_ip_change(self):
        events = []

        def callback(event_type, devices):
            events.append((event_type, devices))

        engine = DiscoveryEngine(
            network_cidr="192.168.1.0/24",
            event_callback=callback,
        )

        with patch("modules.discovery.lookup_vendor", return_value=None):
            engine._process_single("192.168.1.1", "AA:BB:CC:DD:EE:01", "arp_active")
            engine._batcher.flush_now()
            events.clear()

            # Same MAC, different IP
            engine._process_single("192.168.1.99", "AA:BB:CC:DD:EE:01", "arp_active")
            engine._batcher.flush_now()

        assert len(events) == 1
        assert events[0][0] == "device_ip_changed"

    def test_stop_when_not_started(self):
        """Stopping an engine that was never started should be safe."""
        engine = DiscoveryEngine(network_cidr="192.168.1.0/24")
        engine.stop()  # Should not raise

    @patch("modules.discovery.SCAPY_AVAILABLE", False)
    def test_start_without_cidr_does_not_crash(self):
        """Starting without a CIDR should log error and not crash."""
        import subprocess as _subprocess
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = ""

        with patch.object(_subprocess, "run", return_value=mock_result):
            engine = DiscoveryEngine()
            engine._network_cidr = None
            engine.start()
        assert not engine.is_running


# ─── Vendor Lookup Tests ─────────────────────────────────────────────────────


class TestVendorLookup:
    """Tests for the MAC vendor lookup function."""

    def test_lookup_vendor_returns_string_or_none(self):
        result = lookup_vendor("AA:BB:CC:DD:EE:FF")
        # May return None if the OUI is unknown or library not installed
        assert result is None or isinstance(result, str)

    def test_lookup_vendor_invalid_mac(self):
        result = lookup_vendor("not-a-mac")
        assert result is None

    @patch("modules.discovery.MAC_VENDOR_AVAILABLE", False)
    def test_lookup_vendor_library_unavailable(self):
        result = lookup_vendor("AA:BB:CC:DD:EE:FF")
        assert result is None


# ─── Deep Scan Device Tests (scanner.py addition) ───────────────────────────


class TestDeepScanDevice:
    """Tests for the deep_scan_device method added to NetworkScanner."""

    @patch('modules.scanner.subprocess.run')
    def test_deep_scan_device_success(self, mock_run):
        """Test deep scanning a single device."""
        from modules.scanner import NetworkScanner

        nmap_xml = """<?xml version="1.0"?>
        <nmaprun>
            <host>
                <status state="up"/>
                <address addr="192.168.1.50" addrtype="ipv4"/>
                <address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" vendor="TestCo"/>
                <hostnames><hostname name="test-host"/></hostnames>
                <ports>
                    <port protocol="tcp" portid="22">
                        <state state="open"/>
                        <service name="ssh" product="OpenSSH" version="8.9"/>
                    </port>
                    <port protocol="tcp" portid="80">
                        <state state="open"/>
                        <service name="http" product="nginx"/>
                    </port>
                </ports>
            </host>
        </nmaprun>"""

        ping_output = (
            "PING 192.168.1.50 (192.168.1.50) 56(84) bytes of data.\n"
            "64 bytes from 192.168.1.50: icmp_seq=1 ttl=64 time=1.20 ms\n"
            "--- 192.168.1.50 ping statistics ---\n"
            "3 packets transmitted, 3 received, 0% packet loss\n"
            "rtt min/avg/max/mdev = 1.000/1.200/1.400/0.163 ms\n"
        )

        def side_effect(cmd, **kwargs):
            result = MagicMock()
            if cmd[0] == "nmap":
                result.returncode = 0
                result.stdout = nmap_xml
                result.stderr = ""
            elif cmd[0] == "ping":
                result.returncode = 0
                result.stdout = ping_output
                result.stderr = ""
            else:
                result.returncode = 1
                result.stdout = ""
                result.stderr = ""
            return result

        mock_run.side_effect = side_effect

        scanner = NetworkScanner()
        device = scanner.deep_scan_device("192.168.1.50")

        assert device is not None
        assert device.ip == "192.168.1.50"
        assert device.mac == "AA:BB:CC:DD:EE:FF"
        assert 22 in device.open_ports
        assert 80 in device.open_ports
        assert device.latency_ms is not None

    @patch('modules.scanner.subprocess.run')
    def test_deep_scan_device_unreachable(self, mock_run):
        """Test deep scan when host is unreachable."""
        from modules.scanner import NetworkScanner

        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = "Host seems down"
        mock_run.return_value = mock_result

        scanner = NetworkScanner()
        device = scanner.deep_scan_device("10.99.99.99")
        assert device is None


# ─── Integration-style Tests ─────────────────────────────────────────────────


class TestDiscoveryIntegration:
    """Higher-level integration tests for discovery components working together."""

    def test_registry_and_batcher_workflow(self):
        """Simulate a full discovery cycle: add devices, sweep stale, check events."""
        events = []

        def callback(event_type, devices):
            events.append((event_type, [d.mac for d in devices]))

        reg = DeviceRegistry(stale_timeout=1)
        batcher = EventBatcher(flush_callback=callback, flush_interval=0.05)

        # Add devices
        for i in range(5):
            mac = f"AA:BB:CC:DD:EE:{i:02X}"
            is_new, _ = reg.upsert(mac, f"192.168.1.{i + 1}")
            if is_new:
                batcher.add("device_joined", reg.get(mac))

        # Wait for auto-flush
        time.sleep(0.15)

        assert len(events) >= 1
        total_joins = sum(len(devs) for et, devs in events if et == "device_joined")
        assert total_joins == 5

        # Make all devices stale
        for dev in reg.get_all():
            dev.last_seen = datetime.now() - timedelta(seconds=5)

        events.clear()
        offline = reg.sweep_stale()
        for dev in offline:
            batcher.add("device_left", dev)

        time.sleep(0.15)

        total_leaves = sum(len(devs) for et, devs in events if et == "device_left")
        assert total_leaves == 5
        assert reg.online_count == 0

        batcher.stop()

    def test_engine_process_arp_results(self):
        """Test processing a batch of ARP results through the engine."""
        events = []

        def callback(event_type, devices):
            events.append((event_type, len(devices)))

        engine = DiscoveryEngine(
            network_cidr="192.168.1.0/24",
            event_callback=callback,
        )

        arp_results = [
            ("192.168.1.1", "AA:BB:CC:DD:EE:01"),
            ("192.168.1.2", "AA:BB:CC:DD:EE:02"),
            ("192.168.1.3", "AA:BB:CC:DD:EE:03"),
        ]

        with patch("modules.discovery.lookup_vendor", return_value=None):
            engine._process_arp_results(arp_results, source="arp_active")

        engine._batcher.flush_now()

        assert engine.registry.device_count == 3
        assert len(events) == 1
        assert events[0][0] == "device_joined"
        assert events[0][1] == 3

        engine._batcher.stop()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
