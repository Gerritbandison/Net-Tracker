"""
Lightweight Network Discovery Module

Uses ARP-based discovery (active sweep + passive sniffing) for fast,
continuous, low-CPU device detection on local subnets.  Full nmap scans
are only triggered for unknown MACs or on explicit user request.

Architecture:
    - ActiveARPScanner:  Sends ARP who-has requests to every address in the
      local subnet.  Runs in a background thread on a configurable interval
      (default 15 s).  Very lightweight (~0.5 s for a /24).
    - PassiveARPListener:  Sniffs the wire for ARP replies/requests and
      gratuitous ARPs using scapy AsyncSniffer.  Zero extra traffic.
    - DeviceRegistry:  Thread-safe in-memory dict of known devices keyed by
      MAC.  Tracks first_seen, last_seen, ip, vendor, and a TTL-based
      online/offline status.
    - DiscoveryEngine:  Ties everything together: runs the active scanner on
      a timer, starts the passive listener, feeds results into the registry,
      and emits join/leave/change events via a callback.

All public methods are thread-safe.
"""

import logging
import threading
import time
import ipaddress
import struct
import socket
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Callable, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Attempt to import scapy.  If unavailable we provide a graceful fallback
# that relies on the existing ARP-cache/arp-scan methods in scanner.py.
# ---------------------------------------------------------------------------
try:
    from scapy.all import (
        ARP, Ether, srp, AsyncSniffer,
        conf as scapy_conf,
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logger.warning(
        "scapy is not installed – falling back to subprocess-based ARP. "
        "Install scapy for passive ARP sniffing: pip install scapy"
    )

# ---------------------------------------------------------------------------
# OUI / MAC vendor lookup
# ---------------------------------------------------------------------------
try:
    from mac_vendor_lookup import MacLookup
    _mac_lookup = MacLookup()
    # Update vendor DB on first import (cached for process lifetime)
    try:
        _mac_lookup.update_vendors()
    except Exception:
        pass  # offline is fine – uses bundled DB
    MAC_VENDOR_AVAILABLE = True
except ImportError:
    _mac_lookup = None
    MAC_VENDOR_AVAILABLE = False
    logger.info("mac-vendor-lookup not installed – vendor lookup disabled")


def lookup_vendor(mac: str) -> Optional[str]:
    """Look up vendor from MAC OUI prefix.

    Uses the mac-vendor-lookup library which ships an offline IEEE OUI
    database.  Returns None if the library is missing or the OUI is unknown.
    """
    if not MAC_VENDOR_AVAILABLE or _mac_lookup is None:
        return None
    try:
        return _mac_lookup.lookup(mac)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class DiscoveredDevice:
    """Lightweight record for a device found via ARP."""
    mac: str
    ip: str
    vendor: Optional[str] = None
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    is_online: bool = True
    source: str = "arp"  # "arp_active", "arp_passive", "nmap"

    def to_dict(self) -> Dict:
        return {
            "mac": self.mac,
            "ip": self.ip,
            "vendor": self.vendor,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "is_online": self.is_online,
            "source": self.source,
        }


# Type alias for event callbacks
# callback(event_type: str, devices: List[DiscoveredDevice])
EventCallback = Callable[[str, List[DiscoveredDevice]], None]


# ---------------------------------------------------------------------------
# Device Registry  (thread-safe in-memory store with TTL)
# ---------------------------------------------------------------------------

class DeviceRegistry:
    """Thread-safe in-memory device registry with TTL-based stale detection.

    Devices that have not been seen for ``stale_timeout`` seconds are marked
    offline and a ``device_left`` event is emitted.
    """

    def __init__(self, stale_timeout: int = 120):
        """
        Args:
            stale_timeout: seconds after which a device is considered offline
                           if not seen again.
        """
        self._devices: Dict[str, DiscoveredDevice] = {}  # keyed by MAC
        self._lock = threading.Lock()
        self.stale_timeout = stale_timeout

    # -- read helpers --------------------------------------------------------

    @property
    def device_count(self) -> int:
        with self._lock:
            return len(self._devices)

    @property
    def online_count(self) -> int:
        with self._lock:
            return sum(1 for d in self._devices.values() if d.is_online)

    def get_all(self) -> List[DiscoveredDevice]:
        with self._lock:
            return list(self._devices.values())

    def get_online(self) -> List[DiscoveredDevice]:
        with self._lock:
            return [d for d in self._devices.values() if d.is_online]

    def get(self, mac: str) -> Optional[DiscoveredDevice]:
        with self._lock:
            return self._devices.get(mac.upper())

    def get_all_macs(self) -> Set[str]:
        with self._lock:
            return set(self._devices.keys())

    def get_online_macs(self) -> Set[str]:
        with self._lock:
            return {mac for mac, d in self._devices.items() if d.is_online}

    # -- write helpers -------------------------------------------------------

    def upsert(
        self,
        mac: str,
        ip: str,
        vendor: Optional[str] = None,
        source: str = "arp",
    ) -> Tuple[bool, bool]:
        """Insert or update a device.

        Returns:
            (is_new, ip_changed) — booleans for the caller to decide
            which events to emit.
        """
        mac = mac.upper()
        now = datetime.now()

        with self._lock:
            existing = self._devices.get(mac)
            if existing is None:
                # Brand-new device
                if vendor is None:
                    vendor = lookup_vendor(mac)
                self._devices[mac] = DiscoveredDevice(
                    mac=mac,
                    ip=ip,
                    vendor=vendor,
                    first_seen=now,
                    last_seen=now,
                    is_online=True,
                    source=source,
                )
                return True, False

            # Existing device — update
            ip_changed = existing.ip != ip
            was_offline = not existing.is_online
            existing.ip = ip
            existing.last_seen = now
            existing.is_online = True
            existing.source = source
            if vendor and not existing.vendor:
                existing.vendor = vendor
            elif vendor is None and not existing.vendor:
                existing.vendor = lookup_vendor(mac)
            return False, ip_changed

    def sweep_stale(self) -> List[DiscoveredDevice]:
        """Mark devices as offline if they haven't been seen recently.

        Returns:
            List of devices that just went offline.
        """
        cutoff = datetime.now() - timedelta(seconds=self.stale_timeout)
        newly_offline: List[DiscoveredDevice] = []

        with self._lock:
            for dev in self._devices.values():
                if dev.is_online and dev.last_seen < cutoff:
                    dev.is_online = False
                    newly_offline.append(dev)

        return newly_offline

    def clear(self):
        with self._lock:
            self._devices.clear()

    def snapshot(self) -> Dict[str, Dict]:
        """Return a JSON-serialisable snapshot."""
        with self._lock:
            return {mac: dev.to_dict() for mac, dev in self._devices.items()}


# ---------------------------------------------------------------------------
# Active ARP Scanner
# ---------------------------------------------------------------------------

class ActiveARPScanner:
    """Send ARP who-has to every IP in the local subnet.

    Much faster than nmap -sn (typically < 1 s for a /24) and uses virtually
    no CPU because it is a single Layer-2 broadcast burst.
    """

    def __init__(
        self,
        interface: Optional[str] = None,
        timeout: float = 2.0,
    ):
        self.interface = interface
        self.timeout = timeout

    def scan(self, network_cidr: str) -> List[Tuple[str, str]]:
        """Perform an active ARP sweep.

        Args:
            network_cidr: e.g. "192.168.1.0/24"

        Returns:
            List of (ip, mac) tuples for hosts that responded.
        """
        if not SCAPY_AVAILABLE:
            return self._fallback_arp_cache(network_cidr)

        results: List[Tuple[str, str]] = []
        try:
            net = ipaddress.IPv4Network(network_cidr, strict=False)
            # Skip network and broadcast addresses
            hosts = [str(h) for h in net.hosts()]
            if not hosts:
                return results

            # Build ARP request packets
            arp_req = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=hosts)

            kwargs = {"timeout": self.timeout, "verbose": 0}
            if self.interface:
                kwargs["iface"] = self.interface

            answered, _ = srp(arp_req, **kwargs)

            for sent, received in answered:
                ip = received.psrc
                mac = received.hwsrc.upper()
                if mac and mac != "00:00:00:00:00:00":
                    results.append((ip, mac))

            logger.debug(
                "Active ARP sweep of %s found %d hosts", network_cidr, len(results)
            )
        except PermissionError:
            logger.warning(
                "ARP sweep requires root/CAP_NET_RAW – falling back to ARP cache"
            )
            return self._fallback_arp_cache(network_cidr)
        except Exception as e:
            logger.error("Active ARP sweep failed: %s", e)
            return self._fallback_arp_cache(network_cidr)

        return results

    # Fallback: read the kernel ARP cache (no root required)
    @staticmethod
    def _fallback_arp_cache(network_cidr: str) -> List[Tuple[str, str]]:
        """Read /proc/net/arp as a zero-privilege fallback."""
        results: List[Tuple[str, str]] = []
        try:
            net = ipaddress.IPv4Network(network_cidr, strict=False)
        except ValueError:
            return results

        try:
            with open("/proc/net/arp", "r") as f:
                for line in f.readlines()[1:]:  # skip header
                    parts = line.split()
                    if len(parts) >= 4:
                        ip = parts[0]
                        mac = parts[3].upper()
                        if mac == "00:00:00:00:00:00":
                            continue
                        try:
                            if ipaddress.IPv4Address(ip) in net:
                                results.append((ip, mac))
                        except ValueError:
                            continue
        except (OSError, IOError) as e:
            logger.debug("Could not read /proc/net/arp: %s", e)

        return results


# ---------------------------------------------------------------------------
# Passive ARP Listener  (scapy AsyncSniffer based)
# ---------------------------------------------------------------------------

class PassiveARPListener:
    """Sniff the network for ARP traffic and report new/changed devices.

    Runs in a background thread via scapy's AsyncSniffer.  Consumes zero
    extra bandwidth – it only observes traffic that is already on the wire.
    """

    def __init__(
        self,
        interface: Optional[str] = None,
        callback: Optional[Callable[[str, str], None]] = None,
    ):
        """
        Args:
            interface: Network interface to sniff on.
            callback: Called as callback(ip, mac) for every ARP packet seen.
        """
        self.interface = interface
        self.callback = callback
        self._sniffer: Optional[object] = None  # AsyncSniffer
        self._running = False

    def start(self):
        if not SCAPY_AVAILABLE:
            logger.info("Passive ARP listener disabled (scapy not available)")
            return
        if self._running:
            return

        try:
            kwargs = {
                "filter": "arp",
                "prn": self._handle_packet,
                "store": False,
            }
            if self.interface:
                kwargs["iface"] = self.interface

            self._sniffer = AsyncSniffer(**kwargs)
            self._sniffer.start()
            self._running = True
            logger.info(
                "Passive ARP listener started on %s",
                self.interface or "all interfaces",
            )
        except PermissionError:
            logger.warning(
                "Passive ARP listener requires root/CAP_NET_RAW – disabled"
            )
        except Exception as e:
            logger.error("Failed to start passive ARP listener: %s", e)

    def stop(self):
        if self._sniffer is not None and self._running:
            try:
                self._sniffer.stop()
            except Exception:
                pass
            self._running = False
            logger.info("Passive ARP listener stopped")

    @property
    def is_running(self) -> bool:
        return self._running

    def _handle_packet(self, pkt):
        """Process a single ARP packet."""
        if not pkt.haslayer(ARP):
            return
        arp = pkt[ARP]
        # op=1 is who-has (request), op=2 is is-at (reply)
        # Both reveal the sender's IP + MAC
        ip = arp.psrc
        mac = arp.hwsrc.upper() if arp.hwsrc else None

        if not ip or not mac or mac == "00:00:00:00:00:00":
            return
        # Filter out 0.0.0.0 (probes)
        if ip == "0.0.0.0":
            return

        if self.callback:
            try:
                self.callback(ip, mac)
            except Exception as e:
                logger.debug("Passive ARP callback error: %s", e)


# ---------------------------------------------------------------------------
# Event Batcher  (debounce / coalesce rapid events)
# ---------------------------------------------------------------------------

class EventBatcher:
    """Collect events over a short window and flush them as a batch.

    This prevents flooding WebSocket clients when 50 devices respond to an
    ARP sweep within 200 ms.
    """

    def __init__(self, flush_callback: EventCallback, flush_interval: float = 1.0):
        """
        Args:
            flush_callback: Called with (event_type, [devices]) on flush.
            flush_interval: Seconds to wait before flushing accumulated events.
        """
        self._callback = flush_callback
        self._interval = flush_interval
        self._lock = threading.Lock()
        self._pending: Dict[str, List[DiscoveredDevice]] = defaultdict(list)
        self._timer: Optional[threading.Timer] = None
        self._stopped = False

    def add(self, event_type: str, device: DiscoveredDevice):
        with self._lock:
            if self._stopped:
                return
            self._pending[event_type].append(device)
            if self._timer is None:
                self._timer = threading.Timer(self._interval, self._flush)
                self._timer.daemon = True
                self._timer.start()

    def _flush(self):
        with self._lock:
            pending = dict(self._pending)
            self._pending = defaultdict(list)
            self._timer = None

        for event_type, devices in pending.items():
            if devices:
                try:
                    self._callback(event_type, devices)
                except Exception as e:
                    logger.error("Event batcher flush error: %s", e)

    def flush_now(self):
        """Force an immediate flush (used during shutdown)."""
        if self._timer is not None:
            self._timer.cancel()
        self._flush()

    def stop(self):
        with self._lock:
            self._stopped = True
            if self._timer is not None:
                self._timer.cancel()
                self._timer = None
        self._flush()


# ---------------------------------------------------------------------------
# Discovery Engine  (orchestrates everything)
# ---------------------------------------------------------------------------

class DiscoveryEngine:
    """High-level discovery engine that ties active scanning, passive
    sniffing, device registry, and event batching together.

    Usage::

        engine = DiscoveryEngine(
            interface="eth0",
            network_cidr="192.168.1.0/24",
            event_callback=my_handler,
        )
        engine.start()       # begins background threads
        # ...
        engine.stop()        # clean shutdown

    The ``event_callback`` receives ``(event_type, devices)`` where
    *event_type* is one of:

    - ``"device_joined"``   — new MAC seen for the first time
    - ``"device_left"``     — device went stale / offline
    - ``"device_ip_changed"`` — known MAC changed IP
    - ``"device_seen"``     — heartbeat (device still present, batched)
    """

    def __init__(
        self,
        interface: Optional[str] = None,
        network_cidr: Optional[str] = None,
        event_callback: Optional[EventCallback] = None,
        active_interval: float = 15.0,
        stale_timeout: int = 120,
        batch_interval: float = 1.0,
    ):
        """
        Args:
            interface: Network interface (e.g. "eth0", "wlan0").
            network_cidr: Subnet to scan (e.g. "192.168.1.0/24").
                          Auto-detected if None.
            event_callback: Receives batched events.
            active_interval: Seconds between active ARP sweeps.
            stale_timeout: Seconds before a silent device is marked offline.
            batch_interval: Seconds to coalesce events before flushing.
        """
        self.interface = interface
        self._network_cidr = network_cidr
        self._active_interval = active_interval
        self._stale_timeout = stale_timeout

        self.registry = DeviceRegistry(stale_timeout=stale_timeout)
        self._active_scanner = ActiveARPScanner(interface=interface)
        self._passive_listener = PassiveARPListener(
            interface=interface,
            callback=self._on_passive_arp,
        )

        self._event_callback = event_callback
        self._batcher = EventBatcher(
            flush_callback=self._emit_events,
            flush_interval=batch_interval,
        )

        self._active_thread: Optional[threading.Thread] = None
        self._stale_thread: Optional[threading.Thread] = None
        self._running = False
        self._stop_event = threading.Event()

        # Stats
        self._stats = {
            "active_scans": 0,
            "passive_packets": 0,
            "total_devices_seen": 0,
            "total_joins": 0,
            "total_leaves": 0,
        }
        self._stats_lock = threading.Lock()

    # -- public API ----------------------------------------------------------

    @property
    def is_running(self) -> bool:
        return self._running

    def get_stats(self) -> Dict:
        with self._stats_lock:
            return {
                **self._stats,
                "registry_total": self.registry.device_count,
                "registry_online": self.registry.online_count,
                "passive_listener_active": self._passive_listener.is_running,
                "scapy_available": SCAPY_AVAILABLE,
                "mac_vendor_available": MAC_VENDOR_AVAILABLE,
            }

    def get_network_cidr(self) -> Optional[str]:
        """Return the subnet CIDR, auto-detecting if needed."""
        if self._network_cidr:
            return self._network_cidr

        # Auto-detect from interface
        import subprocess, re
        cmd = ["ip", "-o", "-f", "inet", "addr", "show"]
        if self.interface:
            cmd.append(self.interface)
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                match = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)', result.stdout)
                if match:
                    net = ipaddress.IPv4Network(
                        f"{match.group(1)}/{match.group(2)}", strict=False
                    )
                    self._network_cidr = str(net)
                    return self._network_cidr
        except Exception as e:
            logger.debug("Auto-detect network CIDR failed: %s", e)

        return None

    def start(self):
        """Start background discovery threads."""
        if self._running:
            return

        cidr = self.get_network_cidr()
        if not cidr:
            logger.error("Cannot start discovery: no network CIDR available")
            return

        self._running = True
        self._stop_event.clear()
        logger.info(
            "Starting discovery engine on %s (%s) — "
            "active every %.0fs, stale timeout %ds",
            self.interface or "default",
            cidr,
            self._active_interval,
            self._stale_timeout,
        )

        # Start passive listener
        self._passive_listener.start()

        # Start active scan thread
        self._active_thread = threading.Thread(
            target=self._active_loop, daemon=True, name="discovery-active"
        )
        self._active_thread.start()

        # Start stale-sweep thread
        self._stale_thread = threading.Thread(
            target=self._stale_loop, daemon=True, name="discovery-stale"
        )
        self._stale_thread.start()

    def stop(self):
        """Stop all background threads cleanly."""
        if not self._running:
            return
        self._running = False
        self._stop_event.set()

        self._passive_listener.stop()
        self._batcher.stop()

        # Wait for threads
        for t in (self._active_thread, self._stale_thread):
            if t is not None and t.is_alive():
                t.join(timeout=5)

        logger.info("Discovery engine stopped")

    def trigger_active_scan(self):
        """Trigger an immediate active ARP sweep (non-blocking)."""
        if self._running:
            # Wake the active loop early
            self._stop_event.set()

    # -- background loops ----------------------------------------------------

    def _active_loop(self):
        """Periodically run active ARP sweeps."""
        while self._running:
            try:
                cidr = self.get_network_cidr()
                if cidr:
                    results = self._active_scanner.scan(cidr)
                    with self._stats_lock:
                        self._stats["active_scans"] += 1
                    self._process_arp_results(results, source="arp_active")
            except Exception as e:
                logger.error("Active ARP scan error: %s", e)

            # Wait for interval or early wake-up
            self._stop_event.wait(timeout=self._active_interval)
            if not self._running:
                break
            # Reset event (it might have been set for early trigger)
            self._stop_event.clear()

    def _stale_loop(self):
        """Periodically sweep for stale devices."""
        # Check more often than the stale timeout
        check_interval = max(5.0, self._stale_timeout / 4)
        while self._running:
            try:
                newly_offline = self.registry.sweep_stale()
                if newly_offline:
                    with self._stats_lock:
                        self._stats["total_leaves"] += len(newly_offline)
                    for dev in newly_offline:
                        self._batcher.add("device_left", dev)
            except Exception as e:
                logger.error("Stale sweep error: %s", e)

            self._stop_event.wait(timeout=check_interval)
            if not self._running:
                break

    # -- internal helpers ----------------------------------------------------

    def _on_passive_arp(self, ip: str, mac: str):
        """Callback from the passive ARP listener."""
        with self._stats_lock:
            self._stats["passive_packets"] += 1
        self._process_single(ip, mac, source="arp_passive")

    def _process_arp_results(
        self, results: List[Tuple[str, str]], source: str = "arp"
    ):
        """Feed a list of (ip, mac) results into the registry."""
        for ip, mac in results:
            self._process_single(ip, mac, source)

    def _process_single(self, ip: str, mac: str, source: str):
        """Process a single IP/MAC observation."""
        vendor = lookup_vendor(mac)
        is_new, ip_changed = self.registry.upsert(mac, ip, vendor=vendor, source=source)

        dev = self.registry.get(mac)
        if dev is None:
            return

        with self._stats_lock:
            self._stats["total_devices_seen"] += 1

        if is_new:
            with self._stats_lock:
                self._stats["total_joins"] += 1
            self._batcher.add("device_joined", dev)
        elif ip_changed:
            self._batcher.add("device_ip_changed", dev)

    def _emit_events(self, event_type: str, devices: List[DiscoveredDevice]):
        """Forward batched events to the external callback."""
        if self._event_callback:
            try:
                self._event_callback(event_type, devices)
            except Exception as e:
                logger.error("Event callback error for %s: %s", event_type, e)
