#!/usr/bin/env python3
"""
NetMonDash - AI-Powered Network Device Monitor Dashboard

Main entry point for the application.

Architecture:
    1. **DiscoveryEngine** (always-on, lightweight)
       - Passive ARP sniffing via scapy AsyncSniffer (zero extra traffic)
       - Active ARP sweep every 15 s (< 1 s for a /24, near-zero CPU)
       - In-memory DeviceRegistry with TTL-based stale detection
       - Batched event delivery to WebSocket clients

    2. **Deep nmap scan** (infrequent, expensive)
       - Triggered for **new MACs** (unknown device just joined)
       - Triggered on a **long interval** (default 30 min) for all devices
       - Triggered **manually** via the dashboard "Scan Now" button
       - Provides service/version/OS detection, port enumeration

    3. **Cleanup loop** runs every 6 hours to prune old DB records.
"""

import argparse
import asyncio
import logging
import shutil
import signal
import sys
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import List, Optional, Set

import uvicorn

from config import (
    DEFAULT_WEB_PORT,
    DEFAULT_HOST,
    DEFAULT_SCAN_INTERVAL,
    LOG_FILE,
    LOG_FORMAT,
    LOG_DATE_FORMAT,
    LOG_MAX_BYTES,
    LOG_BACKUP_COUNT,
    ENABLE_AI,
    DISCOVERY_ACTIVE_INTERVAL,
    DISCOVERY_STALE_TIMEOUT,
    DISCOVERY_BATCH_INTERVAL,
    DEEP_SCAN_INTERVAL,
    DEEP_SCAN_NEW_DEVICE_DELAY,
)

from modules import (
    detect_network_interfaces,
    get_preferred_interface,
    NetworkScanner,
    AIAnalyzer,
    init_database,
    Notifier,
    DiscoveryEngine,
    DiscoveredDevice,
)

from dashboard import create_app
from dashboard.websocket import (
    broadcast_scan_update,
    broadcast_device_update,
    broadcast_discovery_batch,
)

# Setup logging
from logging.handlers import RotatingFileHandler

VERSION = "2.1.0"

CLEANUP_INTERVAL_SECONDS = 6 * 60 * 60  # 6 hours


def setup_logging(verbose: bool = False) -> None:
    """
    Setup application logging.

    Args:
        verbose: Enable debug logging
    """
    level = logging.DEBUG if verbose else logging.INFO

    # Create formatters and handlers
    formatter = logging.Formatter(LOG_FORMAT, LOG_DATE_FORMAT)

    # File handler with rotation
    file_handler = RotatingFileHandler(
        LOG_FILE,
        maxBytes=LOG_MAX_BYTES,
        backupCount=LOG_BACKUP_COUNT
    )
    file_handler.setFormatter(formatter)
    file_handler.setLevel(logging.DEBUG)

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    console_handler.setLevel(level)

    # Root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)

    # Suppress noisy libraries
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('matplotlib').setLevel(logging.WARNING)
    logging.getLogger('scapy.runtime').setLevel(logging.WARNING)

    logging.info("Logging initialized")


logger = logging.getLogger(__name__)


def check_nmap_available() -> bool:
    """
    Check whether nmap is installed and accessible on the system PATH.

    Returns:
        True if nmap is found, False otherwise.
    """
    return shutil.which("nmap") is not None


class NetMonDash:
    """Main application class for NetMonDash."""

    def __init__(
        self,
        interface: Optional[str] = None,
        port: int = DEFAULT_WEB_PORT,
        scan_interval: int = DEFAULT_SCAN_INTERVAL,
        enable_ai: bool = ENABLE_AI,
        verbose: bool = False,
    ):
        """
        Initialize NetMonDash application.

        Args:
            interface: Network interface to use (None for auto-detect)
            port: Web server port
            scan_interval: Scan interval in seconds (used as deep scan interval)
            enable_ai: Enable AI analysis
            verbose: Enable verbose logging
        """
        self.port = port
        self.scan_interval = scan_interval
        self.enable_ai = enable_ai
        self.running = False
        self.scan_task: Optional[asyncio.Task] = None
        self.cleanup_task: Optional[asyncio.Task] = None
        self.discovery_task: Optional[asyncio.Task] = None

        # Track MACs pending a deep scan
        self._deep_scan_queue: asyncio.Queue = None  # created in lifespan
        self._deep_scanned_macs: Set[str] = set()
        self._last_full_deep_scan: float = 0.0

        # Setup logging
        setup_logging(verbose)

        logger.info("=" * 60)
        logger.info("NetMonDash - AI-Powered Network Monitor  v%s", VERSION)
        logger.info("=" * 60)

        # --- Startup validation: nmap ---
        logger.info("Checking nmap availability...")
        self._nmap_available = check_nmap_available()
        if self._nmap_available:
            logger.info("nmap found — deep scans enabled")
        else:
            logger.warning(
                "nmap not found — deep scans disabled. "
                "ARP-based discovery will still work."
            )

        # --- Startup validation: network interfaces ---
        logger.info("Detecting network interfaces...")
        self.interfaces = detect_network_interfaces()

        if not self.interfaces:
            logger.error("No network interfaces detected!")
            sys.exit(1)

        # Select interface
        if interface:
            # Use specified interface
            selected = next((i for i in self.interfaces if i.name == interface), None)
            if not selected:
                logger.error(f"Interface '{interface}' not found!")
                logger.info(f"Available interfaces: {', '.join(i.name for i in self.interfaces)}")
                sys.exit(1)
            self.interface = selected
        else:
            # Auto-detect preferred interface
            self.interface = get_preferred_interface()

        if not self.interface:
            logger.error("Could not determine network interface!")
            sys.exit(1)

        # Validate the chosen interface has an IP address
        if not self.interface.ip_addresses:
            logger.warning(
                f"Interface '{self.interface.name}' has no IP addresses assigned. "
                "Scanning may not work correctly."
            )

        logger.info(f"Using interface: {self.interface.name} ({self.interface.type})")
        if self.interface.is_a9000:
            logger.info("Netgear A9000 adapter detected!")
            logger.info(f"Supported bands: {', '.join(self.interface.supported_bands)}")

        # Initialize components
        logger.info("Initializing components...")

        # Database
        self.db = init_database()
        logger.info("Database initialized")

        # Scanner (still used for deep scans and WiFi)
        self.scanner = NetworkScanner(interface=self.interface.name)
        logger.info("Scanner initialized")

        # Discovery Engine (lightweight ARP-based)
        self._event_loop: Optional[asyncio.AbstractEventLoop] = None
        self.discovery = DiscoveryEngine(
            interface=self.interface.name,
            event_callback=self._on_discovery_event,
            active_interval=DISCOVERY_ACTIVE_INTERVAL,
            stale_timeout=DISCOVERY_STALE_TIMEOUT,
            batch_interval=DISCOVERY_BATCH_INTERVAL,
        )
        logger.info(
            "Discovery engine initialized (active every %ds, stale timeout %ds)",
            DISCOVERY_ACTIVE_INTERVAL,
            DISCOVERY_STALE_TIMEOUT,
        )

        # AI Analyzer
        if self.enable_ai:
            try:
                self.ai_analyzer = AIAnalyzer()
                logger.info("AI analyzer initialized")
            except Exception as e:
                logger.warning(f"AI analyzer initialization failed: {e}")
                self.ai_analyzer = None
        else:
            self.ai_analyzer = None
            logger.info("AI analysis disabled")

        # Notifier
        self.notifier = Notifier()
        logger.info("Notifier initialized")

        # The asyncio.Event used for manual scan triggers.
        self._scan_now_event: Optional[asyncio.Event] = None

        # Build FastAPI application with lifespan
        self.app = self._build_app()

        logger.info("Application initialized successfully")

    # ------------------------------------------------------------------
    # FastAPI app construction with lifespan
    # ------------------------------------------------------------------

    def _build_app(self):
        """Create the FastAPI app, wiring in the lifespan context manager."""

        @asynccontextmanager
        async def lifespan(app):
            """Manage startup and shutdown of background tasks."""
            logger.info("Lifespan startup: launching background tasks")

            self.running = True
            self._event_loop = asyncio.get_running_loop()

            # Create the manual-scan trigger event on the current loop
            self._scan_now_event = asyncio.Event()
            app.state.scan_now_event = self._scan_now_event

            # Deep scan queue
            self._deep_scan_queue = asyncio.Queue()

            # Store discovery engine in app state for routes
            app.state.discovery = self.discovery

            # Start the discovery engine (background threads)
            self.discovery.start()

            # Launch async background tasks
            self.scan_task = asyncio.create_task(self.deep_scan_loop())
            self.cleanup_task = asyncio.create_task(self.cleanup_loop())
            self.discovery_task = asyncio.create_task(self._process_deep_scan_queue())

            logger.info("Background tasks started")

            yield  # application is running

            # --- Shutdown ---
            logger.info("Lifespan shutdown: stopping background tasks")
            self.running = False

            # Stop discovery engine threads
            self.discovery.stop()

            # Signal the scan event so the loop can exit promptly
            if self._scan_now_event is not None:
                self._scan_now_event.set()

            for task, name in [
                (self.scan_task, "deep_scan_loop"),
                (self.cleanup_task, "cleanup_loop"),
                (self.discovery_task, "deep_scan_queue_processor"),
            ]:
                if task is not None:
                    task.cancel()
                    try:
                        await task
                    except asyncio.CancelledError:
                        logger.info(f"{name} cancelled cleanly")

            logger.info("All background tasks stopped")

        # Create the underlying FastAPI app via the existing factory
        app = create_app(
            db_manager=self.db,
            scanner=self.scanner,
            ai_analyzer=self.ai_analyzer,
            notifier=self.notifier,
        )

        # Attach the lifespan handler
        app.router.lifespan_context = lifespan

        return app

    # ------------------------------------------------------------------
    # Discovery event handler (called from background thread)
    # ------------------------------------------------------------------

    def _on_discovery_event(
        self, event_type: str, devices: List[DiscoveredDevice]
    ):
        """Handle batched discovery events from the DiscoveryEngine.

        This runs on a background thread, so we schedule async work on
        the main event loop.
        """
        if self._event_loop is None or not self.running:
            return

        asyncio.run_coroutine_threadsafe(
            self._handle_discovery_async(event_type, devices),
            self._event_loop,
        )

    async def _handle_discovery_async(
        self, event_type: str, devices: List[DiscoveredDevice]
    ):
        """Async handler for discovery events — updates DB and broadcasts."""
        try:
            for dev in devices:
                if event_type == "device_joined":
                    # Check if this is truly new to the DB
                    existing = self.db.get_device(dev.mac)
                    if not existing:
                        logger.info(
                            "New device discovered via ARP: %s (%s) vendor=%s",
                            dev.ip, dev.mac, dev.vendor,
                        )
                        self.notifier.notify_new_device(dev.ip, dev.mac, None)

                    # Quick ping for baseline latency (non-blocking)
                    loop = asyncio.get_running_loop()
                    ping_data = await loop.run_in_executor(
                        None,
                        lambda ip=dev.ip: self.scanner.ping_host_detailed(
                            ip, count=2, timeout=1
                        ),
                    )

                    # Upsert into database with latency
                    self.db.add_or_update_device(
                        mac=dev.mac,
                        ip=dev.ip,
                        vendor=dev.vendor,
                        latency_ms=ping_data.get("avg_ms"),
                        jitter_ms=ping_data.get("jitter_ms"),
                        packet_loss=ping_data.get("packet_loss"),
                        ttl=ping_data.get("ttl"),
                    )

                    # Queue for deep nmap scan if nmap available
                    if (
                        self._nmap_available
                        and dev.mac not in self._deep_scanned_macs
                        and self._deep_scan_queue is not None
                    ):
                        await self._deep_scan_queue.put(dev)

                elif event_type == "device_left":
                    logger.info(
                        "Device went offline: %s (%s)", dev.ip, dev.mac
                    )
                    self.notifier.notify_device_offline(dev.ip, None)
                    # Mark offline in DB: pass currently-online MACs so that
                    # any device NOT in this set gets marked offline.
                    # The registry has already flipped this device to offline,
                    # so get_online_macs() returns the correct remaining set.
                    remaining_online = self.discovery.registry.get_online_macs()
                    self.db.mark_devices_offline(list(remaining_online))

                elif event_type == "device_ip_changed":
                    logger.info(
                        "Device %s changed IP to %s", dev.mac, dev.ip
                    )
                    self.db.add_or_update_device(
                        mac=dev.mac,
                        ip=dev.ip,
                        vendor=dev.vendor,
                    )

            # Broadcast to WebSocket clients (batched)
            await broadcast_discovery_batch(event_type, devices)

        except Exception as e:
            logger.error("Error handling discovery event %s: %s", event_type, e)

    # ------------------------------------------------------------------
    # Background: process deep scan queue (new devices)
    # ------------------------------------------------------------------

    async def _process_deep_scan_queue(self):
        """Consume the deep-scan queue — nmap new devices one at a time."""
        logger.info("Deep scan queue processor started")

        while self.running:
            try:
                dev = await asyncio.wait_for(
                    self._deep_scan_queue.get(),
                    timeout=5.0,
                )

                # Brief delay so ARP info can settle
                await asyncio.sleep(DEEP_SCAN_NEW_DEVICE_DELAY)

                if not self.running:
                    break

                if dev.mac in self._deep_scanned_macs:
                    continue

                logger.info(
                    "Deep scanning new device %s (%s)...", dev.ip, dev.mac
                )
                loop = asyncio.get_running_loop()
                device_info = await loop.run_in_executor(
                    None,
                    lambda: self.scanner.deep_scan_device(dev.ip),
                )

                if device_info and device_info.mac:
                    self.db.add_or_update_device(
                        mac=device_info.mac,
                        ip=device_info.ip,
                        hostname=device_info.hostname,
                        vendor=device_info.vendor or dev.vendor,
                        open_ports=device_info.open_ports,
                        services=device_info.services,
                        latency_ms=device_info.latency_ms,
                        os_guess=device_info.os_guess,
                        jitter_ms=device_info.jitter_ms,
                        packet_loss=device_info.packet_loss,
                        ttl=device_info.ttl,
                    )
                    await broadcast_device_update(device_info.to_dict(), event="deep_scanned")
                    self._deep_scanned_macs.add(dev.mac)
                    logger.info(
                        "Deep scan complete for %s: %d ports, os=%s",
                        dev.ip,
                        len(device_info.open_ports),
                        device_info.os_guess,
                    )

            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Deep scan queue error: %s", e)
                await asyncio.sleep(2)

        logger.info("Deep scan queue processor stopped")

    # ------------------------------------------------------------------
    # Background: periodic full deep scan (every 30 min)
    # ------------------------------------------------------------------

    async def deep_scan_loop(self) -> None:
        """Periodic full nmap scan at a long interval (default 30 min).

        This replaces the old scan_loop.  Between deep scans, the
        DiscoveryEngine handles real-time device tracking via ARP.
        """
        deep_interval = max(self.scan_interval, DEEP_SCAN_INTERVAL)
        logger.info(
            "Starting deep scan loop (interval: %ds)...", deep_interval
        )

        while self.running:
            try:
                if not self._nmap_available:
                    # No nmap — just record discovery stats periodically
                    registry_snapshot = self.discovery.registry.get_online()
                    online_macs = {d.mac for d in registry_snapshot}

                    # Sync the DB with the discovery registry
                    for dev in registry_snapshot:
                        self.db.add_or_update_device(
                            mac=dev.mac, ip=dev.ip, vendor=dev.vendor,
                        )
                    self.db.mark_devices_offline(list(online_macs))

                    self.db.add_scan(
                        interface=self.interface.name,
                        device_count=len(registry_snapshot),
                        scan_type="arp_discovery",
                        duration_seconds=0,
                    )

                    await broadcast_scan_update({
                        "device_count": len(registry_snapshot),
                        "scan_type": "arp_discovery",
                        "new_devices": 0,
                        "offline_devices": 0,
                        "duration": 0,
                    })

                else:
                    # Full nmap scan
                    logger.info("Starting periodic deep nmap scan...")
                    scan_start = time.time()

                    loop = asyncio.get_running_loop()
                    devices = await loop.run_in_executor(
                        None,
                        lambda: self.scanner.scan_network(
                            service_detection=False
                        ),
                    )
                    scan_duration = time.time() - scan_start

                    logger.info(
                        "Deep scan complete: %d devices in %.2fs",
                        len(devices), scan_duration,
                    )

                    # Track new devices
                    existing_macs = set()
                    new_devices = []

                    for device in devices:
                        if not device.mac:
                            continue

                        existing = self.db.get_device(device.mac)
                        if not existing:
                            new_devices.append(device)
                            logger.info(
                                "New device (deep scan): %s (%s)",
                                device.ip, device.mac,
                            )
                            self.notifier.notify_new_device(
                                device.ip, device.mac, device.hostname
                            )
                            await broadcast_device_update(
                                device.to_dict(), event="new"
                            )

                        # Update database with full scan results
                        self.db.add_or_update_device(
                            mac=device.mac,
                            ip=device.ip,
                            hostname=device.hostname,
                            vendor=device.vendor,
                            open_ports=device.open_ports,
                            services=device.services,
                        )

                        # Feed into discovery registry too
                        self.discovery.registry.upsert(
                            device.mac, device.ip,
                            vendor=device.vendor, source="nmap",
                        )

                        existing_macs.add(device.mac)
                        self._deep_scanned_macs.add(device.mac)

                    # Mark offline
                    offline_count, offline_devices = self.db.mark_devices_offline(
                        list(existing_macs)
                    )
                    for dev_dict in offline_devices:
                        self.notifier.notify_device_offline(
                            dev_dict.get("ip", "unknown"),
                            dev_dict.get("hostname"),
                        )
                        await broadcast_device_update(dev_dict, event="offline")

                    if offline_count > 0:
                        logger.info("%d device(s) went offline", offline_count)

                    # Record scan
                    scan_record = self.db.add_scan(
                        interface=self.interface.name,
                        device_count=len(devices),
                        scan_type="deep_nmap",
                        duration_seconds=scan_duration,
                        raw_data=self.scanner.get_scan_summary(),
                        new_device_count=len(new_devices),
                        offline_device_count=offline_count,
                    )

                    await broadcast_scan_update({
                        "scan_id": scan_record.id,
                        "device_count": len(devices),
                        "scan_type": "deep_nmap",
                        "new_devices": len(new_devices),
                        "offline_devices": offline_count,
                        "duration": scan_duration,
                    })

                    # AI analysis
                    if self.ai_analyzer and (new_devices or len(devices) > 0):
                        try:
                            scan_data = self.scanner.get_scan_summary()
                            insights = self.ai_analyzer.get_quick_insights(
                                scan_data
                            )
                            for insight in insights:
                                logger.info("AI Insight: %s", insight)
                        except Exception as e:
                            logger.error("AI analysis failed: %s", e)

                    self._last_full_deep_scan = time.time()

                # Wait for next deep scan interval or manual trigger
                logger.debug(
                    "Waiting %ds until next deep scan...", deep_interval
                )
                try:
                    await asyncio.wait_for(
                        self._scan_now_event.wait(),
                        timeout=deep_interval,
                    )
                    logger.info("Manual scan trigger received")
                    self._scan_now_event.clear()
                except asyncio.TimeoutError:
                    pass

            except asyncio.CancelledError:
                logger.info("Deep scan loop cancelled")
                break

            except Exception as e:
                logger.error("Error in deep scan loop: %s", e, exc_info=True)
                try:
                    await asyncio.wait_for(
                        self._scan_now_event.wait(),
                        timeout=deep_interval,
                    )
                    self._scan_now_event.clear()
                except (asyncio.TimeoutError, asyncio.CancelledError):
                    pass

        logger.info("Deep scan loop stopped")

    # ------------------------------------------------------------------
    # Background: periodic data cleanup
    # ------------------------------------------------------------------

    async def cleanup_loop(self) -> None:
        """Background task that periodically cleans up old database records."""
        logger.info("Starting cleanup loop (interval: %d seconds)", CLEANUP_INTERVAL_SECONDS)

        while self.running:
            try:
                await asyncio.sleep(CLEANUP_INTERVAL_SECONDS)

                if not self.running:
                    break

                logger.info("Running periodic data cleanup...")
                stats = self.db.cleanup_old_data()
                logger.info(f"Cleanup results: {stats}")

            except asyncio.CancelledError:
                logger.info("Cleanup loop cancelled")
                break

            except Exception as e:
                logger.error(f"Error in cleanup loop: {e}", exc_info=True)

        logger.info("Cleanup loop stopped")

    # ------------------------------------------------------------------
    # Run
    # ------------------------------------------------------------------

    def run(self) -> None:
        """Run the application."""
        logger.info(f"Starting web server on {DEFAULT_HOST}:{self.port}")
        logger.info(f"Dashboard URL: http://localhost:{self.port}")

        # Setup signal handlers for graceful shutdown
        def signal_handler(sig, frame):
            logger.info("Shutdown signal received (%s)", signal.Signals(sig).name)
            self.running = False

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        try:
            uvicorn.run(
                self.app,
                host=DEFAULT_HOST,
                port=self.port,
                log_level="info",
                access_log=True,
            )
        except Exception as e:
            logger.error(f"Server error: {e}", exc_info=True)
        finally:
            self.running = False
            self.discovery.stop()
            logger.info("NetMonDash shut down")


def main() -> None:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="NetMonDash - AI-Powered Network Device Monitor Dashboard",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py
  python main.py --interface wlan0 --port 8080
  python main.py --scan-interval 60 --verbose
  python main.py --no-ai

For more information, visit: https://github.com/yourusername/netmondash
        """
    )

    parser.add_argument(
        '-i', '--interface',
        type=str,
        default=None,
        help='Network interface to use (default: auto-detect)'
    )

    parser.add_argument(
        '-p', '--port',
        type=int,
        default=DEFAULT_WEB_PORT,
        help=f'Web server port (default: {DEFAULT_WEB_PORT})'
    )

    parser.add_argument(
        '--scan-interval',
        type=int,
        default=DEFAULT_SCAN_INTERVAL,
        help=f'Scan interval in seconds (default: {DEFAULT_SCAN_INTERVAL})'
    )

    parser.add_argument(
        '--no-ai',
        action='store_true',
        help='Disable AI analysis'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose logging'
    )

    parser.add_argument(
        '--version',
        action='version',
        version=f'NetMonDash {VERSION}'
    )

    args = parser.parse_args()

    # Create and run application
    try:
        app = NetMonDash(
            interface=args.interface,
            port=args.port,
            scan_interval=args.scan_interval,
            enable_ai=not args.no_ai,
            verbose=args.verbose,
        )

        app.run()

    except KeyboardInterrupt:
        logger.info("Application stopped by user")
        sys.exit(0)

    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
