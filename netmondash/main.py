#!/usr/bin/env python3
"""
NetMonDash - AI-Powered Network Device Monitor Dashboard

Main entry point for the application.
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
from typing import Optional

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
)

from modules import (
    detect_network_interfaces,
    get_preferred_interface,
    NetworkScanner,
    AIAnalyzer,
    init_database,
    Notifier,
)

from dashboard import create_app
from dashboard.websocket import broadcast_scan_update, broadcast_device_update

# Setup logging
from logging.handlers import RotatingFileHandler

VERSION = "2.0.0"

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
            scan_interval: Scan interval in seconds
            enable_ai: Enable AI analysis
            verbose: Enable verbose logging
        """
        self.port = port
        self.scan_interval = scan_interval
        self.enable_ai = enable_ai
        self.running = False
        self.scan_task: Optional[asyncio.Task] = None
        self.cleanup_task: Optional[asyncio.Task] = None

        # Setup logging
        setup_logging(verbose)

        logger.info("=" * 60)
        logger.info("NetMonDash - AI-Powered Network Monitor  v%s", VERSION)
        logger.info("=" * 60)

        # --- Startup validation: nmap ---
        logger.info("Checking nmap availability...")
        if not check_nmap_available():
            logger.error(
                "nmap is not installed or not found on PATH. "
                "Please install nmap (e.g. 'sudo apt install nmap') and try again."
            )
            sys.exit(1)
        logger.info("nmap found")

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

        # Scanner
        self.scanner = NetworkScanner(interface=self.interface.name)
        logger.info(f"Scanner initialized (interval: {self.scan_interval}s)")

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

        # The asyncio.Event used for manual scan triggers.  Created here so
        # it can be stored in app.state before the event loop starts; the
        # actual Event object is bound to the running loop inside lifespan.
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

            # Create the manual-scan trigger event on the current loop
            self._scan_now_event = asyncio.Event()
            app.state.scan_now_event = self._scan_now_event

            # Launch background tasks
            self.scan_task = asyncio.create_task(self.scan_loop())
            self.cleanup_task = asyncio.create_task(self.cleanup_loop())

            logger.info("Background tasks started")

            yield  # application is running

            # --- Shutdown ---
            logger.info("Lifespan shutdown: stopping background tasks")
            self.running = False

            # Signal the scan event so the loop can exit promptly
            if self._scan_now_event is not None:
                self._scan_now_event.set()

            for task, name in [
                (self.scan_task, "scan_loop"),
                (self.cleanup_task, "cleanup_loop"),
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
    # Background: network scan loop
    # ------------------------------------------------------------------

    async def scan_loop(self) -> None:
        """Background task for periodic network scanning."""
        logger.info("Starting scan loop...")

        while self.running:
            try:
                logger.info("Performing network scan...")
                scan_start = time.time()

                # Perform scan (blocking I/O; run in executor so we don't
                # block the event loop)
                loop = asyncio.get_running_loop()
                devices = await loop.run_in_executor(
                    None, lambda: self.scanner.scan_network(service_detection=False)
                )
                scan_duration = time.time() - scan_start

                logger.info(f"Scan complete: {len(devices)} devices found in {scan_duration:.2f}s")

                # Track new devices
                existing_macs = set()
                new_devices = []

                for device in devices:
                    if not device.mac:
                        continue

                    # Check if device exists
                    existing = self.db.get_device(device.mac)

                    if not existing:
                        new_devices.append(device)
                        logger.info(f"New device detected: {device.ip} ({device.mac})")

                        # Send notification
                        self.notifier.notify_new_device(
                            device.ip,
                            device.mac,
                            device.hostname
                        )

                        # Broadcast new-device event over WebSocket
                        await broadcast_device_update(device.to_dict(), event="new")

                    # Update database
                    self.db.add_or_update_device(
                        mac=device.mac,
                        ip=device.ip,
                        hostname=device.hostname,
                        vendor=device.vendor,
                        open_ports=device.open_ports,
                        services=device.services,
                    )

                    existing_macs.add(device.mac)

                # Mark offline devices and handle notifications
                offline_count, offline_devices = self.db.mark_devices_offline(list(existing_macs))

                for dev_dict in offline_devices:
                    self.notifier.notify_device_offline(
                        dev_dict.get("ip", "unknown"),
                        dev_dict.get("hostname"),
                    )
                    await broadcast_device_update(dev_dict, event="offline")

                if offline_count > 0:
                    logger.info(f"{offline_count} device(s) went offline")

                # Record scan with complete metrics
                scan_record = self.db.add_scan(
                    interface=self.interface.name,
                    device_count=len(devices),
                    scan_type='network',
                    duration_seconds=scan_duration,
                    raw_data=self.scanner.get_scan_summary(),
                    new_device_count=len(new_devices),
                    offline_device_count=offline_count,
                )

                # Broadcast update via WebSocket
                await broadcast_scan_update({
                    'scan_id': scan_record.id,
                    'device_count': len(devices),
                    'new_devices': len(new_devices),
                    'offline_devices': offline_count,
                    'duration': scan_duration,
                })

                # Perform AI analysis if enabled and new devices found
                if self.ai_analyzer and (new_devices or len(devices) > 0):
                    logger.info("Performing AI analysis...")
                    try:
                        scan_data = self.scanner.get_scan_summary()
                        insights = self.ai_analyzer.get_quick_insights(scan_data)

                        # Log insights
                        for insight in insights:
                            logger.info(f"AI Insight: {insight}")

                    except Exception as e:
                        logger.error(f"AI analysis failed: {e}")

                # Wait for the next scan interval OR a manual trigger
                logger.debug(f"Waiting {self.scan_interval}s until next scan...")
                try:
                    await asyncio.wait_for(
                        self._scan_now_event.wait(),
                        timeout=self.scan_interval,
                    )
                    # If we reach here, the event was set (manual trigger)
                    logger.info("Manual scan trigger received")
                    self._scan_now_event.clear()
                except asyncio.TimeoutError:
                    # Normal interval elapsed
                    pass

            except asyncio.CancelledError:
                logger.info("Scan loop cancelled")
                break

            except Exception as e:
                logger.error(f"Error in scan loop: {e}", exc_info=True)
                # Even after an error, respect the interval / manual trigger
                try:
                    await asyncio.wait_for(
                        self._scan_now_event.wait(),
                        timeout=self.scan_interval,
                    )
                    self._scan_now_event.clear()
                except (asyncio.TimeoutError, asyncio.CancelledError):
                    pass

        logger.info("Scan loop stopped")

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
            # Uvicorn's own signal handling will take care of stopping the
            # server; we just ensure the flag is toggled.

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        # Run web server -- the lifespan context manager handles the
        # background tasks on the same event loop.
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
