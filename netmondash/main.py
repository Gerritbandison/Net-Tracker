#!/usr/bin/env python3
"""
NetMonDash - AI-Powered Network Device Monitor Dashboard

Main entry point for the application.
"""

import argparse
import asyncio
import logging
import signal
import sys
import time
import threading
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
        self.scan_task = None
        self.scan_lock = threading.Lock()

        # Setup logging
        setup_logging(verbose)

        logger.info("=" * 60)
        logger.info("NetMonDash - AI-Powered Network Monitor")
        logger.info("=" * 60)

        # Detect network interfaces
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

        # Create FastAPI app
        self.app = create_app(
            db_manager=self.db,
            scanner=self.scanner,
            ai_analyzer=self.ai_analyzer,
            notifier=self.notifier,
        )
        self.app.state.scan_executor = self.execute_scan
        self.app.state.scan_lock = self.scan_lock

        logger.info("Application initialized successfully")

    def _run_scan_sync(
        self,
        source: str,
        wait: bool,
        service_detection: bool,
    ) -> dict:
        acquired = self.scan_lock.acquire(blocking=wait)
        if not acquired:
            logger.info("Scan request skipped; scan already in progress")
            return {"status": "in_progress", "source": source}

        try:
            logger.info("Performing network scan...")
            scan_start = time.time()

            devices = self.scanner.scan_network(service_detection=service_detection)
            scan_duration = time.time() - scan_start

            logger.info(f"Scan complete: {len(devices)} devices found in {scan_duration:.2f}s")

            existing_macs = set()
            new_devices = []

            for device in devices:
                if not device.mac:
                    continue

                existing = self.db.get_device(device.mac)

                if not existing:
                    new_devices.append(device)
                    logger.info(f"New device detected: {device.ip} ({device.mac})")

                    if self.notifier:
                        self.notifier.notify_new_device(
                            device.ip,
                            device.mac,
                            device.hostname
                        )

                self.db.add_or_update_device(
                    mac=device.mac,
                    ip=device.ip,
                    hostname=device.hostname,
                    vendor=device.vendor,
                    open_ports=device.open_ports,
                    services=device.services,
                )

                existing_macs.add(device.mac)

            self.db.mark_devices_offline(list(existing_macs))

            scan_summary = self.scanner.get_scan_summary()
            scan_record = self.db.add_scan(
                interface=self.interface.name,
                device_count=len(devices),
                scan_type='network',
                duration_seconds=scan_duration,
                raw_data=scan_summary,
            )

            if self.ai_analyzer and (new_devices or len(devices) > 0):
                logger.info("Performing AI analysis...")
                try:
                    insights = self.ai_analyzer.get_quick_insights(scan_summary)
                    for insight in insights:
                        logger.info(f"AI Insight: {insight}")
                except Exception as e:
                    logger.error(f"AI analysis failed: {e}")

            return {
                "status": "completed",
                "scan_id": scan_record.id,
                "device_count": len(devices),
                "new_devices": len(new_devices),
                "duration": scan_duration,
                "source": source,
            }

        except Exception as e:
            logger.error(f"Error running scan: {e}", exc_info=True)
            return {"status": "error", "message": str(e), "source": source}

        finally:
            self.scan_lock.release()

    async def execute_scan(
        self,
        source: str = "scheduled",
        wait: bool = True,
        service_detection: bool = False,
    ) -> dict:
        result = await asyncio.to_thread(
            self._run_scan_sync,
            source,
            wait,
            service_detection,
        )

        if result.get("status") != "completed":
            return result

        await broadcast_scan_update({
            "scan_id": result["scan_id"],
            "device_count": result["device_count"],
            "new_devices": result["new_devices"],
            "duration": result["duration"],
            "source": result["source"],
        })

        return result

    async def scan_loop(self) -> None:
        """Background task for periodic network scanning."""
        logger.info("Starting scan loop...")

        while self.running:
            try:
                result = await self.execute_scan(source="scheduled", wait=True)
                if result.get("status") != "completed":
                    logger.warning(f"Scheduled scan did not complete: {result.get('status')}")

                logger.debug(f"Waiting {self.scan_interval}s until next scan...")
                await asyncio.sleep(self.scan_interval)

            except asyncio.CancelledError:
                logger.info("Scan loop cancelled")
                break

            except Exception as e:
                logger.error(f"Error in scan loop: {e}", exc_info=True)
                await asyncio.sleep(self.scan_interval)

        logger.info("Scan loop stopped")

    def start_scan_loop(self) -> None:
        """Start the background scan loop."""
        self.running = True
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        self.scan_task = loop.create_task(self.scan_loop())

    def stop_scan_loop(self) -> None:
        """Stop the background scan loop."""
        logger.info("Stopping scan loop...")
        self.running = False

        if self.scan_task:
            self.scan_task.cancel()

    def run(self) -> None:
        """Run the application."""
        logger.info(f"Starting web server on {DEFAULT_HOST}:{self.port}")
        logger.info(f"Dashboard URL: http://localhost:{self.port}")

        # Setup signal handlers
        def signal_handler(sig, frame):
            logger.info("Shutdown signal received")
            self.stop_scan_loop()
            sys.exit(0)

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        # Start scan loop in background
        import threading
        scan_thread = threading.Thread(target=self.start_scan_loop, daemon=True)
        scan_thread.start()

        # Run web server
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
            self.stop_scan_loop()


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
        version='NetMonDash 1.0.0'
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
