"""
Database Module

SQLAlchemy models and database operations for NetMonDash.
"""

import logging
from datetime import datetime, timedelta
from typing import List, Optional, Dict
import json

from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean, Text, Float
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import StaticPool

from config import DATABASE_URL, DB_ECHO, DEVICE_HISTORY_RETENTION_DAYS

logger = logging.getLogger(__name__)

Base = declarative_base()


class Device(Base):
    """Network device model."""

    __tablename__ = "devices"

    mac = Column(String(17), primary_key=True)  # MAC address as primary key
    ip = Column(String(45), nullable=False)  # IPv4 or IPv6
    hostname = Column(String(255), nullable=True)
    vendor = Column(String(255), nullable=True)
    first_seen = Column(DateTime, nullable=False, default=datetime.now)
    last_seen = Column(DateTime, nullable=False, default=datetime.now, onupdate=datetime.now)
    is_online = Column(Boolean, default=True)
    open_ports = Column(Text, nullable=True)  # JSON array of open ports
    services = Column(Text, nullable=True)  # JSON object of port:service mappings
    notes = Column(Text, nullable=True)

    def to_dict(self) -> Dict:
        """Convert to dictionary representation."""
        return {
            "mac": self.mac,
            "ip": self.ip,
            "hostname": self.hostname,
            "vendor": self.vendor,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "is_online": self.is_online,
            "open_ports": json.loads(self.open_ports) if self.open_ports else [],
            "services": json.loads(self.services) if self.services else {},
            "notes": self.notes,
        }

    def __repr__(self) -> str:
        return f"<Device {self.mac} ({self.ip}) - {self.hostname or 'Unknown'}>"


class Scan(Base):
    """Network scan record model."""

    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, nullable=False, default=datetime.now)
    interface = Column(String(50), nullable=True)
    device_count = Column(Integer, nullable=False, default=0)
    scan_type = Column(String(50), nullable=True)  # 'network', 'wifi', 'comprehensive'
    duration_seconds = Column(Float, nullable=True)
    raw_json = Column(Text, nullable=True)  # Full scan results as JSON

    def to_dict(self) -> Dict:
        """Convert to dictionary representation."""
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "interface": self.interface,
            "device_count": self.device_count,
            "scan_type": self.scan_type,
            "duration_seconds": self.duration_seconds,
            "raw_data": json.loads(self.raw_json) if self.raw_json else None,
        }

    def __repr__(self) -> str:
        return f"<Scan {self.id} at {self.timestamp} - {self.device_count} devices>"


class Alert(Base):
    """Security and network alert model."""

    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, nullable=False, default=datetime.now)
    severity = Column(String(20), nullable=False)  # 'critical', 'warning', 'info'
    category = Column(String(50), nullable=True)  # 'security', 'health', 'wifi'
    title = Column(String(255), nullable=False)
    message = Column(Text, nullable=False)
    source_ip = Column(String(45), nullable=True)  # Related device IP
    source_mac = Column(String(17), nullable=True)  # Related device MAC
    command = Column(Text, nullable=True)  # Recommended command to execute
    acknowledged = Column(Boolean, default=False)
    acknowledged_at = Column(DateTime, nullable=True)

    def to_dict(self) -> Dict:
        """Convert to dictionary representation."""
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "severity": self.severity,
            "category": self.category,
            "title": self.title,
            "message": self.message,
            "source_ip": self.source_ip,
            "source_mac": self.source_mac,
            "command": self.command,
            "acknowledged": self.acknowledged,
            "acknowledged_at": self.acknowledged_at.isoformat() if self.acknowledged_at else None,
        }

    def __repr__(self) -> str:
        return f"<Alert {self.id} [{self.severity}] {self.title}>"


class DatabaseManager:
    """Database manager for NetMonDash."""

    def __init__(self, database_url: str = DATABASE_URL, echo: bool = DB_ECHO):
        """
        Initialize database manager.

        Args:
            database_url: SQLAlchemy database URL
            echo: Enable SQL query logging
        """
        self.database_url = database_url
        self.engine = create_engine(
            database_url,
            echo=echo,
            connect_args={"check_same_thread": False} if "sqlite" in database_url else {},
            poolclass=StaticPool if "sqlite" in database_url else None,
        )
        self.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)

        # Create tables
        Base.metadata.create_all(bind=self.engine)
        logger.info("Database initialized successfully")

    def get_session(self) -> Session:
        """Get a new database session."""
        return self.SessionLocal()

    # Device operations

    def add_or_update_device(
        self,
        mac: str,
        ip: str,
        hostname: Optional[str] = None,
        vendor: Optional[str] = None,
        open_ports: Optional[List[int]] = None,
        services: Optional[Dict[int, str]] = None,
    ) -> Device:
        """
        Add a new device or update existing device.

        Args:
            mac: MAC address
            ip: IP address
            hostname: Device hostname
            vendor: Device vendor
            open_ports: List of open ports
            services: Dictionary of port:service mappings

        Returns:
            Device object
        """
        session = self.get_session()
        try:
            device = session.query(Device).filter(Device.mac == mac).first()

            if device:
                # Update existing device
                device.ip = ip
                device.last_seen = datetime.now()
                device.is_online = True

                if hostname:
                    device.hostname = hostname
                if vendor:
                    device.vendor = vendor
                if open_ports is not None:
                    device.open_ports = json.dumps(open_ports)
                if services is not None:
                    device.services = json.dumps(services)

                logger.debug(f"Updated device: {mac}")
            else:
                # Create new device
                device = Device(
                    mac=mac,
                    ip=ip,
                    hostname=hostname,
                    vendor=vendor,
                    open_ports=json.dumps(open_ports) if open_ports else None,
                    services=json.dumps(services) if services else None,
                )
                session.add(device)
                logger.info(f"Added new device: {mac} ({ip})")

            session.commit()
            session.refresh(device)
            return device

        except Exception as e:
            session.rollback()
            logger.error(f"Error adding/updating device {mac}: {e}")
            raise
        finally:
            session.close()

    def get_device(self, mac: str) -> Optional[Device]:
        """Get device by MAC address."""
        session = self.get_session()
        try:
            return session.query(Device).filter(Device.mac == mac).first()
        finally:
            session.close()

    def get_all_devices(self, online_only: bool = False) -> List[Device]:
        """
        Get all devices.

        Args:
            online_only: Only return online devices

        Returns:
            List of Device objects
        """
        session = self.get_session()
        try:
            query = session.query(Device)
            if online_only:
                query = query.filter(Device.is_online == True)
            return query.order_by(Device.last_seen.desc()).all()
        finally:
            session.close()

    def mark_devices_offline(self, current_macs: List[str]) -> int:
        """
        Mark devices as offline if they weren't seen in latest scan.

        Args:
            current_macs: List of MAC addresses from current scan

        Returns:
            Number of devices marked offline
        """
        session = self.get_session()
        try:
            result = session.query(Device).filter(
                Device.mac.notin_(current_macs),
                Device.is_online == True
            ).update({"is_online": False}, synchronize_session=False)

            session.commit()
            logger.info(f"Marked {result} devices as offline")
            return result

        except Exception as e:
            session.rollback()
            logger.error(f"Error marking devices offline: {e}")
            return 0
        finally:
            session.close()

    # Scan operations

    def add_scan(
        self,
        interface: Optional[str],
        device_count: int,
        scan_type: str = "network",
        duration_seconds: Optional[float] = None,
        raw_data: Optional[Dict] = None,
    ) -> Scan:
        """
        Record a network scan.

        Args:
            interface: Network interface used
            device_count: Number of devices found
            scan_type: Type of scan performed
            duration_seconds: Scan duration
            raw_data: Full scan results

        Returns:
            Scan object
        """
        session = self.get_session()
        try:
            scan = Scan(
                interface=interface,
                device_count=device_count,
                scan_type=scan_type,
                duration_seconds=duration_seconds,
                raw_json=json.dumps(raw_data) if raw_data else None,
            )
            session.add(scan)
            session.commit()
            session.refresh(scan)

            logger.info(f"Recorded scan: {scan.id} ({device_count} devices)")
            return scan

        except Exception as e:
            session.rollback()
            logger.error(f"Error recording scan: {e}")
            raise
        finally:
            session.close()

    def get_recent_scans(self, limit: int = 10) -> List[Scan]:
        """
        Get recent scans.

        Args:
            limit: Maximum number of scans to return

        Returns:
            List of Scan objects
        """
        session = self.get_session()
        try:
            return session.query(Scan).order_by(Scan.timestamp.desc()).limit(limit).all()
        finally:
            session.close()

    def get_scan_history(self, hours: int = 24) -> List[Scan]:
        """
        Get scan history for specified time period.

        Args:
            hours: Number of hours to look back

        Returns:
            List of Scan objects
        """
        session = self.get_session()
        try:
            cutoff = datetime.now() - timedelta(hours=hours)
            return session.query(Scan).filter(
                Scan.timestamp >= cutoff
            ).order_by(Scan.timestamp.asc()).all()
        finally:
            session.close()

    # Alert operations

    def add_alert(
        self,
        severity: str,
        title: str,
        message: str,
        category: Optional[str] = None,
        source_ip: Optional[str] = None,
        source_mac: Optional[str] = None,
        command: Optional[str] = None,
    ) -> Alert:
        """
        Create a new alert.

        Args:
            severity: Alert severity
            title: Alert title
            message: Alert message
            category: Alert category
            source_ip: Related device IP
            source_mac: Related device MAC
            command: Recommended command

        Returns:
            Alert object
        """
        session = self.get_session()
        try:
            alert = Alert(
                severity=severity,
                title=title,
                message=message,
                category=category,
                source_ip=source_ip,
                source_mac=source_mac,
                command=command,
            )
            session.add(alert)
            session.commit()
            session.refresh(alert)

            logger.info(f"Created alert: {alert.id} [{severity}] {title}")
            return alert

        except Exception as e:
            session.rollback()
            logger.error(f"Error creating alert: {e}")
            raise
        finally:
            session.close()

    def get_unacknowledged_alerts(self) -> List[Alert]:
        """Get all unacknowledged alerts."""
        session = self.get_session()
        try:
            return session.query(Alert).filter(
                Alert.acknowledged == False
            ).order_by(Alert.timestamp.desc()).all()
        finally:
            session.close()

    def get_recent_alerts(self, limit: int = 50) -> List[Alert]:
        """Get recent alerts."""
        session = self.get_session()
        try:
            return session.query(Alert).order_by(Alert.timestamp.desc()).limit(limit).all()
        finally:
            session.close()

    def acknowledge_alert(self, alert_id: int) -> bool:
        """
        Acknowledge an alert.

        Args:
            alert_id: Alert ID

        Returns:
            True if successful
        """
        session = self.get_session()
        try:
            alert = session.query(Alert).filter(Alert.id == alert_id).first()
            if alert:
                alert.acknowledged = True
                alert.acknowledged_at = datetime.now()
                session.commit()
                logger.info(f"Acknowledged alert: {alert_id}")
                return True
            return False
        except Exception as e:
            session.rollback()
            logger.error(f"Error acknowledging alert {alert_id}: {e}")
            return False
        finally:
            session.close()

    # Maintenance operations

    def cleanup_old_data(self, days: int = DEVICE_HISTORY_RETENTION_DAYS) -> Dict[str, int]:
        """
        Clean up old data.

        Args:
            days: Number of days to retain

        Returns:
            Dictionary with cleanup statistics
        """
        session = self.get_session()
        try:
            cutoff = datetime.now() - timedelta(days=days)

            # Delete old scans
            scans_deleted = session.query(Scan).filter(Scan.timestamp < cutoff).delete()

            # Delete old acknowledged alerts
            alerts_deleted = session.query(Alert).filter(
                Alert.timestamp < cutoff,
                Alert.acknowledged == True
            ).delete()

            session.commit()

            stats = {
                "scans_deleted": scans_deleted,
                "alerts_deleted": alerts_deleted,
            }

            logger.info(f"Cleanup complete: {stats}")
            return stats

        except Exception as e:
            session.rollback()
            logger.error(f"Error during cleanup: {e}")
            return {"scans_deleted": 0, "alerts_deleted": 0}
        finally:
            session.close()


def init_database(database_url: str = DATABASE_URL) -> DatabaseManager:
    """
    Initialize database and return manager.

    Args:
        database_url: SQLAlchemy database URL

    Returns:
        DatabaseManager instance
    """
    return DatabaseManager(database_url)


if __name__ == "__main__":
    # Test the database
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    db = init_database()

    print("Adding test device...")
    device = db.add_or_update_device(
        mac="00:11:22:33:44:55",
        ip="192.168.1.100",
        hostname="test-device",
        vendor="Test Vendor",
        open_ports=[80, 443],
    )
    print(f"Device: {device}")

    print("\nRecording test scan...")
    scan = db.add_scan(
        interface="eth0",
        device_count=1,
        scan_type="test",
    )
    print(f"Scan: {scan}")

    print("\nCreating test alert...")
    alert = db.add_alert(
        severity="warning",
        title="Test Alert",
        message="This is a test alert",
        category="test",
    )
    print(f"Alert: {alert}")

    print("\nGetting all devices...")
    devices = db.get_all_devices()
    for d in devices:
        print(f"  {d}")
