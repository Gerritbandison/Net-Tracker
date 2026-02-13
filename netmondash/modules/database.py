"""
Database Module

SQLAlchemy models and database operations for NetMonDash.
Provides persistent storage for devices, scans, alerts, network events,
bandwidth samples, and device categorization.
"""

import logging
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Tuple
import json
from collections import Counter

from sqlalchemy import (
    create_engine, Column, Integer, String, DateTime, Boolean,
    Text, Float, Index, func, or_,
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import StaticPool

from config import DATABASE_URL, DB_ECHO, DEVICE_HISTORY_RETENTION_DAYS

logger = logging.getLogger(__name__)

Base = declarative_base()


# ─── Models ───────────────────────────────────────────────────────────────────

class Device(Base):
    """Network device model."""

    __tablename__ = "devices"

    mac = Column(String(17), primary_key=True)
    ip = Column(String(45), nullable=False)
    hostname = Column(String(255), nullable=True)
    vendor = Column(String(255), nullable=True)
    first_seen = Column(DateTime, nullable=False, default=datetime.now)
    last_seen = Column(DateTime, nullable=False, default=datetime.now, onupdate=datetime.now)
    is_online = Column(Boolean, default=True)
    open_ports = Column(Text, nullable=True)  # JSON array
    services = Column(Text, nullable=True)    # JSON object of port:service
    notes = Column(Text, nullable=True)
    category = Column(String(50), nullable=True, default="unknown")
    is_trusted = Column(Boolean, default=False)
    is_blocked = Column(Boolean, default=False)
    custom_name = Column(String(255), nullable=True)
    last_port_change = Column(DateTime, nullable=True)
    avg_latency_ms = Column(Float, nullable=True)
    os_guess = Column(String(255), nullable=True)
    scan_count = Column(Integer, default=0)

    __table_args__ = (
        Index('idx_device_online', 'is_online'),
        Index('idx_device_category', 'category'),
        Index('idx_device_last_seen', 'last_seen'),
    )

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
            "category": self.category,
            "is_trusted": self.is_trusted,
            "is_blocked": self.is_blocked,
            "custom_name": self.custom_name,
            "display_name": self.custom_name or self.hostname or self.ip,
            "last_port_change": self.last_port_change.isoformat() if self.last_port_change else None,
            "avg_latency_ms": self.avg_latency_ms,
            "os_guess": self.os_guess,
            "scan_count": self.scan_count,
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
    new_device_count = Column(Integer, nullable=False, default=0)
    offline_device_count = Column(Integer, nullable=False, default=0)
    scan_type = Column(String(50), nullable=True)
    duration_seconds = Column(Float, nullable=True)
    raw_json = Column(Text, nullable=True)
    network_range = Column(String(50), nullable=True)
    error_message = Column(Text, nullable=True)

    __table_args__ = (
        Index('idx_scan_timestamp', 'timestamp'),
        Index('idx_scan_type', 'scan_type'),
    )

    def to_dict(self) -> Dict:
        """Convert to dictionary representation."""
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "interface": self.interface,
            "device_count": self.device_count,
            "new_device_count": self.new_device_count,
            "offline_device_count": self.offline_device_count,
            "scan_type": self.scan_type,
            "duration_seconds": self.duration_seconds,
            "raw_data": json.loads(self.raw_json) if self.raw_json else None,
            "network_range": self.network_range,
            "error_message": self.error_message,
        }

    def __repr__(self) -> str:
        return f"<Scan {self.id} at {self.timestamp} - {self.device_count} devices>"


class Alert(Base):
    """Security and network alert model."""

    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, nullable=False, default=datetime.now)
    severity = Column(String(20), nullable=False)
    category = Column(String(50), nullable=True)
    title = Column(String(255), nullable=False)
    message = Column(Text, nullable=False)
    source_ip = Column(String(45), nullable=True)
    source_mac = Column(String(17), nullable=True)
    command = Column(Text, nullable=True)
    acknowledged = Column(Boolean, default=False)
    acknowledged_at = Column(DateTime, nullable=True)
    auto_generated = Column(Boolean, default=False)
    related_scan_id = Column(Integer, nullable=True)

    __table_args__ = (
        Index('idx_alert_severity', 'severity'),
        Index('idx_alert_acknowledged', 'acknowledged'),
        Index('idx_alert_timestamp', 'timestamp'),
    )

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
            "auto_generated": self.auto_generated,
        }

    def __repr__(self) -> str:
        return f"<Alert {self.id} [{self.severity}] {self.title}>"


class NetworkEvent(Base):
    """Track significant network events for timeline display."""

    __tablename__ = "network_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, nullable=False, default=datetime.now)
    event_type = Column(String(50), nullable=False)
    device_mac = Column(String(17), nullable=True)
    device_ip = Column(String(45), nullable=True)
    description = Column(Text, nullable=False)
    details_json = Column(Text, nullable=True)

    __table_args__ = (
        Index('idx_event_timestamp', 'timestamp'),
        Index('idx_event_type', 'event_type'),
        Index('idx_event_device', 'device_mac'),
    )

    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "event_type": self.event_type,
            "device_mac": self.device_mac,
            "device_ip": self.device_ip,
            "description": self.description,
            "details": json.loads(self.details_json) if self.details_json else None,
        }


class BandwidthSample(Base):
    """Track network bandwidth/latency measurements over time."""

    __tablename__ = "bandwidth_samples"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, nullable=False, default=datetime.now)
    device_mac = Column(String(17), nullable=True)
    latency_ms = Column(Float, nullable=True)
    packet_loss_pct = Column(Float, nullable=True)
    interface = Column(String(50), nullable=True)

    __table_args__ = (
        Index('idx_bw_timestamp', 'timestamp'),
        Index('idx_bw_device', 'device_mac'),
    )

    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "device_mac": self.device_mac,
            "latency_ms": self.latency_ms,
            "packet_loss_pct": self.packet_loss_pct,
            "interface": self.interface,
        }


# ─── Device Categories ────────────────────────────────────────────────────────

DEVICE_CATEGORIES = {
    "router": {"label": "Router/Gateway", "icon": "router"},
    "computer": {"label": "Computer", "icon": "computer"},
    "phone": {"label": "Phone/Tablet", "icon": "phone"},
    "iot": {"label": "IoT Device", "icon": "iot"},
    "printer": {"label": "Printer", "icon": "printer"},
    "camera": {"label": "Camera", "icon": "camera"},
    "server": {"label": "Server", "icon": "server"},
    "storage": {"label": "NAS/Storage", "icon": "storage"},
    "media": {"label": "Media Device", "icon": "media"},
    "gaming": {"label": "Gaming", "icon": "gaming"},
    "network": {"label": "Network Equipment", "icon": "network"},
    "unknown": {"label": "Unknown", "icon": "unknown"},
}


def guess_device_category(vendor: Optional[str], hostname: Optional[str],
                          open_ports: Optional[List[int]] = None) -> str:
    """Guess device category from vendor, hostname and open ports."""
    vendor_lower = (vendor or "").lower()
    hostname_lower = (hostname or "").lower()
    ports = set(open_ports or [])

    # Router detection
    if any(kw in vendor_lower for kw in ["netgear", "tp-link", "linksys", "asus", "cisco", "ubiquiti", "mikrotik"]):
        if ports & {80, 443, 53}:
            return "router"
        return "network"

    # Phone/Tablet detection
    if any(kw in vendor_lower for kw in ["apple", "samsung", "huawei", "xiaomi", "oneplus", "google"]):
        if not ports or ports <= {62078, 5353}:
            return "phone"

    # Printer detection
    if any(kw in vendor_lower for kw in ["hp", "canon", "epson", "brother", "lexmark"]):
        return "printer"
    if ports & {631, 9100, 515}:
        return "printer"

    # Camera detection
    if any(kw in vendor_lower for kw in ["hikvision", "dahua", "axis", "ring", "nest"]):
        return "camera"
    if 554 in ports:
        return "camera"

    # Server detection
    if ports & {22, 80, 443, 3306, 5432, 8080, 8443}:
        if len(ports) >= 3:
            return "server"

    # Media device detection
    if any(kw in vendor_lower for kw in ["sonos", "roku", "amazon", "chromecast"]):
        return "media"

    # Gaming detection
    if any(kw in vendor_lower for kw in ["sony", "microsoft", "nintendo", "valve"]):
        return "gaming"

    # IoT detection
    if any(kw in vendor_lower for kw in ["espressif", "tuya", "shelly", "philips hue"]):
        return "iot"

    # NAS/Storage
    if any(kw in vendor_lower for kw in ["synology", "qnap", "western digital", "seagate"]):
        return "storage"
    if ports & {139, 445, 548, 2049}:
        return "storage"

    # Computer fallback
    if any(kw in hostname_lower for kw in ["desktop", "laptop", "pc", "macbook", "imac"]):
        return "computer"
    if ports & {3389, 5900, 22}:
        return "computer"

    return "unknown"


# ─── Database Manager ─────────────────────────────────────────────────────────

class DatabaseManager:
    """Database manager for NetMonDash."""

    def __init__(self, database_url: str = DATABASE_URL, echo: bool = DB_ECHO):
        self.database_url = database_url
        self.engine = create_engine(
            database_url,
            echo=echo,
            connect_args={"check_same_thread": False} if "sqlite" in database_url else {},
            poolclass=StaticPool if "sqlite" in database_url else None,
        )
        self.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
        Base.metadata.create_all(bind=self.engine)
        logger.info("Database initialized successfully")

    def get_session(self) -> Session:
        """Get a new database session."""
        return self.SessionLocal()

    # ── Device Operations ──────────────────────────────────────────────────

    def add_or_update_device(
        self,
        mac: str,
        ip: str,
        hostname: Optional[str] = None,
        vendor: Optional[str] = None,
        open_ports: Optional[List[int]] = None,
        services: Optional[Dict[int, str]] = None,
        latency_ms: Optional[float] = None,
        os_guess: Optional[str] = None,
    ) -> Device:
        """Add a new device or update existing device."""
        session = self.get_session()
        try:
            device = session.query(Device).filter(Device.mac == mac).first()

            if device:
                device.ip = ip
                device.last_seen = datetime.now()
                device.is_online = True
                device.scan_count = (device.scan_count or 0) + 1

                if hostname:
                    device.hostname = hostname
                if vendor:
                    device.vendor = vendor
                if latency_ms is not None:
                    device.avg_latency_ms = latency_ms
                if os_guess:
                    device.os_guess = os_guess

                # Detect port changes
                old_ports = set(json.loads(device.open_ports)) if device.open_ports else set()
                new_ports = set(open_ports) if open_ports else set()
                if old_ports != new_ports and (old_ports or new_ports):
                    device.last_port_change = datetime.now()
                    added = new_ports - old_ports
                    removed = old_ports - new_ports
                    if added or removed:
                        self._record_event(
                            session,
                            event_type="port_change",
                            device_mac=mac,
                            device_ip=ip,
                            description=f"Port change on {ip}: +{list(added)} -{list(removed)}",
                            details={"added": list(added), "removed": list(removed)},
                        )

                if open_ports is not None:
                    device.open_ports = json.dumps(open_ports)
                if services is not None:
                    device.services = json.dumps(services)

                # Auto-categorize if still unknown
                if device.category == "unknown" or device.category is None:
                    device.category = guess_device_category(
                        device.vendor, device.hostname, open_ports
                    )

                logger.debug(f"Updated device: {mac}")
            else:
                category = guess_device_category(vendor, hostname, open_ports)
                device = Device(
                    mac=mac,
                    ip=ip,
                    hostname=hostname,
                    vendor=vendor,
                    open_ports=json.dumps(open_ports) if open_ports else None,
                    services=json.dumps(services) if services else None,
                    category=category,
                    avg_latency_ms=latency_ms,
                    os_guess=os_guess,
                    scan_count=1,
                )
                session.add(device)
                logger.info(f"Added new device: {mac} ({ip}) category={category}")

                self._record_event(
                    session,
                    event_type="device_joined",
                    device_mac=mac,
                    device_ip=ip,
                    description=f"New device joined: {hostname or ip} ({vendor or 'unknown vendor'})",
                    details={"hostname": hostname, "vendor": vendor, "ports": open_ports},
                )

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

    def get_all_devices(self, online_only: bool = False, category: Optional[str] = None) -> List[Device]:
        """Get all devices with optional filtering."""
        session = self.get_session()
        try:
            query = session.query(Device)
            if online_only:
                query = query.filter(Device.is_online == True)
            if category:
                query = query.filter(Device.category == category)
            return query.order_by(Device.last_seen.desc()).all()
        finally:
            session.close()

    def search_devices(self, query_str: str) -> List[Device]:
        """Search devices by IP, MAC, hostname, or vendor."""
        session = self.get_session()
        try:
            search = f"%{query_str}%"
            return session.query(Device).filter(
                or_(
                    Device.ip.like(search),
                    Device.mac.like(search),
                    Device.hostname.like(search),
                    Device.vendor.like(search),
                    Device.custom_name.like(search),
                    Device.notes.like(search),
                )
            ).order_by(Device.last_seen.desc()).all()
        finally:
            session.close()

    def mark_devices_offline(self, current_macs: List[str]) -> Tuple[int, List[Dict]]:
        """Mark devices as offline and return info about which went offline."""
        session = self.get_session()
        try:
            newly_offline = session.query(Device).filter(
                Device.mac.notin_(current_macs),
                Device.is_online == True
            ).all()

            offline_info = []
            for device in newly_offline:
                device.is_online = False
                offline_info.append(device.to_dict())
                self._record_event(
                    session,
                    event_type="device_left",
                    device_mac=device.mac,
                    device_ip=device.ip,
                    description=f"Device went offline: {device.custom_name or device.hostname or device.ip}",
                )

            session.commit()
            count = len(offline_info)
            logger.info(f"Marked {count} devices as offline")
            return count, offline_info

        except Exception as e:
            session.rollback()
            logger.error(f"Error marking devices offline: {e}")
            return 0, []
        finally:
            session.close()

    def update_device_field(self, mac: str, **kwargs) -> bool:
        """Update specific fields on a device."""
        session = self.get_session()
        try:
            device = session.query(Device).filter(Device.mac == mac).first()
            if not device:
                return False
            for key, value in kwargs.items():
                if hasattr(device, key):
                    setattr(device, key, value)
            session.commit()
            return True
        except Exception as e:
            session.rollback()
            logger.error(f"Error updating device {mac}: {e}")
            return False
        finally:
            session.close()

    def delete_device(self, mac: str) -> bool:
        """Delete a device by MAC address."""
        session = self.get_session()
        try:
            device = session.query(Device).filter(Device.mac == mac).first()
            if not device:
                return False
            session.delete(device)
            session.commit()
            logger.info(f"Deleted device: {mac}")
            return True
        except Exception as e:
            session.rollback()
            logger.error(f"Error deleting device {mac}: {e}")
            return False
        finally:
            session.close()

    def get_device_count_by_category(self) -> Dict[str, int]:
        """Get count of devices per category."""
        session = self.get_session()
        try:
            results = session.query(
                Device.category, func.count(Device.mac)
            ).group_by(Device.category).all()
            return {cat or "unknown": count for cat, count in results}
        finally:
            session.close()

    def get_device_count_by_vendor(self, limit: int = 10) -> List[Tuple[str, int]]:
        """Get top vendors by device count."""
        session = self.get_session()
        try:
            return session.query(
                Device.vendor, func.count(Device.mac)
            ).filter(
                Device.vendor.isnot(None)
            ).group_by(Device.vendor).order_by(
                func.count(Device.mac).desc()
            ).limit(limit).all()
        finally:
            session.close()

    # ── Scan Operations ────────────────────────────────────────────────────

    def add_scan(
        self,
        interface: Optional[str],
        device_count: int,
        scan_type: str = "network",
        duration_seconds: Optional[float] = None,
        raw_data: Optional[Dict] = None,
        new_device_count: int = 0,
        offline_device_count: int = 0,
        network_range: Optional[str] = None,
        error_message: Optional[str] = None,
    ) -> Scan:
        """Record a network scan."""
        session = self.get_session()
        try:
            scan = Scan(
                interface=interface,
                device_count=device_count,
                new_device_count=new_device_count,
                offline_device_count=offline_device_count,
                scan_type=scan_type,
                duration_seconds=duration_seconds,
                raw_json=json.dumps(raw_data) if raw_data else None,
                network_range=network_range,
                error_message=error_message,
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
        """Get recent scans."""
        session = self.get_session()
        try:
            return session.query(Scan).order_by(Scan.timestamp.desc()).limit(limit).all()
        finally:
            session.close()

    def get_scan_history(self, hours: int = 24) -> List[Scan]:
        """Get scan history for specified time period."""
        session = self.get_session()
        try:
            cutoff = datetime.now() - timedelta(hours=hours)
            return session.query(Scan).filter(
                Scan.timestamp >= cutoff
            ).order_by(Scan.timestamp.asc()).all()
        finally:
            session.close()

    def get_scan_stats(self, hours: int = 24) -> Dict:
        """Get aggregated scan statistics."""
        session = self.get_session()
        try:
            cutoff = datetime.now() - timedelta(hours=hours)
            scans = session.query(Scan).filter(Scan.timestamp >= cutoff).all()
            if not scans:
                return {
                    "total_scans": 0, "avg_duration": 0, "avg_devices": 0,
                    "max_devices": 0, "total_new_devices": 0, "error_count": 0,
                }
            return {
                "total_scans": len(scans),
                "avg_duration": sum(s.duration_seconds or 0 for s in scans) / len(scans),
                "avg_devices": sum(s.device_count for s in scans) / len(scans),
                "max_devices": max(s.device_count for s in scans),
                "total_new_devices": sum(s.new_device_count or 0 for s in scans),
                "error_count": sum(1 for s in scans if s.error_message),
            }
        finally:
            session.close()

    # ── Alert Operations ───────────────────────────────────────────────────

    def add_alert(
        self,
        severity: str,
        title: str,
        message: str,
        category: Optional[str] = None,
        source_ip: Optional[str] = None,
        source_mac: Optional[str] = None,
        command: Optional[str] = None,
        auto_generated: bool = False,
        related_scan_id: Optional[int] = None,
    ) -> Alert:
        """Create a new alert."""
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
                auto_generated=auto_generated,
                related_scan_id=related_scan_id,
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

    def get_alerts_by_severity(self, severity: str, limit: int = 50) -> List[Alert]:
        """Get alerts filtered by severity."""
        session = self.get_session()
        try:
            return session.query(Alert).filter(
                Alert.severity == severity
            ).order_by(Alert.timestamp.desc()).limit(limit).all()
        finally:
            session.close()

    def acknowledge_alert(self, alert_id: int) -> bool:
        """Acknowledge an alert."""
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

    def acknowledge_all_alerts(self) -> int:
        """Acknowledge all unacknowledged alerts. Returns count acknowledged."""
        session = self.get_session()
        try:
            now = datetime.now()
            count = session.query(Alert).filter(
                Alert.acknowledged == False
            ).update({
                "acknowledged": True,
                "acknowledged_at": now,
            }, synchronize_session=False)
            session.commit()
            logger.info(f"Acknowledged {count} alerts")
            return count
        except Exception as e:
            session.rollback()
            logger.error(f"Error acknowledging all alerts: {e}")
            return 0
        finally:
            session.close()

    def get_alert_summary(self) -> Dict:
        """Get alert count summary by severity."""
        session = self.get_session()
        try:
            results = session.query(
                Alert.severity, func.count(Alert.id)
            ).filter(
                Alert.acknowledged == False
            ).group_by(Alert.severity).all()
            summary = {"critical": 0, "warning": 0, "info": 0}
            for severity, count in results:
                summary[severity] = count
            summary["total"] = sum(summary.values())
            return summary
        finally:
            session.close()

    # ── Network Event Operations ───────────────────────────────────────────

    def _record_event(
        self,
        session: Session,
        event_type: str,
        description: str,
        device_mac: Optional[str] = None,
        device_ip: Optional[str] = None,
        details: Optional[Dict] = None,
    ):
        """Record a network event (called within existing session)."""
        event = NetworkEvent(
            event_type=event_type,
            device_mac=device_mac,
            device_ip=device_ip,
            description=description,
            details_json=json.dumps(details) if details else None,
        )
        session.add(event)

    def add_event(
        self,
        event_type: str,
        description: str,
        device_mac: Optional[str] = None,
        device_ip: Optional[str] = None,
        details: Optional[Dict] = None,
    ) -> NetworkEvent:
        """Add a network event."""
        session = self.get_session()
        try:
            event = NetworkEvent(
                event_type=event_type,
                device_mac=device_mac,
                device_ip=device_ip,
                description=description,
                details_json=json.dumps(details) if details else None,
            )
            session.add(event)
            session.commit()
            session.refresh(event)
            return event
        except Exception as e:
            session.rollback()
            logger.error(f"Error adding event: {e}")
            raise
        finally:
            session.close()

    def get_recent_events(self, limit: int = 50, event_type: Optional[str] = None) -> List[NetworkEvent]:
        """Get recent network events."""
        session = self.get_session()
        try:
            query = session.query(NetworkEvent)
            if event_type:
                query = query.filter(NetworkEvent.event_type == event_type)
            return query.order_by(NetworkEvent.timestamp.desc()).limit(limit).all()
        finally:
            session.close()

    def get_device_events(self, device_mac: str, limit: int = 20) -> List[NetworkEvent]:
        """Get events for a specific device."""
        session = self.get_session()
        try:
            return session.query(NetworkEvent).filter(
                NetworkEvent.device_mac == device_mac
            ).order_by(NetworkEvent.timestamp.desc()).limit(limit).all()
        finally:
            session.close()

    # ── Bandwidth/Latency Operations ───────────────────────────────────────

    def add_bandwidth_sample(
        self,
        latency_ms: Optional[float] = None,
        packet_loss_pct: Optional[float] = None,
        device_mac: Optional[str] = None,
        interface: Optional[str] = None,
    ) -> BandwidthSample:
        """Record a bandwidth/latency sample."""
        session = self.get_session()
        try:
            sample = BandwidthSample(
                device_mac=device_mac,
                latency_ms=latency_ms,
                packet_loss_pct=packet_loss_pct,
                interface=interface,
            )
            session.add(sample)
            session.commit()
            session.refresh(sample)
            return sample
        except Exception as e:
            session.rollback()
            logger.error(f"Error adding bandwidth sample: {e}")
            raise
        finally:
            session.close()

    def get_latency_history(self, hours: int = 24, device_mac: Optional[str] = None) -> List[BandwidthSample]:
        """Get latency history."""
        session = self.get_session()
        try:
            cutoff = datetime.now() - timedelta(hours=hours)
            query = session.query(BandwidthSample).filter(BandwidthSample.timestamp >= cutoff)
            if device_mac:
                query = query.filter(BandwidthSample.device_mac == device_mac)
            return query.order_by(BandwidthSample.timestamp.asc()).all()
        finally:
            session.close()

    # ── Analytics ──────────────────────────────────────────────────────────

    def get_dashboard_stats(self) -> Dict:
        """Get comprehensive dashboard statistics."""
        session = self.get_session()
        try:
            devices = session.query(Device).all()
            online = [d for d in devices if d.is_online]

            unack_alerts = session.query(Alert).filter(Alert.acknowledged == False).all()
            critical_alerts = [a for a in unack_alerts if a.severity == "critical"]

            recent_scans = session.query(Scan).filter(
                Scan.timestamp >= datetime.now() - timedelta(hours=24)
            ).all()

            categories = {}
            for d in devices:
                cat = d.category or "unknown"
                categories[cat] = categories.get(cat, 0) + 1

            vendor_counts = Counter(d.vendor for d in devices if d.vendor)
            top_vendors = vendor_counts.most_common(5)

            trusted = sum(1 for d in devices if d.is_trusted)

            return {
                "total_devices": len(devices),
                "online_devices": len(online),
                "offline_devices": len(devices) - len(online),
                "trusted_devices": trusted,
                "unacknowledged_alerts": len(unack_alerts),
                "critical_alerts": len(critical_alerts),
                "warning_alerts": sum(1 for a in unack_alerts if a.severity == "warning"),
                "scans_24h": len(recent_scans),
                "last_scan": recent_scans[-1].timestamp.isoformat() if recent_scans else None,
                "avg_scan_duration": (
                    sum(s.duration_seconds or 0 for s in recent_scans) / len(recent_scans)
                    if recent_scans else 0
                ),
                "categories": categories,
                "top_vendors": [{"vendor": v, "count": c} for v, c in top_vendors],
                "new_devices_24h": sum(s.new_device_count or 0 for s in recent_scans),
            }
        finally:
            session.close()

    def get_network_timeline(self, hours: int = 24, limit: int = 100) -> List[Dict]:
        """Get a timeline of network events for display."""
        session = self.get_session()
        try:
            cutoff = datetime.now() - timedelta(hours=hours)
            events = session.query(NetworkEvent).filter(
                NetworkEvent.timestamp >= cutoff
            ).order_by(NetworkEvent.timestamp.desc()).limit(limit).all()
            return [e.to_dict() for e in events]
        finally:
            session.close()

    # ── Maintenance ────────────────────────────────────────────────────────

    def cleanup_old_data(self, days: int = DEVICE_HISTORY_RETENTION_DAYS) -> Dict[str, int]:
        """Clean up old data."""
        session = self.get_session()
        try:
            cutoff = datetime.now() - timedelta(days=days)

            scans_deleted = session.query(Scan).filter(Scan.timestamp < cutoff).delete()
            alerts_deleted = session.query(Alert).filter(
                Alert.timestamp < cutoff,
                Alert.acknowledged == True
            ).delete()
            events_deleted = session.query(NetworkEvent).filter(
                NetworkEvent.timestamp < cutoff
            ).delete()
            bw_deleted = session.query(BandwidthSample).filter(
                BandwidthSample.timestamp < cutoff
            ).delete()

            session.commit()

            stats = {
                "scans_deleted": scans_deleted,
                "alerts_deleted": alerts_deleted,
                "events_deleted": events_deleted,
                "bandwidth_samples_deleted": bw_deleted,
            }
            logger.info(f"Cleanup complete: {stats}")
            return stats
        except Exception as e:
            session.rollback()
            logger.error(f"Error during cleanup: {e}")
            return {"scans_deleted": 0, "alerts_deleted": 0, "events_deleted": 0, "bandwidth_samples_deleted": 0}
        finally:
            session.close()

    def get_database_info(self) -> Dict:
        """Get database size and record counts."""
        session = self.get_session()
        try:
            return {
                "devices": session.query(func.count(Device.mac)).scalar(),
                "scans": session.query(func.count(Scan.id)).scalar(),
                "alerts": session.query(func.count(Alert.id)).scalar(),
                "events": session.query(func.count(NetworkEvent.id)).scalar(),
                "bandwidth_samples": session.query(func.count(BandwidthSample.id)).scalar(),
            }
        finally:
            session.close()


def init_database(database_url: str = DATABASE_URL) -> DatabaseManager:
    """Initialize database and return manager."""
    return DatabaseManager(database_url)
