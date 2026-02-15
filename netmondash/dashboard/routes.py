"""
API Routes

FastAPI routes for NetMonDash dashboard.
Provides HTML page routes and REST API endpoints for device management,
scanning, alerts, events, analytics, trends, device risk scoring,
channel analysis, scan profiles, and system administration.
"""

import asyncio
import logging
import csv
import json
import io
from datetime import datetime
from typing import Optional, List

from fastapi import APIRouter, Request, HTTPException, Query, Response
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse

from modules.database import DEVICE_CATEGORIES

logger = logging.getLogger(__name__)

router = APIRouter()


# ─── Helper Functions ─────────────────────────────────────────────────────────

def _get_db(request: Request):
    """Get the database manager or raise 503."""
    db = request.app.state.db_manager
    if not db:
        raise HTTPException(status_code=503, detail="Database not available")
    return db


def _get_scanner(request: Request):
    """Get the scanner or raise 503."""
    scanner = request.app.state.scanner
    if not scanner:
        raise HTTPException(status_code=503, detail="Scanner not available")
    return scanner


def _get_ai(request: Request):
    """Get the AI analyzer or raise 503."""
    ai = request.app.state.ai_analyzer
    if not ai:
        raise HTTPException(status_code=503, detail="AI analyzer not available")
    return ai


# ─── HTML Page Routes ─────────────────────────────────────────────────────────

@router.get("/devices", response_class=HTMLResponse)
async def devices_page(request: Request):
    """Devices page."""
    templates = request.app.state.templates
    return templates.TemplateResponse(
        request,
        "devices.html",
        {
            "page": "devices",
            "title": "NetMonDash - Devices",
        }
    )


@router.get("/wifi", response_class=HTMLResponse)
async def wifi_page(request: Request):
    """WiFi analysis page."""
    templates = request.app.state.templates
    return templates.TemplateResponse(
        request,
        "wifi.html",
        {
            "page": "wifi",
            "title": "NetMonDash - WiFi Analysis",
        }
    )


@router.get("/insights", response_class=HTMLResponse)
async def insights_page(request: Request):
    """AI insights page."""
    templates = request.app.state.templates
    return templates.TemplateResponse(
        request,
        "insights.html",
        {
            "page": "insights",
            "title": "NetMonDash - AI Insights",
        }
    )


@router.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request):
    """Settings page."""
    templates = request.app.state.templates
    return templates.TemplateResponse(
        request,
        "settings.html",
        {
            "page": "settings",
            "title": "NetMonDash - Settings",
        }
    )


# ─── Device API Endpoints ─────────────────────────────────────────────────────

@router.get("/api/devices")
async def get_devices(
    request: Request,
    online_only: bool = Query(False, description="Only return online devices"),
    category: Optional[str] = Query(None, description="Filter by device category"),
    page: int = Query(0, ge=0, description="Page number (0 = no pagination)"),
    per_page: int = Query(50, ge=1, le=200, description="Items per page"),
    sort_by: str = Query("last_seen", description="Sort field"),
    sort_order: str = Query("desc", pattern="^(asc|desc)$", description="Sort order"),
    search: Optional[str] = Query(None, description="Search query"),
):
    """Get all network devices with optional filtering, sorting, and pagination."""
    db = _get_db(request)

    try:
        if page > 0:
            result = db.get_devices_paginated(
                page=page,
                per_page=per_page,
                online_only=online_only,
                category=category,
                sort_by=sort_by,
                sort_order=sort_order,
                search=search,
            )
            return result.to_dict()
        else:
            devices = db.get_all_devices(online_only=online_only, category=category)
            return {
                "count": len(devices),
                "devices": [device.to_dict() for device in devices],
            }
    except Exception as e:
        logger.error(f"Error getting devices: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/devices/search")
async def search_devices(
    request: Request,
    q: str = Query(..., min_length=1, description="Search query string"),
):
    """Search devices by IP, MAC, hostname, vendor, custom name, or notes."""
    db = _get_db(request)

    try:
        devices = db.search_devices(q)
        return {
            "query": q,
            "count": len(devices),
            "devices": [device.to_dict() for device in devices],
        }
    except Exception as e:
        logger.error(f"Error searching devices: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/devices/{mac}")
async def get_device(request: Request, mac: str):
    """Get specific device by MAC address."""
    db = _get_db(request)

    try:
        device = db.get_device(mac)
        if not device:
            raise HTTPException(status_code=404, detail="Device not found")

        return device.to_dict()
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting device {mac}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/devices/{mac}/changelog")
async def get_device_changelog(
    request: Request,
    mac: str,
    limit: int = Query(50, ge=1, le=200, description="Maximum changes to return"),
):
    """Get change history for a specific device."""
    db = _get_db(request)

    try:
        device = db.get_device(mac)
        if not device:
            raise HTTPException(status_code=404, detail="Device not found")

        changes = db.get_device_changelog(mac, limit=limit)
        return {
            "device_mac": mac,
            "count": len(changes),
            "changes": [c.to_dict() for c in changes],
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting device changelog: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/devices/{mac}/uptime")
async def get_device_uptime(
    request: Request,
    mac: str,
    days: int = Query(7, ge=1, le=90, description="Days to look back"),
):
    """Get uptime statistics for a specific device."""
    db = _get_db(request)

    try:
        device = db.get_device(mac)
        if not device:
            raise HTTPException(status_code=404, detail="Device not found")

        uptime = db.get_device_uptime(mac, days=days)
        return uptime
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting device uptime: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/devices/{mac}/risk")
async def get_device_risk(request: Request, mac: str):
    """Get risk score for a specific device."""
    db = _get_db(request)
    ai = _get_ai(request)
    scanner = request.app.state.scanner

    try:
        device = db.get_device(mac)
        if not device:
            raise HTTPException(status_code=404, detail="Device not found")

        device_data = device.to_dict()
        gateway_ip = scanner.get_gateway_ip() if scanner else None
        is_gw = (gateway_ip and device_data.get("ip") == gateway_ip)

        risk = ai.calculate_device_risk_score(device_data, is_gateway=is_gw)

        # Persist the risk score
        db.update_device_risk_score(mac, risk["score"])

        return risk
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error calculating device risk: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.put("/api/devices/{mac}")
async def update_device(request: Request, mac: str):
    """Update device fields (category, custom_name, is_trusted, is_blocked, notes)."""
    db = _get_db(request)

    try:
        body = await request.json()

        # Validate that the device exists
        device = db.get_device(mac)
        if not device:
            raise HTTPException(status_code=404, detail="Device not found")

        # Only allow updating specific fields
        allowed_fields = {"category", "custom_name", "is_trusted", "is_blocked", "notes"}
        update_kwargs = {}

        for field in allowed_fields:
            if field in body:
                update_kwargs[field] = body[field]

        if not update_kwargs:
            raise HTTPException(
                status_code=400,
                detail=f"No valid fields to update. Allowed fields: {', '.join(sorted(allowed_fields))}",
            )

        # Validate category if provided
        if "category" in update_kwargs:
            if update_kwargs["category"] not in DEVICE_CATEGORIES:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid category '{update_kwargs['category']}'. "
                           f"Valid categories: {', '.join(sorted(DEVICE_CATEGORIES.keys()))}",
                )

        success = db.update_device_field(mac, **update_kwargs)

        if not success:
            raise HTTPException(status_code=500, detail="Failed to update device")

        # Return the updated device
        updated_device = db.get_device(mac)
        return {
            "success": True,
            "mac": mac,
            "updated_fields": list(update_kwargs.keys()),
            "device": updated_device.to_dict() if updated_device else None,
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating device {mac}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/api/devices/{mac}")
async def delete_device(request: Request, mac: str):
    """Delete a device by MAC address."""
    db = _get_db(request)

    try:
        # Verify the device exists first
        device = db.get_device(mac)
        if not device:
            raise HTTPException(status_code=404, detail="Device not found")

        success = db.delete_device(mac)

        if not success:
            raise HTTPException(status_code=500, detail="Failed to delete device")

        return {
            "success": True,
            "mac": mac,
            "message": f"Device {mac} deleted",
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting device {mac}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/api/devices/{mac}/notes")
async def update_device_notes(request: Request, mac: str):
    """Update device notes."""
    db = _get_db(request)

    try:
        body = await request.json()
        notes = body.get("notes", "")

        # Verify the device exists
        device = db.get_device(mac)
        if not device:
            raise HTTPException(status_code=404, detail="Device not found")

        # Use update_device_field to properly query and update in the same session
        success = db.update_device_field(mac, notes=notes)

        if not success:
            raise HTTPException(status_code=500, detail="Failed to update notes")

        return {"success": True, "mac": mac, "notes": notes}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating device notes: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/api/devices/{mac}/scan")
async def trigger_device_scan(request: Request, mac: str):
    """Trigger a deep nmap scan for a single device.

    Returns the updated device info after the scan completes.
    """
    db = _get_db(request)
    scanner = _get_scanner(request)

    device = db.get_device(mac)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    ip = device.get("ip") if isinstance(device, dict) else device.ip

    try:
        loop = asyncio.get_running_loop()
        device_info = await loop.run_in_executor(
            None,
            lambda: scanner.deep_scan_device(ip),
        )

        if device_info is None:
            return {
                "success": False,
                "message": f"Host {ip} is unreachable",
                "mac": mac,
            }

        # Update database with full scan results
        db.add_or_update_device(
            mac=device_info.mac or mac,
            ip=device_info.ip,
            hostname=device_info.hostname,
            vendor=device_info.vendor,
            open_ports=device_info.open_ports,
            services=device_info.services,
            latency_ms=device_info.latency_ms,
            os_guess=device_info.os_guess,
            jitter_ms=device_info.jitter_ms,
            packet_loss=device_info.packet_loss,
            ttl=device_info.ttl,
        )

        return {
            "success": True,
            "message": f"Deep scan complete for {ip}",
            "mac": mac,
            "device": device_info.to_dict(),
        }

    except Exception as e:
        logger.error(f"Error scanning device {mac}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ─── Scan API Endpoints ───────────────────────────────────────────────────────

@router.get("/api/scans/recent")
async def get_recent_scans(
    request: Request,
    limit: int = Query(10, ge=1, le=100, description="Number of scans to return"),
):
    """Get recent scans."""
    db = _get_db(request)

    try:
        scans = db.get_recent_scans(limit=limit)
        return {
            "count": len(scans),
            "scans": [scan.to_dict() for scan in scans],
        }
    except Exception as e:
        logger.error(f"Error getting recent scans: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/scans/history")
async def get_scan_history(
    request: Request,
    hours: int = Query(24, ge=1, le=168, description="Hours to look back"),
):
    """Get scan history."""
    db = _get_db(request)

    try:
        scans = db.get_scan_history(hours=hours)
        return {
            "count": len(scans),
            "scans": [scan.to_dict() for scan in scans],
        }
    except Exception as e:
        logger.error(f"Error getting scan history: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/scans/stats")
async def get_scan_stats(
    request: Request,
    hours: int = Query(24, ge=1, le=168, description="Hours to look back"),
):
    """Get aggregated scan statistics."""
    db = _get_db(request)

    try:
        stats = db.get_scan_stats(hours=hours)
        return stats
    except Exception as e:
        logger.error(f"Error getting scan stats: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/scan/profiles")
async def get_scan_profiles(request: Request):
    """Get available scan profiles."""
    scanner = _get_scanner(request)

    try:
        return {
            "profiles": scanner.get_available_profiles(),
        }
    except Exception as e:
        logger.error(f"Error getting scan profiles: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/api/scan/trigger")
async def trigger_scan(request: Request):
    """Trigger a manual network scan by setting the scan event flag."""
    scanner = _get_scanner(request)

    try:
        # Try the scan_now_event first (main.py lifespan sets this)
        scan_event = getattr(request.app.state, "scan_now_event", None)
        if scan_event is None:
            scan_event = getattr(request.app.state, "scan_event", None)

        if scan_event and isinstance(scan_event, asyncio.Event):
            scan_event.set()

            # Also trigger discovery engine active scan if available
            discovery = getattr(request.app.state, "discovery", None)
            if discovery:
                discovery.trigger_active_scan()

            return {
                "success": True,
                "message": "Scan triggered successfully",
                "timestamp": datetime.now().isoformat(),
            }

        summary = scanner.get_scan_summary()
        return {
            "success": True,
            "message": "Scan triggered",
            "timestamp": datetime.now().isoformat(),
            "scanner_status": "active" if summary else "idle",
        }

    except Exception as e:
        logger.error(f"Error triggering scan: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/discovery/stats")
async def get_discovery_stats(request: Request):
    """Get real-time discovery engine statistics."""
    discovery = getattr(request.app.state, "discovery", None)
    if not discovery:
        return {
            "available": False,
            "message": "Discovery engine not running",
        }

    return {
        "available": True,
        **discovery.get_stats(),
    }


@router.get("/api/discovery/devices")
async def get_discovery_devices(request: Request):
    """Get live device list from the in-memory discovery registry."""
    discovery = getattr(request.app.state, "discovery", None)
    if not discovery:
        raise HTTPException(status_code=503, detail="Discovery engine not running")

    devices = discovery.registry.get_all()
    return {
        "total": len(devices),
        "online": sum(1 for d in devices if d.is_online),
        "devices": [d.to_dict() for d in devices],
    }


# ─── WiFi API Endpoints ───────────────────────────────────────────────────────

@router.get("/api/wifi/metrics")
async def get_wifi_metrics(request: Request):
    """Get current WiFi metrics."""
    scanner = _get_scanner(request)

    try:
        metrics = scanner.get_wifi_metrics()

        if not metrics:
            return {"available": False}

        return {
            "available": True,
            "metrics": metrics.to_dict(),
        }
    except Exception as e:
        logger.error(f"Error getting WiFi metrics: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/wifi/networks")
async def get_wifi_networks(request: Request):
    """Scan for available WiFi networks."""
    scanner = _get_scanner(request)

    try:
        networks = scanner.scan_wifi_networks()
        return {
            "count": len(networks),
            "networks": networks,
        }
    except Exception as e:
        logger.error(f"Error scanning WiFi networks: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/wifi/channel-analysis")
async def get_channel_analysis(request: Request):
    """Get WiFi channel analysis and recommendations."""
    scanner = _get_scanner(request)

    try:
        analysis = scanner.get_channel_analysis()
        return analysis
    except Exception as e:
        logger.error(f"Error getting channel analysis: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ─── Alert API Endpoints ──────────────────────────────────────────────────────

@router.get("/api/alerts")
async def get_alerts(
    request: Request,
    unacknowledged_only: bool = Query(False, description="Only return unacknowledged alerts"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    limit: int = Query(50, ge=1, le=200, description="Maximum number of alerts"),
    page: int = Query(0, ge=0, description="Page number (0 = no pagination)"),
    per_page: int = Query(50, ge=1, le=200, description="Items per page"),
):
    """Get alerts with optional filtering and pagination."""
    db = _get_db(request)

    try:
        if page > 0:
            result = db.get_alerts_paginated(
                page=page,
                per_page=per_page,
                severity=severity,
                acknowledged=False if unacknowledged_only else None,
            )
            return result.to_dict()

        if unacknowledged_only:
            alerts = db.get_unacknowledged_alerts()
        elif severity:
            alerts = db.get_alerts_by_severity(severity, limit=limit)
        else:
            alerts = db.get_recent_alerts(limit=limit)

        return {
            "count": len(alerts),
            "alerts": [alert.to_dict() for alert in alerts],
        }
    except Exception as e:
        logger.error(f"Error getting alerts: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/alerts/summary")
async def get_alert_summary(request: Request):
    """Get alert count summary by severity."""
    db = _get_db(request)

    try:
        return db.get_alert_summary()
    except Exception as e:
        logger.error(f"Error getting alert summary: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/api/alerts/{alert_id}/acknowledge")
async def acknowledge_alert(request: Request, alert_id: int):
    """Acknowledge an alert."""
    db = _get_db(request)

    try:
        success = db.acknowledge_alert(alert_id)

        if not success:
            raise HTTPException(status_code=404, detail="Alert not found")

        return {"success": True, "alert_id": alert_id}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error acknowledging alert: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/api/alerts/acknowledge-all")
async def acknowledge_all_alerts(request: Request):
    """Acknowledge all unacknowledged alerts."""
    db = _get_db(request)

    try:
        count = db.acknowledge_all_alerts()
        return {
            "success": True,
            "acknowledged_count": count,
            "message": f"Acknowledged {count} alert(s)",
        }
    except Exception as e:
        logger.error(f"Error acknowledging all alerts: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ─── Events API Endpoints ─────────────────────────────────────────────────────

@router.get("/api/events")
async def get_events(
    request: Request,
    limit: int = Query(50, ge=1, le=500, description="Maximum number of events"),
    event_type: Optional[str] = Query(None, description="Filter by event type"),
):
    """Get network events timeline with optional event_type filter."""
    db = _get_db(request)

    try:
        events = db.get_recent_events(limit=limit, event_type=event_type)
        return {
            "count": len(events),
            "events": [event.to_dict() for event in events],
        }
    except Exception as e:
        logger.error(f"Error getting events: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/events/{device_mac}")
async def get_device_events(
    request: Request,
    device_mac: str,
    limit: int = Query(20, ge=1, le=200, description="Maximum number of events"),
):
    """Get events for a specific device."""
    db = _get_db(request)

    try:
        events = db.get_device_events(device_mac, limit=limit)
        return {
            "device_mac": device_mac,
            "count": len(events),
            "events": [event.to_dict() for event in events],
        }
    except Exception as e:
        logger.error(f"Error getting events for device {device_mac}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ─── Latency API Endpoints ────────────────────────────────────────────────────

@router.get("/api/latency")
async def get_latency_history(
    request: Request,
    hours: int = Query(24, ge=1, le=168, description="Hours to look back"),
    device_mac: Optional[str] = Query(None, description="Filter by device MAC address"),
):
    """Get latency history for charting and analysis."""
    db = _get_db(request)

    try:
        samples = db.get_latency_history(hours=hours, device_mac=device_mac)
        return {
            "hours": hours,
            "device_mac": device_mac,
            "count": len(samples),
            "samples": [sample.to_dict() for sample in samples],
        }
    except Exception as e:
        logger.error(f"Error getting latency history: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ─── Trend API Endpoints ────────────────────────────────────────────────────

@router.get("/api/trends/devices")
async def get_device_count_trend(
    request: Request,
    days: int = Query(7, ge=1, le=90, description="Days to look back"),
):
    """Get device count trend over time."""
    db = _get_db(request)

    try:
        trend = db.get_device_count_trend(days=days)
        return {
            "days": days,
            "count": len(trend),
            "trend": trend,
        }
    except Exception as e:
        logger.error(f"Error getting device count trend: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/trends/latency")
async def get_latency_trend(
    request: Request,
    hours: int = Query(24, ge=1, le=168, description="Hours to look back"),
    device_mac: Optional[str] = Query(None, description="Filter by device MAC"),
):
    """Get latency trend data for charting."""
    db = _get_db(request)

    try:
        trend = db.get_latency_trend(hours=hours, device_mac=device_mac)
        return {
            "hours": hours,
            "device_mac": device_mac,
            "count": len(trend),
            "trend": trend,
        }
    except Exception as e:
        logger.error(f"Error getting latency trend: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/trends/alerts")
async def get_alert_trend(
    request: Request,
    days: int = Query(7, ge=1, le=90, description="Days to look back"),
):
    """Get alert count trend by day."""
    db = _get_db(request)

    try:
        trend = db.get_alert_trend(days=days)
        return {
            "days": days,
            "count": len(trend),
            "trend": trend,
        }
    except Exception as e:
        logger.error(f"Error getting alert trend: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/trends/events")
async def get_event_frequency(
    request: Request,
    days: int = Query(7, ge=1, le=90, description="Days to look back"),
):
    """Get event type frequency distribution."""
    db = _get_db(request)

    try:
        freq = db.get_event_frequency(days=days)
        return {
            "days": days,
            "event_types": freq,
        }
    except Exception as e:
        logger.error(f"Error getting event frequency: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/trends/scan-duration")
async def get_scan_duration_trend(
    request: Request,
    days: int = Query(7, ge=1, le=90, description="Days to look back"),
):
    """Get scan duration trend for performance monitoring."""
    db = _get_db(request)

    try:
        trend = db.get_scan_duration_trend(days=days)
        return {
            "days": days,
            "count": len(trend),
            "trend": trend,
        }
    except Exception as e:
        logger.error(f"Error getting scan duration trend: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ─── AI Insights & Analysis Endpoints ─────────────────────────────────────────

@router.get("/api/insights")
async def get_insights(request: Request):
    """Get AI-generated insights."""
    db = _get_db(request)
    ai = request.app.state.ai_analyzer

    if not ai:
        return {
            "available": False,
            "message": "AI analysis not available",
        }

    try:
        # Get recent scan data
        scans = db.get_recent_scans(limit=1)
        if not scans:
            return {
                "available": False,
                "message": "No scan data available",
            }

        scan = scans[0]
        scan_data = scan.to_dict()

        # Get quick insights
        insights = ai.get_quick_insights(scan_data.get("raw_data", {}))

        return {
            "available": True,
            "insights": insights,
            "timestamp": datetime.now().isoformat(),
        }
    except Exception as e:
        logger.error(f"Error getting insights: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/api/analyze/security")
async def analyze_security(request: Request):
    """Perform security analysis."""
    db = _get_db(request)
    ai = _get_ai(request)

    try:
        # Get recent scan data
        scans = db.get_recent_scans(limit=1)
        if not scans:
            raise HTTPException(status_code=404, detail="No scan data available")

        scan = scans[0]
        scan_data = scan.to_dict().get("raw_data", {})

        # Perform analysis
        recommendations = ai.analyze_security(scan_data)

        return {
            "count": len(recommendations),
            "recommendations": [rec.to_dict() for rec in recommendations],
            "timestamp": datetime.now().isoformat(),
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error performing security analysis: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/api/analyze/health")
async def analyze_health(request: Request):
    """Perform network health analysis."""
    db = _get_db(request)
    ai = _get_ai(request)

    try:
        scans = db.get_recent_scans(limit=1)
        if not scans:
            raise HTTPException(status_code=404, detail="No scan data available")

        scan = scans[0]
        scan_data = scan.to_dict().get("raw_data", {})

        recommendations = ai.analyze_network_health(scan_data)

        return {
            "count": len(recommendations),
            "recommendations": [rec.to_dict() for rec in recommendations],
            "timestamp": datetime.now().isoformat(),
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error performing health analysis: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/api/analyze/wifi")
async def analyze_wifi(request: Request):
    """Perform WiFi optimization analysis."""
    scanner = _get_scanner(request)
    ai = _get_ai(request)

    try:
        # Gather WiFi data from the scanner
        wifi_data = {}

        metrics = scanner.get_wifi_metrics()
        if metrics:
            wifi_data["metrics"] = metrics.to_dict()

        networks = scanner.scan_wifi_networks()
        if networks:
            wifi_data["networks"] = networks

        if not wifi_data:
            raise HTTPException(status_code=404, detail="No WiFi data available")

        # Perform WiFi optimization analysis
        recommendations = ai.analyze_wifi_optimization(wifi_data)

        return {
            "count": len(recommendations),
            "recommendations": [rec.to_dict() for rec in recommendations],
            "timestamp": datetime.now().isoformat(),
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error performing WiFi analysis: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/api/analyze/performance")
async def analyze_performance(request: Request):
    """Perform latency and performance analysis on all devices."""
    db = _get_db(request)
    ai = _get_ai(request)

    try:
        devices = db.get_all_devices(online_only=True)
        if not devices:
            raise HTTPException(status_code=404, detail="No online devices")

        devices_data = [d.to_dict() for d in devices]
        recommendations = ai.analyze_latency_health(devices_data)

        return {
            "count": len(recommendations),
            "recommendations": [rec.to_dict() for rec in recommendations],
            "timestamp": datetime.now().isoformat(),
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error performing performance analysis: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/api/analyze/trends")
async def analyze_trends(
    request: Request,
    days: int = Query(7, ge=1, le=90, description="Days to look back"),
):
    """Perform trend analysis across device counts, alerts, and latency."""
    db = _get_db(request)
    ai = _get_ai(request)

    try:
        device_trend = db.get_device_count_trend(days=days)
        alert_trend = db.get_alert_trend(days=days)
        latency_trend = db.get_latency_trend(hours=days * 24)

        recommendations = ai.analyze_network_trends(
            device_trend, alert_trend, latency_trend
        )

        return {
            "count": len(recommendations),
            "recommendations": [rec.to_dict() for rec in recommendations],
            "timestamp": datetime.now().isoformat(),
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error performing trend analysis: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/api/analyze/comprehensive")
async def analyze_comprehensive(request: Request):
    """Run comprehensive analysis combining all analysis types."""
    db = _get_db(request)
    ai = _get_ai(request)
    scanner = request.app.state.scanner

    try:
        # Get scan data
        scans = db.get_recent_scans(limit=1)
        scan_data = scans[0].to_dict().get("raw_data", {}) if scans else {}

        # Get WiFi data
        wifi_data = None
        if scanner:
            try:
                metrics = scanner.get_wifi_metrics()
                if metrics:
                    wifi_data = metrics.to_dict()
            except Exception:
                pass

        # Get device data
        devices = db.get_all_devices(online_only=True)
        devices_data = [d.to_dict() for d in devices] if devices else None

        # Get trend data
        device_trend = db.get_device_count_trend(days=7)
        alert_trend = db.get_alert_trend(days=7)
        latency_trend = db.get_latency_trend(hours=168)

        report = ai.get_comprehensive_health_report(
            scan_data=scan_data,
            wifi_data=wifi_data,
            devices_data=devices_data,
            device_count_trend=device_trend,
            alert_trend=alert_trend,
            latency_trend=latency_trend,
        )

        return report

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error performing comprehensive analysis: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/analyze/device-risks")
async def get_all_device_risks(request: Request):
    """Get risk scores for all devices, sorted by risk."""
    db = _get_db(request)
    ai = _get_ai(request)
    scanner = request.app.state.scanner

    try:
        devices = db.get_all_devices()
        gateway_ip = scanner.get_gateway_ip() if scanner else None

        device_dicts = [d.to_dict() for d in devices]
        scan_data = {
            "devices": device_dicts,
            "gateway": gateway_ip,
        }

        risks = ai.calculate_all_device_risks(scan_data)

        # Persist scores
        for risk in risks:
            mac = None
            ip = risk.get("device_ip", "")
            for d in devices:
                if d.ip == ip:
                    mac = d.mac
                    break
            if mac:
                db.update_device_risk_score(mac, risk["score"])

        return {
            "count": len(risks),
            "device_risks": risks,
            "timestamp": datetime.now().isoformat(),
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error calculating device risks: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ─── Network Summary Endpoint ─────────────────────────────────────────────────

@router.get("/api/network/summary")
async def get_network_summary(request: Request):
    """Get comprehensive network summary combining scanner and database data."""
    db = _get_db(request)
    scanner = request.app.state.scanner

    try:
        # Get dashboard stats from database
        stats = db.get_dashboard_stats()

        # Get alert summary
        alert_summary = db.get_alert_summary()

        # Get scanner summary if available
        scanner_summary = None
        if scanner:
            try:
                scanner_summary = scanner.get_network_summary()
            except Exception as e:
                logger.warning(f"Could not get scanner network summary: {e}")

        return {
            "stats": stats,
            "alert_summary": alert_summary,
            "scanner_summary": scanner_summary,
            "timestamp": datetime.now().isoformat(),
        }
    except Exception as e:
        logger.error(f"Error getting network summary: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/network/health")
async def get_network_health(request: Request):
    """Get network health summary."""
    db = _get_db(request)

    try:
        health = db.get_network_health_summary()
        return health
    except Exception as e:
        logger.error(f"Error getting network health: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/network/timeline")
async def get_network_timeline(
    request: Request,
    hours: int = Query(24, ge=1, le=168, description="Hours to look back"),
    limit: int = Query(100, ge=1, le=500, description="Maximum events"),
):
    """Get a timeline of network events."""
    db = _get_db(request)

    try:
        timeline = db.get_network_timeline(hours=hours, limit=limit)
        return {
            "hours": hours,
            "count": len(timeline),
            "events": timeline,
        }
    except Exception as e:
        logger.error(f"Error getting network timeline: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ─── Categories Endpoint ──────────────────────────────────────────────────────

@router.get("/api/categories")
async def get_categories(request: Request):
    """Get device categories list with counts from the database."""
    db = _get_db(request)

    try:
        counts = db.get_device_count_by_category()

        # Build category list with metadata and counts
        categories = []
        for key, meta in DEVICE_CATEGORIES.items():
            categories.append({
                "key": key,
                "label": meta["label"],
                "icon": meta["icon"],
                "count": counts.get(key, 0),
            })

        return {
            "count": len(categories),
            "categories": categories,
            "total_devices": sum(counts.values()),
        }
    except Exception as e:
        logger.error(f"Error getting categories: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/vendors")
async def get_top_vendors(
    request: Request,
    limit: int = Query(10, ge=1, le=50, description="Number of top vendors"),
):
    """Get top vendors by device count."""
    db = _get_db(request)

    try:
        vendors = db.get_device_count_by_vendor(limit=limit)
        return {
            "count": len(vendors),
            "vendors": [{"vendor": v, "count": c} for v, c in vendors],
        }
    except Exception as e:
        logger.error(f"Error getting vendors: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ─── Export Endpoint ───────────────────────────────────────────────────────────

@router.get("/api/export")
async def export_data(
    request: Request,
    format: str = Query("json", pattern="^(json|csv)$", description="Export format"),
    data_type: str = Query("devices", pattern="^(devices|scans|alerts|events)$", description="Data type"),
):
    """Export data in various formats."""
    db = _get_db(request)

    try:
        # Get data based on type
        if data_type == "devices":
            items = db.get_all_devices()
            data = [device.to_dict() for device in items]
        elif data_type == "scans":
            items = db.get_recent_scans(limit=100)
            data = [scan.to_dict() for scan in items]
        elif data_type == "alerts":
            items = db.get_recent_alerts(limit=100)
            data = [alert.to_dict() for alert in items]
        elif data_type == "events":
            items = db.get_recent_events(limit=500)
            data = [event.to_dict() for event in items]
        else:
            raise HTTPException(status_code=400, detail="Invalid data type")

        # Export as JSON
        if format == "json":
            return JSONResponse(
                content={
                    "data_type": data_type,
                    "count": len(data),
                    "exported_at": datetime.now().isoformat(),
                    "data": data,
                }
            )

        # Export as CSV
        elif format == "csv":
            if not data:
                raise HTTPException(status_code=404, detail="No data to export")

            # Create CSV
            output = io.StringIO()
            writer = csv.DictWriter(output, fieldnames=data[0].keys())
            writer.writeheader()
            writer.writerows(data)

            # Return as streaming response
            return StreamingResponse(
                iter([output.getvalue()]),
                media_type="text/csv",
                headers={
                    "Content-Disposition": f"attachment; filename=netmondash_{data_type}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
                }
            )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error exporting data: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ─── Statistics Endpoint ──────────────────────────────────────────────────────

@router.get("/api/stats")
async def get_statistics(request: Request):
    """Get comprehensive dashboard statistics."""
    db = _get_db(request)

    try:
        stats = db.get_dashboard_stats()
        return stats
    except Exception as e:
        logger.error(f"Error getting statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ─── Database Administration Endpoints ────────────────────────────────────────

@router.get("/api/database/info")
async def get_database_info(request: Request):
    """Get database record counts and size information."""
    db = _get_db(request)

    try:
        info = db.get_database_info()
        return {
            "tables": info,
            "total_records": sum(info.values()),
            "timestamp": datetime.now().isoformat(),
        }
    except Exception as e:
        logger.error(f"Error getting database info: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/api/database/cleanup")
async def cleanup_database(
    request: Request,
    days: int = Query(30, ge=1, le=365, description="Delete data older than this many days"),
):
    """Trigger cleanup of old data from the database."""
    db = _get_db(request)

    try:
        result = db.cleanup_old_data(days=days)
        total_deleted = sum(result.values())
        return {
            "success": True,
            "days_threshold": days,
            "deleted": result,
            "total_deleted": total_deleted,
            "message": f"Cleaned up {total_deleted} old record(s) older than {days} day(s)",
            "timestamp": datetime.now().isoformat(),
        }
    except Exception as e:
        logger.error(f"Error during database cleanup: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ─── Settings Endpoint ────────────────────────────────────────────────────────

@router.get("/api/settings/current")
async def get_current_settings(request: Request):
    """Get current runtime settings and component status."""
    try:
        from config import (
            DEFAULT_SCAN_INTERVAL,
            SCAN_INTERVAL,
            WEB_PORT,
            ENABLE_AI,
            DEBUG_MODE,
            DEVICE_HISTORY_RETENTION_DAYS,
            OLLAMA_MODEL,
            OLLAMA_API_URL,
        )

        return {
            "scan_interval": SCAN_INTERVAL,
            "default_scan_interval": DEFAULT_SCAN_INTERVAL,
            "web_port": WEB_PORT,
            "ai_enabled": ENABLE_AI,
            "debug_mode": DEBUG_MODE,
            "retention_days": DEVICE_HISTORY_RETENTION_DAYS,
            "ollama_model": OLLAMA_MODEL,
            "ollama_url": OLLAMA_API_URL,
            "components": {
                "database": request.app.state.db_manager is not None,
                "scanner": request.app.state.scanner is not None,
                "ai_analyzer": request.app.state.ai_analyzer is not None,
                "notifier": getattr(request.app.state, "notifier", None) is not None,
            },
            "timestamp": datetime.now().isoformat(),
        }
    except Exception as e:
        logger.error(f"Error getting settings: {e}")
        raise HTTPException(status_code=500, detail=str(e))
