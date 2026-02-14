"""
API Routes

FastAPI routes for NetMonDash dashboard.
Provides HTML page routes and REST API endpoints for device management,
scanning, alerts, events, analytics, and system administration.
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
        "devices.html",
        {
            "request": request,
            "page": "devices",
            "title": "NetMonDash - Devices",
        }
    )


@router.get("/wifi", response_class=HTMLResponse)
async def wifi_page(request: Request):
    """WiFi analysis page."""
    templates = request.app.state.templates
    return templates.TemplateResponse(
        "wifi.html",
        {
            "request": request,
            "page": "wifi",
            "title": "NetMonDash - WiFi Analysis",
        }
    )


@router.get("/insights", response_class=HTMLResponse)
async def insights_page(request: Request):
    """AI insights page."""
    templates = request.app.state.templates
    return templates.TemplateResponse(
        "insights.html",
        {
            "request": request,
            "page": "insights",
            "title": "NetMonDash - AI Insights",
        }
    )


@router.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request):
    """Settings page."""
    templates = request.app.state.templates
    return templates.TemplateResponse(
        "settings.html",
        {
            "request": request,
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
):
    """Get all network devices with optional filtering."""
    db = _get_db(request)

    try:
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


@router.post("/api/scan/trigger")
async def trigger_scan(request: Request):
    """Trigger a manual network scan by setting the scan event flag."""
    scanner = _get_scanner(request)

    try:
        # Set the scan event flag if available on app state
        scan_event = getattr(request.app.state, "scan_event", None)
        if scan_event and isinstance(scan_event, asyncio.Event):
            scan_event.set()
            return {
                "success": True,
                "message": "Scan triggered successfully",
                "timestamp": datetime.now().isoformat(),
            }

        # Fallback: run a quick scan summary to confirm scanner is operational
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


# ─── Alert API Endpoints ──────────────────────────────────────────────────────

@router.get("/api/alerts")
async def get_alerts(
    request: Request,
    unacknowledged_only: bool = Query(False, description="Only return unacknowledged alerts"),
    limit: int = Query(50, ge=1, le=200, description="Maximum number of alerts"),
):
    """Get alerts."""
    db = _get_db(request)

    try:
        if unacknowledged_only:
            alerts = db.get_unacknowledged_alerts()
        else:
            alerts = db.get_recent_alerts(limit=limit)

        return {
            "count": len(alerts),
            "alerts": [alert.to_dict() for alert in alerts],
        }
    except Exception as e:
        logger.error(f"Error getting alerts: {e}")
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


# ─── Export Endpoint ───────────────────────────────────────────────────────────

@router.get("/api/export")
async def export_data(
    request: Request,
    format: str = Query("json", regex="^(json|csv)$", description="Export format"),
    data_type: str = Query("devices", regex="^(devices|scans|alerts)$", description="Data type"),
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
