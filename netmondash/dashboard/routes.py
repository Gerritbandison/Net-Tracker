"""
API Routes

FastAPI routes for NetMonDash dashboard.
"""

import logging
import csv
import json
import io
from datetime import datetime
from typing import Optional, List

from fastapi import APIRouter, Request, HTTPException, Query, Response
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse

logger = logging.getLogger(__name__)

router = APIRouter()


# HTML Page Routes

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


# API Endpoints

@router.get("/api/devices")
async def get_devices(
    request: Request,
    online_only: bool = Query(False, description="Only return online devices"),
):
    """Get all network devices."""
    db = request.app.state.db_manager

    if not db:
        raise HTTPException(status_code=503, detail="Database not available")

    try:
        devices = db.get_all_devices(online_only=online_only)
        return {
            "count": len(devices),
            "devices": [device.to_dict() for device in devices],
        }
    except Exception as e:
        logger.error(f"Error getting devices: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/devices/{mac}")
async def get_device(request: Request, mac: str):
    """Get specific device by MAC address."""
    db = request.app.state.db_manager

    if not db:
        raise HTTPException(status_code=503, detail="Database not available")

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


@router.post("/api/devices/{mac}/notes")
async def update_device_notes(request: Request, mac: str):
    """Update device notes."""
    db = request.app.state.db_manager

    if not db:
        raise HTTPException(status_code=503, detail="Database not available")

    try:
        body = await request.json()
        notes = body.get("notes", "")

        device = db.get_device(mac)
        if not device:
            raise HTTPException(status_code=404, detail="Device not found")

        # Update notes in database
        session = db.get_session()
        try:
            device.notes = notes
            session.commit()
            return {"success": True, "mac": mac}
        finally:
            session.close()

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating device notes: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/scans/recent")
async def get_recent_scans(
    request: Request,
    limit: int = Query(10, ge=1, le=100, description="Number of scans to return"),
):
    """Get recent scans."""
    db = request.app.state.db_manager

    if not db:
        raise HTTPException(status_code=503, detail="Database not available")

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
    db = request.app.state.db_manager

    if not db:
        raise HTTPException(status_code=503, detail="Database not available")

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
    """Trigger a manual network scan."""
    scanner = request.app.state.scanner

    if not scanner:
        raise HTTPException(status_code=503, detail="Scanner not available")

    try:
        # This would trigger a scan in the background
        # In practice, this would notify the scan loop to run immediately
        return {
            "success": True,
            "message": "Scan triggered",
        }
    except Exception as e:
        logger.error(f"Error triggering scan: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/wifi/metrics")
async def get_wifi_metrics(request: Request):
    """Get current WiFi metrics."""
    scanner = request.app.state.scanner

    if not scanner:
        raise HTTPException(status_code=503, detail="Scanner not available")

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
    scanner = request.app.state.scanner

    if not scanner:
        raise HTTPException(status_code=503, detail="Scanner not available")

    try:
        networks = scanner.scan_wifi_networks()
        return {
            "count": len(networks),
            "networks": networks,
        }
    except Exception as e:
        logger.error(f"Error scanning WiFi networks: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/alerts")
async def get_alerts(
    request: Request,
    unacknowledged_only: bool = Query(False, description="Only return unacknowledged alerts"),
    limit: int = Query(50, ge=1, le=200, description="Maximum number of alerts"),
):
    """Get alerts."""
    db = request.app.state.db_manager

    if not db:
        raise HTTPException(status_code=503, detail="Database not available")

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
    db = request.app.state.db_manager

    if not db:
        raise HTTPException(status_code=503, detail="Database not available")

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


@router.get("/api/insights")
async def get_insights(request: Request):
    """Get AI-generated insights."""
    db = request.app.state.db_manager
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
    db = request.app.state.db_manager
    ai = request.app.state.ai_analyzer

    if not ai:
        raise HTTPException(status_code=503, detail="AI analyzer not available")

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
    db = request.app.state.db_manager
    ai = request.app.state.ai_analyzer

    if not ai:
        raise HTTPException(status_code=503, detail="AI analyzer not available")

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


@router.get("/api/export")
async def export_data(
    request: Request,
    format: str = Query("json", regex="^(json|csv)$", description="Export format"),
    data_type: str = Query("devices", regex="^(devices|scans|alerts)$", description="Data type"),
):
    """Export data in various formats."""
    db = request.app.state.db_manager

    if not db:
        raise HTTPException(status_code=503, detail="Database not available")

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


@router.get("/api/stats")
async def get_statistics(request: Request):
    """Get dashboard statistics."""
    db = request.app.state.db_manager

    if not db:
        raise HTTPException(status_code=503, detail="Database not available")

    try:
        devices = db.get_all_devices()
        online_devices = [d for d in devices if d.is_online]
        unack_alerts = db.get_unacknowledged_alerts()
        recent_scans = db.get_scan_history(hours=24)

        # Count critical alerts
        critical_alerts = [a for a in unack_alerts if a.severity == "critical"]

        return {
            "total_devices": len(devices),
            "online_devices": len(online_devices),
            "offline_devices": len(devices) - len(online_devices),
            "unacknowledged_alerts": len(unack_alerts),
            "critical_alerts": len(critical_alerts),
            "scans_24h": len(recent_scans),
            "last_scan": recent_scans[-1].timestamp.isoformat() if recent_scans else None,
        }
    except Exception as e:
        logger.error(f"Error getting statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))
