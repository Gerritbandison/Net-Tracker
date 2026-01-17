"""
WebSocket Handlers

Real-time updates via WebSockets.
"""

import logging
import asyncio
import json
from typing import Set
from datetime import datetime

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from fastapi.websockets import WebSocketState

logger = logging.getLogger(__name__)

router = APIRouter()


class ConnectionManager:
    """Manage WebSocket connections."""

    def __init__(self):
        self.active_connections: Set[WebSocket] = set()

    async def connect(self, websocket: WebSocket):
        """Accept and register a new connection."""
        await websocket.accept()
        self.active_connections.add(websocket)
        logger.info(f"WebSocket connected. Total connections: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        """Unregister a connection."""
        self.active_connections.discard(websocket)
        logger.info(f"WebSocket disconnected. Total connections: {len(self.active_connections)}")

    async def send_personal_message(self, message: dict, websocket: WebSocket):
        """Send message to a specific connection."""
        try:
            if websocket.client_state == WebSocketState.CONNECTED:
                await websocket.send_json(message)
        except Exception as e:
            logger.error(f"Error sending personal message: {e}")

    async def broadcast(self, message: dict):
        """Broadcast message to all connected clients."""
        disconnected = set()

        for connection in self.active_connections:
            try:
                if connection.client_state == WebSocketState.CONNECTED:
                    await connection.send_json(message)
                else:
                    disconnected.add(connection)
            except Exception as e:
                logger.error(f"Error broadcasting to connection: {e}")
                disconnected.add(connection)

        # Clean up disconnected clients
        for conn in disconnected:
            self.disconnect(conn)


# Global connection manager
manager = ConnectionManager()


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """
    Main WebSocket endpoint for real-time updates.

    Messages from client:
    - {"type": "ping"} - Keep-alive
    - {"type": "subscribe", "channel": "devices|scans|alerts"} - Subscribe to updates

    Messages to client:
    - {"type": "pong"} - Keep-alive response
    - {"type": "scan_update", "data": {...}} - New scan completed
    - {"type": "device_update", "data": {...}} - Device status changed
    - {"type": "alert", "data": {...}} - New alert
    - {"type": "stats", "data": {...}} - Updated statistics
    """
    await manager.connect(websocket)

    try:
        # Send initial connection confirmation
        await websocket.send_json({
            "type": "connected",
            "timestamp": datetime.now().isoformat(),
            "message": "WebSocket connection established"
        })

        # Handle incoming messages
        while True:
            try:
                # Wait for message with timeout for heartbeat
                data = await asyncio.wait_for(
                    websocket.receive_json(),
                    timeout=30.0
                )

                message_type = data.get("type")

                if message_type == "ping":
                    # Respond to keep-alive
                    await websocket.send_json({
                        "type": "pong",
                        "timestamp": datetime.now().isoformat()
                    })

                elif message_type == "subscribe":
                    # Handle subscription (future enhancement)
                    channel = data.get("channel", "all")
                    await websocket.send_json({
                        "type": "subscribed",
                        "channel": channel,
                        "timestamp": datetime.now().isoformat()
                    })

                elif message_type == "get_stats":
                    # Send current statistics
                    db = websocket.app.state.db_manager
                    if db:
                        devices = db.get_all_devices()
                        online_devices = [d for d in devices if d.is_online]
                        alerts = db.get_unacknowledged_alerts()

                        await websocket.send_json({
                            "type": "stats",
                            "data": {
                                "total_devices": len(devices),
                                "online_devices": len(online_devices),
                                "unacknowledged_alerts": len(alerts),
                            },
                            "timestamp": datetime.now().isoformat()
                        })

            except asyncio.TimeoutError:
                # Send heartbeat
                try:
                    await websocket.send_json({
                        "type": "heartbeat",
                        "timestamp": datetime.now().isoformat()
                    })
                except Exception:
                    break

            except json.JSONDecodeError:
                logger.warning("Received invalid JSON from WebSocket client")
                await websocket.send_json({
                    "type": "error",
                    "message": "Invalid JSON"
                })

    except WebSocketDisconnect:
        logger.info("WebSocket client disconnected normally")

    except Exception as e:
        logger.error(f"WebSocket error: {e}")

    finally:
        manager.disconnect(websocket)


async def broadcast_scan_update(scan_data: dict):
    """
    Broadcast scan update to all connected clients.

    Args:
        scan_data: Scan result data
    """
    await manager.broadcast({
        "type": "scan_update",
        "data": scan_data,
        "timestamp": datetime.now().isoformat()
    })


async def broadcast_device_update(device_data: dict, event: str = "updated"):
    """
    Broadcast device update to all connected clients.

    Args:
        device_data: Device data
        event: Event type (new, updated, offline)
    """
    await manager.broadcast({
        "type": "device_update",
        "event": event,
        "data": device_data,
        "timestamp": datetime.now().isoformat()
    })


async def broadcast_alert(alert_data: dict):
    """
    Broadcast new alert to all connected clients.

    Args:
        alert_data: Alert data
    """
    await manager.broadcast({
        "type": "alert",
        "data": alert_data,
        "timestamp": datetime.now().isoformat()
    })


async def broadcast_stats(stats: dict):
    """
    Broadcast statistics update to all connected clients.

    Args:
        stats: Statistics data
    """
    await manager.broadcast({
        "type": "stats",
        "data": stats,
        "timestamp": datetime.now().isoformat()
    })


# Export broadcast functions for use by other modules
__all__ = [
    "router",
    "manager",
    "broadcast_scan_update",
    "broadcast_device_update",
    "broadcast_alert",
    "broadcast_stats",
]
