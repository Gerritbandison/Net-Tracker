"""
WebSocket Handlers

Real-time updates via WebSockets with typed subscriptions,
connection tracking, and rate-limited broadcasts.
"""

import logging
import asyncio
import json
import time
from typing import Set, Dict, Optional
from datetime import datetime
from collections import defaultdict

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from fastapi.websockets import WebSocketState

logger = logging.getLogger(__name__)

router = APIRouter()


class ConnectionManager:
    """Manage WebSocket connections with subscriptions and rate limiting."""

    def __init__(self):
        self.active_connections: Set[WebSocket] = set()
        self.subscriptions: Dict[WebSocket, Set[str]] = defaultdict(lambda: {"all"})
        self._last_broadcast: Dict[str, float] = {}
        self._broadcast_interval = 0.5  # Min seconds between broadcasts of same type
        self._stats = {
            "total_connections": 0,
            "total_messages_sent": 0,
            "total_messages_received": 0,
        }

    @property
    def connection_count(self) -> int:
        return len(self.active_connections)

    def get_stats(self) -> Dict:
        return {
            **self._stats,
            "active_connections": self.connection_count,
        }

    async def connect(self, websocket: WebSocket):
        """Accept and register a new connection."""
        await websocket.accept()
        self.active_connections.add(websocket)
        self.subscriptions[websocket] = {"all"}
        self._stats["total_connections"] += 1
        logger.info(f"WebSocket connected. Total connections: {self.connection_count}")

    def disconnect(self, websocket: WebSocket):
        """Unregister a connection."""
        self.active_connections.discard(websocket)
        self.subscriptions.pop(websocket, None)
        logger.info(f"WebSocket disconnected. Total connections: {self.connection_count}")

    def subscribe(self, websocket: WebSocket, channel: str):
        """Subscribe a connection to a channel."""
        self.subscriptions[websocket].add(channel)
        logger.debug(f"Client subscribed to {channel}")

    def unsubscribe(self, websocket: WebSocket, channel: str):
        """Unsubscribe a connection from a channel."""
        self.subscriptions[websocket].discard(channel)

    async def send_personal_message(self, message: dict, websocket: WebSocket):
        """Send message to a specific connection."""
        try:
            if websocket.client_state == WebSocketState.CONNECTED:
                await websocket.send_json(message)
                self._stats["total_messages_sent"] += 1
        except Exception as e:
            logger.error(f"Error sending personal message: {e}")

    async def broadcast(self, message: dict, channel: str = "all"):
        """Broadcast message to all connected clients subscribed to the channel."""
        # Rate limiting
        now = time.monotonic()
        msg_type = message.get("type", "unknown")
        rate_key = f"{channel}:{msg_type}"
        last = self._last_broadcast.get(rate_key, 0)
        if now - last < self._broadcast_interval:
            return
        self._last_broadcast[rate_key] = now

        disconnected = set()

        for connection in self.active_connections:
            subs = self.subscriptions.get(connection, {"all"})
            if "all" in subs or channel in subs:
                try:
                    if connection.client_state == WebSocketState.CONNECTED:
                        await connection.send_json(message)
                        self._stats["total_messages_sent"] += 1
                    else:
                        disconnected.add(connection)
                except Exception as e:
                    logger.error(f"Error broadcasting to connection: {e}")
                    disconnected.add(connection)

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
    - {"type": "subscribe", "channel": "devices|scans|alerts|all"} - Subscribe to updates
    - {"type": "unsubscribe", "channel": "..."} - Unsubscribe from updates
    - {"type": "get_stats"} - Request current statistics

    Messages to client:
    - {"type": "pong"} - Keep-alive response
    - {"type": "connected"} - Connection confirmation
    - {"type": "subscribed", "channel": "..."} - Subscription confirmation
    - {"type": "scan_update", "data": {...}} - New scan completed
    - {"type": "device_update", "data": {...}, "event": "..."} - Device status changed
    - {"type": "alert", "data": {...}} - New alert
    - {"type": "stats", "data": {...}} - Updated statistics
    - {"type": "heartbeat"} - Server heartbeat
    - {"type": "event", "data": {...}} - Network event
    """
    await manager.connect(websocket)

    try:
        await websocket.send_json({
            "type": "connected",
            "timestamp": datetime.now().isoformat(),
            "message": "WebSocket connection established",
            "connection_count": manager.connection_count,
        })

        while True:
            try:
                data = await asyncio.wait_for(
                    websocket.receive_json(),
                    timeout=30.0
                )

                manager._stats["total_messages_received"] += 1
                message_type = data.get("type")

                if message_type == "ping":
                    await websocket.send_json({
                        "type": "pong",
                        "timestamp": datetime.now().isoformat()
                    })

                elif message_type == "subscribe":
                    channel = data.get("channel", "all")
                    manager.subscribe(websocket, channel)
                    await websocket.send_json({
                        "type": "subscribed",
                        "channel": channel,
                        "timestamp": datetime.now().isoformat()
                    })

                elif message_type == "unsubscribe":
                    channel = data.get("channel", "all")
                    manager.unsubscribe(websocket, channel)
                    await websocket.send_json({
                        "type": "unsubscribed",
                        "channel": channel,
                        "timestamp": datetime.now().isoformat()
                    })

                elif message_type == "get_stats":
                    db = websocket.app.state.db_manager
                    if db:
                        stats = db.get_dashboard_stats()
                        await websocket.send_json({
                            "type": "stats",
                            "data": stats,
                            "timestamp": datetime.now().isoformat()
                        })

                elif message_type == "get_ws_stats":
                    await websocket.send_json({
                        "type": "ws_stats",
                        "data": manager.get_stats(),
                        "timestamp": datetime.now().isoformat()
                    })

            except asyncio.TimeoutError:
                try:
                    await websocket.send_json({
                        "type": "heartbeat",
                        "timestamp": datetime.now().isoformat(),
                        "connections": manager.connection_count,
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


# ─── Broadcast Functions ──────────────────────────────────────────────────────

async def broadcast_scan_update(scan_data: dict):
    """Broadcast scan update to all clients subscribed to scans."""
    await manager.broadcast({
        "type": "scan_update",
        "data": scan_data,
        "timestamp": datetime.now().isoformat()
    }, channel="scans")


async def broadcast_device_update(device_data: dict, event: str = "updated"):
    """Broadcast device update to all clients subscribed to devices."""
    await manager.broadcast({
        "type": "device_update",
        "event": event,
        "data": device_data,
        "timestamp": datetime.now().isoformat()
    }, channel="devices")


async def broadcast_alert(alert_data: dict):
    """Broadcast new alert to all clients subscribed to alerts."""
    await manager.broadcast({
        "type": "alert",
        "data": alert_data,
        "timestamp": datetime.now().isoformat()
    }, channel="alerts")


async def broadcast_stats(stats: dict):
    """Broadcast statistics update to all connected clients."""
    await manager.broadcast({
        "type": "stats",
        "data": stats,
        "timestamp": datetime.now().isoformat()
    })


async def broadcast_event(event_data: dict):
    """Broadcast a network event to all connected clients."""
    await manager.broadcast({
        "type": "event",
        "data": event_data,
        "timestamp": datetime.now().isoformat()
    })


__all__ = [
    "router",
    "manager",
    "broadcast_scan_update",
    "broadcast_device_update",
    "broadcast_alert",
    "broadcast_stats",
    "broadcast_event",
]
