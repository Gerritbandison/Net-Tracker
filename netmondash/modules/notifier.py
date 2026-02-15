"""
Notifier Module

Pluggable notification system with multiple backends:
  - Desktop (notify-send / libnotify)
  - Webhook (HTTP POST to any URL — Slack, Discord, Teams, custom)
  - Email (SMTP)

Usage:
    notifier = Notifier()  # desktop only (backward-compatible)

    # With webhook:
    notifier = Notifier(backends=[
        DesktopBackend(),
        WebhookBackend("https://hooks.slack.com/services/..."),
    ])

    # With email:
    notifier = Notifier(backends=[
        DesktopBackend(),
        EmailBackend("smtp.gmail.com", 587, "user@gmail.com", "apppassword", ["admin@co.com"]),
    ])
"""

import json
import logging
import smtplib
import subprocess
from abc import ABC, abstractmethod
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Dict, List, Optional

import requests

from config import (
    ENABLE_DESKTOP_NOTIFICATIONS,
    NOTIFICATION_TIMEOUT,
    NOTIFY_ON_NEW_DEVICE,
    NOTIFY_ON_CRITICAL_ALERT,
)

logger = logging.getLogger(__name__)


# ─── Backend Interface ────────────────────────────────────────────────────────


class NotifierBackend(ABC):
    """Base class for notification backends."""

    @abstractmethod
    def send(
        self,
        title: str,
        message: str,
        urgency: str = "normal",
        **kwargs,
    ) -> bool:
        """Send a notification.

        Args:
            title: Short notification title.
            message: Notification body.
            urgency: One of 'low', 'normal', 'critical'.

        Returns:
            True if delivery succeeded.
        """


# ─── Desktop Backend (notify-send) ────────────────────────────────────────────


class DesktopBackend(NotifierBackend):
    """Linux desktop notifications via notify-send (libnotify)."""

    def __init__(self, timeout_ms: int = NOTIFICATION_TIMEOUT):
        self.timeout_ms = timeout_ms
        self.available = self._check()

    def _check(self) -> bool:
        try:
            result = subprocess.run(
                ["which", "notify-send"],
                capture_output=True,
                timeout=2,
            )
            if result.returncode == 0:
                logger.debug("notify-send is available")
                return True
            logger.warning("notify-send not found")
            return False
        except Exception as e:
            logger.warning(f"Error checking for notify-send: {e}")
            return False

    def send(
        self,
        title: str,
        message: str,
        urgency: str = "normal",
        timeout: Optional[int] = None,
        icon: Optional[str] = None,
        **kwargs,
    ) -> bool:
        if not self.available:
            return False

        timeout = timeout or self.timeout_ms
        icon = icon or "network-wired"

        try:
            cmd = [
                "notify-send",
                title,
                message,
                f"--urgency={urgency}",
                f"--expire-time={timeout}",
                f"--icon={icon}",
            ]
            result = subprocess.run(cmd, capture_output=True, timeout=5)
            if result.returncode == 0:
                logger.debug(f"Desktop notification sent: {title}")
                return True
            logger.warning(f"notify-send failed: {result.stderr.decode()}")
            return False
        except subprocess.TimeoutExpired:
            logger.error("Notification command timed out")
            return False
        except Exception as e:
            logger.error(f"Error sending desktop notification: {e}")
            return False


# ─── Webhook Backend ──────────────────────────────────────────────────────────


class WebhookBackend(NotifierBackend):
    """Send notifications via HTTP POST to a webhook URL.

    Works with Slack, Discord, Microsoft Teams, and any custom endpoint.
    The payload format adapts to detected service type.
    """

    def __init__(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        timeout: int = 10,
        service: Optional[str] = None,
    ):
        """
        Args:
            url: Webhook URL.
            headers: Extra HTTP headers (e.g. Authorization).
            timeout: HTTP request timeout in seconds.
            service: Force service type ('slack', 'discord', 'teams', 'generic').
                     Auto-detected from URL if None.
        """
        self.url = url
        self.headers = {"Content-Type": "application/json", **(headers or {})}
        self.timeout = timeout
        self.service = service or self._detect_service(url)

    @staticmethod
    def _detect_service(url: str) -> str:
        if "hooks.slack.com" in url:
            return "slack"
        if "discord.com/api/webhooks" in url or "discordapp.com/api/webhooks" in url:
            return "discord"
        if "webhook.office.com" in url or "outlook.office.com" in url:
            return "teams"
        return "generic"

    def _build_payload(self, title: str, message: str, urgency: str) -> Dict:
        color_map = {"critical": "#ff0000", "normal": "#36a64f", "low": "#cccccc"}
        color = color_map.get(urgency, "#36a64f")

        if self.service == "slack":
            return {
                "attachments": [{
                    "color": color,
                    "title": title,
                    "text": message,
                    "footer": "NetMonDash",
                }]
            }

        if self.service == "discord":
            return {
                "embeds": [{
                    "title": title,
                    "description": message,
                    "color": int(color.lstrip("#"), 16),
                    "footer": {"text": "NetMonDash"},
                }]
            }

        if self.service == "teams":
            return {
                "@type": "MessageCard",
                "@context": "http://schema.org/extensions",
                "themeColor": color.lstrip("#"),
                "summary": title,
                "sections": [{
                    "activityTitle": title,
                    "text": message,
                }],
            }

        # Generic — simple JSON
        return {
            "title": title,
            "message": message,
            "urgency": urgency,
            "source": "NetMonDash",
        }

    def send(
        self,
        title: str,
        message: str,
        urgency: str = "normal",
        **kwargs,
    ) -> bool:
        payload = self._build_payload(title, message, urgency)
        try:
            resp = requests.post(
                self.url,
                json=payload,
                headers=self.headers,
                timeout=self.timeout,
            )
            if resp.status_code < 300:
                logger.debug(f"Webhook notification sent: {title}")
                return True
            logger.warning(
                "Webhook returned %d: %s", resp.status_code, resp.text[:200]
            )
            return False
        except requests.Timeout:
            logger.error("Webhook request timed out")
            return False
        except Exception as e:
            logger.error(f"Webhook error: {e}")
            return False


# ─── Email Backend ────────────────────────────────────────────────────────────


class EmailBackend(NotifierBackend):
    """Send notifications via SMTP email."""

    def __init__(
        self,
        smtp_host: str,
        smtp_port: int = 587,
        username: str = "",
        password: str = "",
        recipients: Optional[List[str]] = None,
        from_addr: Optional[str] = None,
        use_tls: bool = True,
    ):
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.username = username
        self.password = password
        self.recipients = recipients or []
        self.from_addr = from_addr or username
        self.use_tls = use_tls

    def send(
        self,
        title: str,
        message: str,
        urgency: str = "normal",
        **kwargs,
    ) -> bool:
        if not self.recipients:
            logger.warning("No email recipients configured")
            return False

        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = f"[NetMonDash] [{urgency.upper()}] {title}"
            msg["From"] = self.from_addr
            msg["To"] = ", ".join(self.recipients)

            # Plain text
            msg.attach(MIMEText(message, "plain"))

            # HTML version
            urgency_colors = {
                "critical": "#dc3545",
                "normal": "#28a745",
                "low": "#6c757d",
            }
            color = urgency_colors.get(urgency, "#28a745")
            html = (
                f'<div style="font-family: sans-serif; padding: 16px;">'
                f'<h2 style="color: {color};">{title}</h2>'
                f'<p style="white-space: pre-wrap;">{message}</p>'
                f'<hr><small style="color: #999;">NetMonDash Network Monitor</small>'
                f'</div>'
            )
            msg.attach(MIMEText(html, "html"))

            with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=10) as server:
                if self.use_tls:
                    server.starttls()
                if self.username and self.password:
                    server.login(self.username, self.password)
                server.sendmail(self.from_addr, self.recipients, msg.as_string())

            logger.debug(f"Email notification sent: {title}")
            return True

        except smtplib.SMTPException as e:
            logger.error(f"SMTP error: {e}")
            return False
        except Exception as e:
            logger.error(f"Email error: {e}")
            return False


# ─── Main Notifier (backward-compatible facade) ──────────────────────────────


class Notifier:
    """Notification manager with pluggable backends.

    Backward-compatible: ``Notifier()`` uses desktop notifications only.
    """

    def __init__(
        self,
        enabled: bool = ENABLE_DESKTOP_NOTIFICATIONS,
        backends: Optional[List[NotifierBackend]] = None,
    ):
        self.enabled = enabled

        if backends is not None:
            self.backends = backends
        elif enabled:
            desktop = DesktopBackend()
            if desktop.available:
                self.backends = [desktop]
            else:
                self.backends = []
                self.enabled = False
        else:
            self.backends = []

    # Legacy compatibility: _check_notify_send
    def _check_notify_send(self) -> bool:
        if not self.enabled:
            return False
        try:
            result = subprocess.run(
                ["which", "notify-send"],
                capture_output=True,
                timeout=2,
            )
            if result.returncode == 0:
                return True
            self.enabled = False
            return False
        except Exception:
            self.enabled = False
            return False

    def send_notification(
        self,
        title: str,
        message: str,
        urgency: str = "normal",
        timeout: int = NOTIFICATION_TIMEOUT,
        icon: Optional[str] = None,
    ) -> bool:
        if not self.enabled:
            logger.debug("Notifications disabled, skipping")
            return False

        sent = False
        for backend in self.backends:
            try:
                if backend.send(
                    title=title,
                    message=message,
                    urgency=urgency,
                    timeout=timeout,
                    icon=icon,
                ):
                    sent = True
            except Exception as e:
                logger.error(f"Backend {type(backend).__name__} error: {e}")
        return sent

    # ── Convenience methods (unchanged API) ──

    def notify_new_device(self, ip: str, mac: str, hostname: Optional[str] = None) -> bool:
        if not NOTIFY_ON_NEW_DEVICE:
            return False
        device_name = hostname or ip
        return self.send_notification(
            title=f"New Device Detected: {device_name}",
            message=f"IP: {ip}\nMAC: {mac}",
            urgency="normal",
            icon="network-wired",
        )

    def notify_device_offline(self, ip: str, hostname: Optional[str] = None) -> bool:
        device_name = hostname or ip
        return self.send_notification(
            title=f"Device Offline: {device_name}",
            message=f"{device_name} is no longer responding",
            urgency="low",
            icon="network-offline",
        )

    def notify_critical_alert(self, title: str, message: str, command: Optional[str] = None) -> bool:
        if not NOTIFY_ON_CRITICAL_ALERT:
            return False
        full_message = message
        if command:
            full_message += f"\n\nRecommended: {command}"
        return self.send_notification(
            title=f"🔒 Security Alert: {title}",
            message=full_message,
            urgency="critical",
            timeout=10000,
            icon="dialog-warning",
        )

    def notify_wifi_issue(self, issue: str, signal_strength: Optional[int] = None) -> bool:
        message = issue
        if signal_strength is not None:
            message += f"\nSignal: {signal_strength} dBm"
        return self.send_notification(
            title="WiFi Issue Detected",
            message=message,
            urgency="normal",
            icon="network-wireless",
        )

    def notify_scan_complete(self, device_count: int, new_devices: int = 0) -> bool:
        if new_devices > 0:
            message = f"Found {device_count} devices ({new_devices} new)"
            urgency = "normal"
        else:
            message = f"Found {device_count} devices"
            urgency = "low"
        return self.send_notification(
            title="Network Scan Complete",
            message=message,
            urgency=urgency,
            timeout=3000,
            icon="network-wired",
        )

    def notify_custom(
        self,
        title: str,
        message: str,
        urgency: str = "normal",
        icon: Optional[str] = None,
    ) -> bool:
        return self.send_notification(
            title=title,
            message=message,
            urgency=urgency,
            icon=icon or "dialog-information",
        )


if __name__ == "__main__":
    # Test the notifier
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    notifier = Notifier()

    print("Sending test notifications...")

    # Test new device notification
    print("\n1. New device notification")
    notifier.notify_new_device(
        ip="192.168.1.100",
        mac="00:11:22:33:44:55",
        hostname="test-device"
    )

    import time
    time.sleep(2)

    # Test critical alert
    print("\n2. Critical alert notification")
    notifier.notify_critical_alert(
        title="Unknown device detected",
        message="Device with unusual port activity detected",
        command="sudo ufw deny from 192.168.1.100"
    )

    time.sleep(2)

    # Test WiFi issue
    print("\n3. WiFi issue notification")
    notifier.notify_wifi_issue(
        issue="Weak signal detected",
        signal_strength=-75
    )

    time.sleep(2)

    # Test scan complete
    print("\n4. Scan complete notification")
    notifier.notify_scan_complete(
        device_count=15,
        new_devices=2
    )

    print("\nTest complete!")
