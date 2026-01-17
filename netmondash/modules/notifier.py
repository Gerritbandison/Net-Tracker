"""
Notifier Module

Desktop notification support using libnotify.
"""

import logging
import subprocess
from typing import Optional

from config import (
    ENABLE_DESKTOP_NOTIFICATIONS,
    NOTIFICATION_TIMEOUT,
    NOTIFY_ON_NEW_DEVICE,
    NOTIFY_ON_CRITICAL_ALERT,
)

logger = logging.getLogger(__name__)


class Notifier:
    """Desktop notification manager."""

    def __init__(self, enabled: bool = ENABLE_DESKTOP_NOTIFICATIONS):
        """
        Initialize notifier.

        Args:
            enabled: Enable desktop notifications
        """
        self.enabled = enabled
        self._check_notify_send()

    def _check_notify_send(self) -> bool:
        """
        Check if notify-send is available.

        Returns:
            True if notify-send is available
        """
        if not self.enabled:
            return False

        try:
            result = subprocess.run(
                ["which", "notify-send"],
                capture_output=True,
                timeout=2,
            )
            if result.returncode == 0:
                logger.debug("notify-send is available")
                return True
            else:
                logger.warning("notify-send not found, disabling notifications")
                self.enabled = False
                return False
        except Exception as e:
            logger.warning(f"Error checking for notify-send: {e}")
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
        """
        Send a desktop notification.

        Args:
            title: Notification title
            message: Notification message
            urgency: Urgency level ('low', 'normal', 'critical')
            timeout: Timeout in milliseconds
            icon: Icon name or path

        Returns:
            True if notification was sent successfully
        """
        if not self.enabled:
            logger.debug("Notifications disabled, skipping")
            return False

        try:
            cmd = [
                "notify-send",
                title,
                message,
                f"--urgency={urgency}",
                f"--expire-time={timeout}",
            ]

            if icon:
                cmd.extend([f"--icon={icon}"])
            else:
                # Default icon for network notifications
                cmd.extend(["--icon=network-wired"])

            result = subprocess.run(
                cmd,
                capture_output=True,
                timeout=5,
            )

            if result.returncode == 0:
                logger.debug(f"Notification sent: {title}")
                return True
            else:
                logger.warning(f"Failed to send notification: {result.stderr.decode()}")
                return False

        except subprocess.TimeoutExpired:
            logger.error("Notification command timed out")
            return False
        except Exception as e:
            logger.error(f"Error sending notification: {e}")
            return False

    def notify_new_device(self, ip: str, mac: str, hostname: Optional[str] = None) -> bool:
        """
        Send notification for new device detection.

        Args:
            ip: Device IP address
            mac: Device MAC address
            hostname: Device hostname

        Returns:
            True if notification was sent
        """
        if not NOTIFY_ON_NEW_DEVICE:
            return False

        device_name = hostname or ip
        message = f"IP: {ip}\nMAC: {mac}"

        return self.send_notification(
            title=f"New Device Detected: {device_name}",
            message=message,
            urgency="normal",
            icon="network-wired",
        )

    def notify_device_offline(self, ip: str, hostname: Optional[str] = None) -> bool:
        """
        Send notification when device goes offline.

        Args:
            ip: Device IP address
            hostname: Device hostname

        Returns:
            True if notification was sent
        """
        device_name = hostname or ip

        return self.send_notification(
            title=f"Device Offline: {device_name}",
            message=f"{device_name} is no longer responding",
            urgency="low",
            icon="network-offline",
        )

    def notify_critical_alert(self, title: str, message: str, command: Optional[str] = None) -> bool:
        """
        Send notification for critical security alert.

        Args:
            title: Alert title
            message: Alert message
            command: Recommended command

        Returns:
            True if notification was sent
        """
        if not NOTIFY_ON_CRITICAL_ALERT:
            return False

        full_message = message
        if command:
            full_message += f"\n\nRecommended: {command}"

        return self.send_notification(
            title=f"🔒 Security Alert: {title}",
            message=full_message,
            urgency="critical",
            timeout=10000,  # 10 seconds for critical alerts
            icon="dialog-warning",
        )

    def notify_wifi_issue(self, issue: str, signal_strength: Optional[int] = None) -> bool:
        """
        Send notification for WiFi issues.

        Args:
            issue: Issue description
            signal_strength: Current signal strength in dBm

        Returns:
            True if notification was sent
        """
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
        """
        Send notification when scan completes.

        Args:
            device_count: Total devices found
            new_devices: Number of new devices

        Returns:
            True if notification was sent
        """
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
        """
        Send custom notification.

        Args:
            title: Notification title
            message: Notification message
            urgency: Urgency level
            icon: Icon name

        Returns:
            True if notification was sent
        """
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
