"""
Unit tests for the notifier module.
"""

import smtplib
import subprocess
import sys
from unittest.mock import MagicMock, Mock, patch

import pytest

# Ensure the netmondash directory is importable
sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parent.parent))

from modules.notifier import Notifier


# ---- Helpers ----------------------------------------------------------------


def _make_notifier(enabled=True, notify_send_available=True):
    """
    Create a Notifier with a mocked _check_notify_send subprocess call.

    Args:
        enabled: Whether notifications are enabled.
        notify_send_available: Whether notify-send is found on the system.

    Returns:
        A Notifier instance.
    """
    mock_result = MagicMock()
    mock_result.returncode = 0 if notify_send_available else 1

    with patch("modules.notifier.subprocess.run", return_value=mock_result):
        notifier = Notifier(enabled=enabled)

    return notifier


# ---- Notifier Initialization ------------------------------------------------


class TestNotifierInit:
    """Tests for Notifier initialization."""

    @patch("modules.notifier.subprocess.run")
    def test_init_enabled_and_notify_send_available(self, mock_run):
        """Enabled notifier with notify-send present stays enabled."""
        mock_run.return_value = MagicMock(returncode=0)

        notifier = Notifier(enabled=True)

        assert notifier.enabled is True
        mock_run.assert_called_once()

    @patch("modules.notifier.subprocess.run")
    def test_init_enabled_but_notify_send_missing(self, mock_run):
        """Enabled notifier without notify-send becomes disabled."""
        mock_run.return_value = MagicMock(returncode=1)

        notifier = Notifier(enabled=True)

        assert notifier.enabled is False

    @patch("modules.notifier.subprocess.run")
    def test_init_disabled_skips_check(self, mock_run):
        """Disabled notifier never runs the which check."""
        notifier = Notifier(enabled=False)

        assert notifier.enabled is False
        mock_run.assert_not_called()

    @patch(
        "modules.notifier.subprocess.run",
        side_effect=FileNotFoundError("which not found"),
    )
    def test_init_exception_disables_notifier(self, mock_run):
        """An exception during the check disables the notifier."""
        notifier = Notifier(enabled=True)

        assert notifier.enabled is False


# ---- _check_notify_send -----------------------------------------------------


class TestCheckNotifySend:
    """Tests for _check_notify_send method."""

    def test_check_returns_false_when_disabled(self):
        """Returns False immediately when notifications are disabled."""
        notifier = _make_notifier(enabled=False)

        result = notifier._check_notify_send()

        assert result is False

    @patch("modules.notifier.subprocess.run")
    def test_check_returns_true_when_found(self, mock_run):
        """Returns True when 'which notify-send' succeeds."""
        mock_run.return_value = MagicMock(returncode=0)
        notifier = _make_notifier(enabled=True)

        result = notifier._check_notify_send()

        assert result is True
        assert notifier.enabled is True

    @patch("modules.notifier.subprocess.run")
    def test_check_returns_false_when_not_found(self, mock_run):
        """Returns False and disables when notify-send is not on PATH."""
        mock_run.return_value = MagicMock(returncode=1)
        notifier = _make_notifier(enabled=True)

        result = notifier._check_notify_send()

        assert result is False
        assert notifier.enabled is False

    @patch(
        "modules.notifier.subprocess.run",
        side_effect=subprocess.TimeoutExpired(cmd="which", timeout=2),
    )
    def test_check_timeout_disables(self, mock_run):
        """A timeout during the which check disables the notifier."""
        notifier = _make_notifier(enabled=True)

        result = notifier._check_notify_send()

        assert result is False
        assert notifier.enabled is False

    @patch(
        "modules.notifier.subprocess.run",
        side_effect=OSError("permission denied"),
    )
    def test_check_oserror_disables(self, mock_run):
        """An OSError during the which check disables the notifier."""
        notifier = _make_notifier(enabled=True)

        result = notifier._check_notify_send()

        assert result is False
        assert notifier.enabled is False


# ---- send_notification -------------------------------------------------------


class TestSendNotification:
    """Tests for send_notification method."""

    @patch("modules.notifier.subprocess.run")
    def test_send_success(self, mock_run):
        """Successful notification returns True."""
        mock_run.return_value = MagicMock(returncode=0)
        notifier = _make_notifier(enabled=True)

        result = notifier.send_notification("Title", "Body")

        assert result is True
        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        assert cmd[0] == "notify-send"
        assert "Title" in cmd
        assert "Body" in cmd

    @patch("modules.notifier.subprocess.run")
    def test_send_includes_urgency_and_timeout(self, mock_run):
        """Command includes --urgency and --expire-time flags."""
        mock_run.return_value = MagicMock(returncode=0)
        notifier = _make_notifier(enabled=True)

        notifier.send_notification("T", "M", urgency="critical", timeout=8000)

        cmd = mock_run.call_args[0][0]
        assert "--urgency=critical" in cmd
        assert "--expire-time=8000" in cmd

    @patch("modules.notifier.subprocess.run")
    def test_send_with_custom_icon(self, mock_run):
        """Custom icon is passed in the command."""
        mock_run.return_value = MagicMock(returncode=0)
        notifier = _make_notifier(enabled=True)

        notifier.send_notification("T", "M", icon="dialog-error")

        cmd = mock_run.call_args[0][0]
        assert "--icon=dialog-error" in cmd

    @patch("modules.notifier.subprocess.run")
    def test_send_without_icon_uses_default(self, mock_run):
        """When no icon is given the default network-wired icon is used."""
        mock_run.return_value = MagicMock(returncode=0)
        notifier = _make_notifier(enabled=True)

        notifier.send_notification("T", "M")

        cmd = mock_run.call_args[0][0]
        assert "--icon=network-wired" in cmd

    @patch("modules.notifier.subprocess.run")
    def test_send_failure_nonzero_return(self, mock_run):
        """Non-zero return code from notify-send returns False."""
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stderr = b"something went wrong"
        mock_run.return_value = mock_result

        notifier = _make_notifier(enabled=True)

        result = notifier.send_notification("T", "M")

        assert result is False

    @patch(
        "modules.notifier.subprocess.run",
        side_effect=subprocess.TimeoutExpired(cmd="notify-send", timeout=5),
    )
    def test_send_timeout_returns_false(self, mock_run):
        """A timeout during send returns False."""
        notifier = _make_notifier(enabled=True)

        result = notifier.send_notification("T", "M")

        assert result is False

    @patch(
        "modules.notifier.subprocess.run",
        side_effect=RuntimeError("unexpected"),
    )
    def test_send_exception_returns_false(self, mock_run):
        """An unexpected exception during send returns False."""
        notifier = _make_notifier(enabled=True)

        result = notifier.send_notification("T", "M")

        assert result is False

    def test_send_when_disabled_returns_false(self):
        """Disabled notifier short-circuits without calling subprocess."""
        notifier = _make_notifier(enabled=False)

        with patch("modules.notifier.subprocess.run") as mock_run:
            result = notifier.send_notification("T", "M")

        assert result is False
        mock_run.assert_not_called()


# ---- notify_new_device -------------------------------------------------------


class TestNotifyNewDevice:
    """Tests for notify_new_device method."""

    @patch("modules.notifier.subprocess.run")
    def test_new_device_with_hostname(self, mock_run):
        """Notification title uses hostname when provided."""
        mock_run.return_value = MagicMock(returncode=0)
        notifier = _make_notifier(enabled=True)

        with patch("modules.notifier.NOTIFY_ON_NEW_DEVICE", True):
            result = notifier.notify_new_device(
                ip="192.168.1.50",
                mac="AA:BB:CC:DD:EE:FF",
                hostname="my-laptop",
            )

        assert result is True
        cmd = mock_run.call_args[0][0]
        # Title should contain the hostname
        assert any("my-laptop" in arg for arg in cmd)

    @patch("modules.notifier.subprocess.run")
    def test_new_device_without_hostname(self, mock_run):
        """Notification title falls back to IP when no hostname is given."""
        mock_run.return_value = MagicMock(returncode=0)
        notifier = _make_notifier(enabled=True)

        with patch("modules.notifier.NOTIFY_ON_NEW_DEVICE", True):
            result = notifier.notify_new_device(
                ip="10.0.0.5",
                mac="11:22:33:44:55:66",
            )

        assert result is True
        cmd = mock_run.call_args[0][0]
        assert any("10.0.0.5" in arg for arg in cmd)

    @patch("modules.notifier.subprocess.run")
    def test_new_device_message_contains_mac(self, mock_run):
        """The notification body contains the MAC address."""
        mock_run.return_value = MagicMock(returncode=0)
        notifier = _make_notifier(enabled=True)

        with patch("modules.notifier.NOTIFY_ON_NEW_DEVICE", True):
            notifier.notify_new_device(
                ip="192.168.1.50",
                mac="AA:BB:CC:DD:EE:FF",
            )

        cmd = mock_run.call_args[0][0]
        # The message (second positional arg) should contain the MAC
        assert any("AA:BB:CC:DD:EE:FF" in arg for arg in cmd)

    def test_new_device_disabled_by_config(self):
        """Returns False when NOTIFY_ON_NEW_DEVICE is False."""
        notifier = _make_notifier(enabled=True)

        with patch("modules.notifier.NOTIFY_ON_NEW_DEVICE", False):
            result = notifier.notify_new_device(
                ip="192.168.1.1",
                mac="00:00:00:00:00:00",
            )

        assert result is False


# ---- notify_device_offline ---------------------------------------------------


class TestNotifyDeviceOffline:
    """Tests for notify_device_offline method."""

    @patch("modules.notifier.subprocess.run")
    def test_offline_with_hostname(self, mock_run):
        """Notification uses hostname in both title and body."""
        mock_run.return_value = MagicMock(returncode=0)
        notifier = _make_notifier(enabled=True)

        result = notifier.notify_device_offline(
            ip="192.168.1.10",
            hostname="server-01",
        )

        assert result is True
        cmd = mock_run.call_args[0][0]
        assert any("server-01" in arg for arg in cmd)

    @patch("modules.notifier.subprocess.run")
    def test_offline_without_hostname(self, mock_run):
        """Notification falls back to IP when no hostname is given."""
        mock_run.return_value = MagicMock(returncode=0)
        notifier = _make_notifier(enabled=True)

        result = notifier.notify_device_offline(ip="10.0.0.1")

        assert result is True
        cmd = mock_run.call_args[0][0]
        assert any("10.0.0.1" in arg for arg in cmd)

    @patch("modules.notifier.subprocess.run")
    def test_offline_uses_low_urgency(self, mock_run):
        """Device-offline notifications have 'low' urgency."""
        mock_run.return_value = MagicMock(returncode=0)
        notifier = _make_notifier(enabled=True)

        notifier.notify_device_offline(ip="192.168.1.1")

        cmd = mock_run.call_args[0][0]
        assert "--urgency=low" in cmd

    @patch("modules.notifier.subprocess.run")
    def test_offline_uses_network_offline_icon(self, mock_run):
        """Device-offline notification uses the network-offline icon."""
        mock_run.return_value = MagicMock(returncode=0)
        notifier = _make_notifier(enabled=True)

        notifier.notify_device_offline(ip="192.168.1.1")

        cmd = mock_run.call_args[0][0]
        assert "--icon=network-offline" in cmd


# ---- notify_critical_alert ---------------------------------------------------


class TestNotifyCriticalAlert:
    """Tests for notify_critical_alert method."""

    @patch("modules.notifier.subprocess.run")
    def test_critical_alert_basic(self, mock_run):
        """Critical alert sends with critical urgency."""
        mock_run.return_value = MagicMock(returncode=0)
        notifier = _make_notifier(enabled=True)

        with patch("modules.notifier.NOTIFY_ON_CRITICAL_ALERT", True):
            result = notifier.notify_critical_alert(
                title="Intrusion detected",
                message="Unknown device probing ports",
            )

        assert result is True
        cmd = mock_run.call_args[0][0]
        assert "--urgency=critical" in cmd
        assert "--icon=dialog-warning" in cmd

    @patch("modules.notifier.subprocess.run")
    def test_critical_alert_with_command(self, mock_run):
        """The recommended command is appended to the message body."""
        mock_run.return_value = MagicMock(returncode=0)
        notifier = _make_notifier(enabled=True)

        with patch("modules.notifier.NOTIFY_ON_CRITICAL_ALERT", True):
            notifier.notify_critical_alert(
                title="Suspicious traffic",
                message="Port scan detected",
                command="sudo ufw deny from 10.0.0.99",
            )

        cmd = mock_run.call_args[0][0]
        # The message arg should contain the command text
        assert any("sudo ufw deny from 10.0.0.99" in arg for arg in cmd)

    @patch("modules.notifier.subprocess.run")
    def test_critical_alert_without_command(self, mock_run):
        """No command text in the message when command is None."""
        mock_run.return_value = MagicMock(returncode=0)
        notifier = _make_notifier(enabled=True)

        with patch("modules.notifier.NOTIFY_ON_CRITICAL_ALERT", True):
            notifier.notify_critical_alert(
                title="Alert",
                message="Something happened",
            )

        cmd = mock_run.call_args[0][0]
        assert not any("Recommended" in arg for arg in cmd)

    @patch("modules.notifier.subprocess.run")
    def test_critical_alert_uses_10s_timeout(self, mock_run):
        """Critical alerts use a 10 000 ms timeout."""
        mock_run.return_value = MagicMock(returncode=0)
        notifier = _make_notifier(enabled=True)

        with patch("modules.notifier.NOTIFY_ON_CRITICAL_ALERT", True):
            notifier.notify_critical_alert(title="A", message="B")

        cmd = mock_run.call_args[0][0]
        assert "--expire-time=10000" in cmd

    def test_critical_alert_disabled_by_config(self):
        """Returns False when NOTIFY_ON_CRITICAL_ALERT is False."""
        notifier = _make_notifier(enabled=True)

        with patch("modules.notifier.NOTIFY_ON_CRITICAL_ALERT", False):
            result = notifier.notify_critical_alert(
                title="Alert",
                message="Something happened",
            )

        assert result is False


# ---- notify_wifi_issue -------------------------------------------------------


class TestNotifyWifiIssue:
    """Tests for notify_wifi_issue method."""

    @patch("modules.notifier.subprocess.run")
    def test_wifi_issue_basic(self, mock_run):
        """WiFi issue notification includes the issue description."""
        mock_run.return_value = MagicMock(returncode=0)
        notifier = _make_notifier(enabled=True)

        result = notifier.notify_wifi_issue(issue="Frequent disconnections")

        assert result is True
        cmd = mock_run.call_args[0][0]
        assert any("Frequent disconnections" in arg for arg in cmd)
        assert any("WiFi Issue" in arg for arg in cmd)

    @patch("modules.notifier.subprocess.run")
    def test_wifi_issue_with_signal_strength(self, mock_run):
        """Signal strength is appended to the message when provided."""
        mock_run.return_value = MagicMock(returncode=0)
        notifier = _make_notifier(enabled=True)

        notifier.notify_wifi_issue(issue="Weak signal", signal_strength=-78)

        cmd = mock_run.call_args[0][0]
        assert any("-78 dBm" in arg for arg in cmd)

    @patch("modules.notifier.subprocess.run")
    def test_wifi_issue_without_signal_strength(self, mock_run):
        """No signal line in the message when signal_strength is None."""
        mock_run.return_value = MagicMock(returncode=0)
        notifier = _make_notifier(enabled=True)

        notifier.notify_wifi_issue(issue="Channel congestion")

        cmd = mock_run.call_args[0][0]
        assert not any("dBm" in arg for arg in cmd)

    @patch("modules.notifier.subprocess.run")
    def test_wifi_issue_uses_wireless_icon(self, mock_run):
        """WiFi notifications use the network-wireless icon."""
        mock_run.return_value = MagicMock(returncode=0)
        notifier = _make_notifier(enabled=True)

        notifier.notify_wifi_issue(issue="Interference")

        cmd = mock_run.call_args[0][0]
        assert "--icon=network-wireless" in cmd


# ---- notify_scan_complete ----------------------------------------------------


class TestNotifyScanComplete:
    """Tests for notify_scan_complete method."""

    @patch("modules.notifier.subprocess.run")
    def test_scan_complete_with_new_devices(self, mock_run):
        """When new_devices > 0, message mentions new devices and urgency is normal."""
        mock_run.return_value = MagicMock(returncode=0)
        notifier = _make_notifier(enabled=True)

        result = notifier.notify_scan_complete(device_count=12, new_devices=3)

        assert result is True
        cmd = mock_run.call_args[0][0]
        assert any("12" in arg and "3 new" in arg for arg in cmd)
        assert "--urgency=normal" in cmd

    @patch("modules.notifier.subprocess.run")
    def test_scan_complete_no_new_devices(self, mock_run):
        """When new_devices == 0, urgency is low and no 'new' text appears."""
        mock_run.return_value = MagicMock(returncode=0)
        notifier = _make_notifier(enabled=True)

        result = notifier.notify_scan_complete(device_count=8, new_devices=0)

        assert result is True
        cmd = mock_run.call_args[0][0]
        assert "--urgency=low" in cmd
        # Message should say "Found 8 devices" without "(X new)"
        message_args = [arg for arg in cmd if "8" in arg and "devices" in arg]
        assert len(message_args) == 1
        assert "new" not in message_args[0]

    @patch("modules.notifier.subprocess.run")
    def test_scan_complete_uses_3s_timeout(self, mock_run):
        """Scan-complete notifications use a 3 000 ms timeout."""
        mock_run.return_value = MagicMock(returncode=0)
        notifier = _make_notifier(enabled=True)

        notifier.notify_scan_complete(device_count=5)

        cmd = mock_run.call_args[0][0]
        assert "--expire-time=3000" in cmd

    @patch("modules.notifier.subprocess.run")
    def test_scan_complete_uses_network_wired_icon(self, mock_run):
        """Scan-complete uses the network-wired icon."""
        mock_run.return_value = MagicMock(returncode=0)
        notifier = _make_notifier(enabled=True)

        notifier.notify_scan_complete(device_count=1)

        cmd = mock_run.call_args[0][0]
        assert "--icon=network-wired" in cmd

    @patch("modules.notifier.subprocess.run")
    def test_scan_complete_title(self, mock_run):
        """Title is 'Network Scan Complete'."""
        mock_run.return_value = MagicMock(returncode=0)
        notifier = _make_notifier(enabled=True)

        notifier.notify_scan_complete(device_count=5)

        cmd = mock_run.call_args[0][0]
        assert "Network Scan Complete" in cmd


# ---- notify_custom -----------------------------------------------------------


class TestNotifyCustom:
    """Tests for notify_custom method."""

    @patch("modules.notifier.subprocess.run")
    def test_custom_with_icon(self, mock_run):
        """Custom notification uses the provided icon."""
        mock_run.return_value = MagicMock(returncode=0)
        notifier = _make_notifier(enabled=True)

        result = notifier.notify_custom(
            title="Custom Title",
            message="Custom Body",
            icon="my-icon",
        )

        assert result is True
        cmd = mock_run.call_args[0][0]
        assert "--icon=my-icon" in cmd

    @patch("modules.notifier.subprocess.run")
    def test_custom_without_icon_uses_default(self, mock_run):
        """When no icon is supplied, dialog-information is used."""
        mock_run.return_value = MagicMock(returncode=0)
        notifier = _make_notifier(enabled=True)

        notifier.notify_custom(title="T", message="M")

        cmd = mock_run.call_args[0][0]
        assert "--icon=dialog-information" in cmd

    @patch("modules.notifier.subprocess.run")
    def test_custom_urgency(self, mock_run):
        """The urgency parameter is forwarded correctly."""
        mock_run.return_value = MagicMock(returncode=0)
        notifier = _make_notifier(enabled=True)

        notifier.notify_custom(title="T", message="M", urgency="low")

        cmd = mock_run.call_args[0][0]
        assert "--urgency=low" in cmd

    @patch("modules.notifier.subprocess.run")
    def test_custom_passes_title_and_message(self, mock_run):
        """Title and message appear in the subprocess command."""
        mock_run.return_value = MagicMock(returncode=0)
        notifier = _make_notifier(enabled=True)

        notifier.notify_custom(title="Hello", message="World")

        cmd = mock_run.call_args[0][0]
        assert "Hello" in cmd
        assert "World" in cmd


# ---- Integration-style edge cases -------------------------------------------


class TestEdgeCases:
    """Additional edge-case tests."""

    def test_disabled_notifier_all_methods_return_false(self):
        """Every public notification method returns False when disabled."""
        notifier = _make_notifier(enabled=False)

        with patch("modules.notifier.NOTIFY_ON_NEW_DEVICE", True), \
             patch("modules.notifier.NOTIFY_ON_CRITICAL_ALERT", True):
            assert notifier.send_notification("T", "M") is False
            assert notifier.notify_new_device("1.2.3.4", "AA:BB:CC:DD:EE:FF") is False
            assert notifier.notify_device_offline("1.2.3.4") is False
            assert notifier.notify_critical_alert("T", "M") is False
            assert notifier.notify_wifi_issue("issue") is False
            assert notifier.notify_scan_complete(5) is False
            assert notifier.notify_custom("T", "M") is False

    @patch("modules.notifier.subprocess.run")
    def test_send_notification_called_with_capture_output_and_timeout(self, mock_run):
        """subprocess.run is called with capture_output=True and timeout=5."""
        mock_run.return_value = MagicMock(returncode=0)
        notifier = _make_notifier(enabled=True)

        notifier.send_notification("T", "M")

        _, kwargs = mock_run.call_args
        assert kwargs["capture_output"] is True
        assert kwargs["timeout"] == 5

    @patch("modules.notifier.subprocess.run")
    def test_check_notify_send_called_with_which(self, mock_run):
        """_check_notify_send invokes 'which notify-send'."""
        mock_run.return_value = MagicMock(returncode=0)
        notifier = _make_notifier(enabled=True)

        notifier._check_notify_send()

        cmd = mock_run.call_args[0][0]
        assert cmd == ["which", "notify-send"]

    @patch("modules.notifier.subprocess.run")
    def test_check_notify_send_uses_timeout_2(self, mock_run):
        """_check_notify_send passes timeout=2 to subprocess.run."""
        mock_run.return_value = MagicMock(returncode=0)
        notifier = _make_notifier(enabled=True)

        notifier._check_notify_send()

        _, kwargs = mock_run.call_args
        assert kwargs["timeout"] == 2


# ---- Backend classes --------------------------------------------------------


from modules.notifier import (
    NotifierBackend,
    DesktopBackend,
    WebhookBackend,
    EmailBackend,
)


class TestDesktopBackend:
    """Tests for the DesktopBackend class."""

    @patch("modules.notifier.subprocess.run")
    def test_available_when_notify_send_found(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0)
        backend = DesktopBackend()
        assert backend.available is True

    @patch("modules.notifier.subprocess.run")
    def test_unavailable_when_notify_send_missing(self, mock_run):
        mock_run.return_value = MagicMock(returncode=1)
        backend = DesktopBackend()
        assert backend.available is False

    @patch("modules.notifier.subprocess.run")
    def test_send_returns_false_when_unavailable(self, mock_run):
        mock_run.return_value = MagicMock(returncode=1)
        backend = DesktopBackend()
        assert backend.send("T", "M") is False

    @patch("modules.notifier.subprocess.run")
    def test_send_success(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0)
        backend = DesktopBackend()
        result = backend.send("Title", "Body", urgency="normal", icon="test-icon")
        assert result is True

    @patch("modules.notifier.subprocess.run")
    def test_send_includes_correct_args(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0)
        backend = DesktopBackend()
        backend.send("T", "M", urgency="critical", timeout=5000, icon="my-icon")
        cmd = mock_run.call_args[0][0]
        assert "notify-send" == cmd[0]
        assert "--urgency=critical" in cmd
        assert "--expire-time=5000" in cmd
        assert "--icon=my-icon" in cmd


class TestWebhookBackend:
    """Tests for the WebhookBackend class."""

    def test_detect_slack(self):
        assert WebhookBackend._detect_service("https://hooks.slack.com/services/XXX") == "slack"

    def test_detect_discord(self):
        assert WebhookBackend._detect_service("https://discord.com/api/webhooks/123/abc") == "discord"

    def test_detect_teams(self):
        assert WebhookBackend._detect_service("https://webhook.office.com/xxx") == "teams"

    def test_detect_generic(self):
        assert WebhookBackend._detect_service("https://example.com/hook") == "generic"

    def test_build_slack_payload(self):
        backend = WebhookBackend("https://hooks.slack.com/services/XXX")
        payload = backend._build_payload("Title", "Body", "critical")
        assert "attachments" in payload
        assert payload["attachments"][0]["title"] == "Title"
        assert payload["attachments"][0]["color"] == "#ff0000"

    def test_build_discord_payload(self):
        backend = WebhookBackend("https://discord.com/api/webhooks/123/abc")
        payload = backend._build_payload("Title", "Body", "normal")
        assert "embeds" in payload
        assert payload["embeds"][0]["title"] == "Title"

    def test_build_teams_payload(self):
        backend = WebhookBackend("https://webhook.office.com/xxx")
        payload = backend._build_payload("Title", "Body", "low")
        assert payload["@type"] == "MessageCard"
        assert payload["sections"][0]["activityTitle"] == "Title"

    def test_build_generic_payload(self):
        backend = WebhookBackend("https://example.com/hook")
        payload = backend._build_payload("Title", "Body", "normal")
        assert payload["title"] == "Title"
        assert payload["message"] == "Body"
        assert payload["source"] == "NetMonDash"

    @patch("modules.notifier.requests.post")
    def test_send_success(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_post.return_value = mock_resp

        backend = WebhookBackend("https://example.com/hook")
        assert backend.send("Title", "Body") is True
        mock_post.assert_called_once()

    @patch("modules.notifier.requests.post")
    def test_send_failure_status(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_resp.text = "Internal Server Error"
        mock_post.return_value = mock_resp

        backend = WebhookBackend("https://example.com/hook")
        assert backend.send("Title", "Body") is False

    @patch("modules.notifier.requests.post", side_effect=Exception("Network error"))
    def test_send_exception(self, mock_post):
        backend = WebhookBackend("https://example.com/hook")
        assert backend.send("Title", "Body") is False

    def test_custom_headers(self):
        backend = WebhookBackend(
            "https://example.com/hook",
            headers={"Authorization": "Bearer token123"},
        )
        assert "Authorization" in backend.headers
        assert backend.headers["Authorization"] == "Bearer token123"

    def test_force_service_type(self):
        backend = WebhookBackend("https://example.com/hook", service="slack")
        assert backend.service == "slack"


class TestEmailBackend:
    """Tests for the EmailBackend class."""

    def test_no_recipients_returns_false(self):
        backend = EmailBackend("smtp.example.com", recipients=[])
        assert backend.send("Title", "Body") is False

    @patch("modules.notifier.smtplib.SMTP")
    def test_send_success(self, mock_smtp_class):
        mock_server = MagicMock()
        mock_smtp_class.return_value.__enter__ = Mock(return_value=mock_server)
        mock_smtp_class.return_value.__exit__ = Mock(return_value=False)

        backend = EmailBackend(
            "smtp.example.com",
            smtp_port=587,
            username="user@example.com",
            password="pass123",
            recipients=["admin@example.com"],
        )
        result = backend.send("Alert", "Something happened", urgency="critical")
        assert result is True
        mock_server.starttls.assert_called_once()
        mock_server.login.assert_called_once_with("user@example.com", "pass123")
        mock_server.sendmail.assert_called_once()

    @patch("modules.notifier.smtplib.SMTP", side_effect=smtplib.SMTPException("Connection refused"))
    def test_send_smtp_error(self, mock_smtp_class):
        backend = EmailBackend(
            "smtp.example.com",
            recipients=["admin@example.com"],
        )
        assert backend.send("Title", "Body") is False

    def test_from_addr_defaults_to_username(self):
        backend = EmailBackend("smtp.example.com", username="user@test.com")
        assert backend.from_addr == "user@test.com"

    def test_from_addr_override(self):
        backend = EmailBackend(
            "smtp.example.com",
            username="user@test.com",
            from_addr="noreply@test.com",
        )
        assert backend.from_addr == "noreply@test.com"


class TestNotifierMultiBackend:
    """Tests for using multiple backends with the Notifier."""

    def test_notifier_with_custom_backends(self):
        mock_backend1 = MagicMock(spec=NotifierBackend)
        mock_backend1.send.return_value = True
        mock_backend2 = MagicMock(spec=NotifierBackend)
        mock_backend2.send.return_value = True

        notifier = Notifier(enabled=True, backends=[mock_backend1, mock_backend2])

        with patch("modules.notifier.NOTIFY_ON_NEW_DEVICE", True):
            result = notifier.notify_new_device("192.168.1.1", "AA:BB:CC:DD:EE:FF")

        assert result is True
        mock_backend1.send.assert_called_once()
        mock_backend2.send.assert_called_once()

    def test_notifier_one_backend_fails_others_still_called(self):
        mock_good = MagicMock(spec=NotifierBackend)
        mock_good.send.return_value = True
        mock_bad = MagicMock(spec=NotifierBackend)
        mock_bad.send.return_value = False

        notifier = Notifier(enabled=True, backends=[mock_bad, mock_good])
        result = notifier.send_notification("T", "M")

        assert result is True  # At least one succeeded
        mock_bad.send.assert_called_once()
        mock_good.send.assert_called_once()

    def test_notifier_all_backends_fail(self):
        mock_bad = MagicMock(spec=NotifierBackend)
        mock_bad.send.return_value = False

        notifier = Notifier(enabled=True, backends=[mock_bad])
        result = notifier.send_notification("T", "M")
        assert result is False

    def test_notifier_backend_exception_doesnt_crash(self):
        mock_bad = MagicMock(spec=NotifierBackend)
        mock_bad.send.side_effect = RuntimeError("Boom!")
        mock_good = MagicMock(spec=NotifierBackend)
        mock_good.send.return_value = True

        notifier = Notifier(enabled=True, backends=[mock_bad, mock_good])
        result = notifier.send_notification("T", "M")

        # Good backend still runs despite bad one crashing
        assert result is True
        mock_good.send.assert_called_once()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
