"""
Comprehensive unit tests for the AI Analyzer module.

Tests AIRecommendation, AIAnalyzer initialization, Ollama connectivity,
response parsing, rule-based analysis, anomaly detection, security scoring,
quick insights, health analysis, WiFi analysis, fallback behaviour, and
comprehensive analysis.
"""

import json
import sys
import time

import pytest
from unittest.mock import Mock, patch, MagicMock, PropertyMock

# Ensure the netmondash package root is importable
sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parent.parent))

from modules.ai_analyzer import (
    AIAnalyzer,
    AIRecommendation,
    DANGEROUS_PORTS,
    EXPECTED_GATEWAY_PORTS,
    RISKY_COMBINATIONS,
)
from config import SEVERITY_CRITICAL, SEVERITY_WARNING, SEVERITY_INFO


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_session():
    """Patch requests.Session so AIAnalyzer.__init__ never hits the network."""
    with patch("modules.ai_analyzer.requests.Session") as mock_cls:
        session_instance = MagicMock()
        # Default: connection check fails (Ollama offline)
        response = MagicMock()
        response.status_code = 200
        session_instance.get.return_value = response
        mock_cls.return_value = session_instance
        yield session_instance


@pytest.fixture
def analyzer(mock_session):
    """Return an AIAnalyzer whose initial connection check succeeds."""
    return AIAnalyzer(api_url="http://localhost:11434", model="test-model")


@pytest.fixture
def offline_analyzer():
    """Return an AIAnalyzer that believes Ollama is offline."""
    import requests as req_lib

    with patch("modules.ai_analyzer.requests.Session") as mock_cls:
        session_instance = MagicMock()
        session_instance.get.side_effect = req_lib.exceptions.ConnectionError(
            "connection refused"
        )
        mock_cls.return_value = session_instance
        a = AIAnalyzer(api_url="http://localhost:11434", model="test-model")
    # Force offline and pin the timestamp so the cache does not expire
    a._ollama_available = False
    a._last_availability_check = time.time()
    return a


@pytest.fixture
def clean_scan_data():
    """Scan data with no issues -- all ports safe, vendors known."""
    return {
        "device_count": 2,
        "gateway": "192.168.1.1",
        "devices": [
            {
                "ip": "192.168.1.1",
                "mac": "00:11:22:33:44:55",
                "hostname": "router",
                "vendor": "Netgear",
                "open_ports": [80, 443],
            },
            {
                "ip": "192.168.1.10",
                "mac": "AA:BB:CC:DD:EE:FF",
                "hostname": "laptop",
                "vendor": "Dell",
                "open_ports": [22],
            },
        ],
    }


@pytest.fixture
def risky_scan_data():
    """Scan data with a variety of security issues."""
    return {
        "device_count": 4,
        "gateway": "192.168.1.1",
        "devices": [
            {
                "ip": "192.168.1.1",
                "mac": "00:11:22:33:44:55",
                "hostname": "router",
                "vendor": "Netgear",
                "open_ports": [80, 443, 23],  # telnet on gateway
            },
            {
                "ip": "192.168.1.100",
                "mac": "AA:BB:CC:DD:EE:FF",
                "hostname": "unknown",
                "vendor": None,  # unknown vendor
                "open_ports": [21, 22, 23, 3389],  # dangerous ports + combo
            },
            {
                "ip": "192.168.1.101",
                "mac": "11:22:33:44:55:66",
                "hostname": "fileserver",
                "vendor": "Dell",
                # > 10 ports + risky combinations (139+445)
                "open_ports": [
                    22, 80, 443, 139, 445, 3306, 8080,
                    1000, 1001, 1002, 1003,
                ],
            },
            {
                "ip": "192.168.1.102",
                "mac": "22:33:44:55:66:77",
                "hostname": "workstation",
                "vendor": "Lenovo",
                "open_ports": [5900, 3389],  # VNC + RDP combo
            },
        ],
    }


# =========================================================================
# 1. AIRecommendation tests
# =========================================================================


class TestAIRecommendation:
    """Tests for the AIRecommendation data class."""

    def test_to_dict_all_fields(self):
        rec = AIRecommendation(
            severity=SEVERITY_CRITICAL,
            description="Test description",
            recommendation="Test recommendation",
            command="nmap -sV 192.168.1.1",
            category="security",
        )
        d = rec.to_dict()
        assert d == {
            "severity": SEVERITY_CRITICAL,
            "description": "Test description",
            "recommendation": "Test recommendation",
            "command": "nmap -sV 192.168.1.1",
            "category": "security",
        }

    def test_to_dict_no_command(self):
        rec = AIRecommendation(
            severity=SEVERITY_INFO,
            description="Desc",
            recommendation="Rec",
        )
        d = rec.to_dict()
        assert d["command"] is None
        assert d["category"] == "general"

    def test_repr_short_description(self):
        rec = AIRecommendation(
            severity=SEVERITY_WARNING,
            description="Short",
            recommendation="Rec",
        )
        r = repr(rec)
        assert "[warning]" in r.lower()
        assert "Short" in r

    def test_repr_long_description_is_truncated(self):
        long_desc = "A" * 100
        rec = AIRecommendation(
            severity=SEVERITY_CRITICAL,
            description=long_desc,
            recommendation="Rec",
        )
        r = repr(rec)
        # __repr__ truncates at 50 chars and appends "..."
        assert "..." in r
        assert len(r) < len(long_desc) + 50

    def test_default_category(self):
        rec = AIRecommendation(
            severity=SEVERITY_INFO,
            description="d",
            recommendation="r",
        )
        assert rec.category == "general"


# =========================================================================
# 2. AIAnalyzer initialisation
# =========================================================================


class TestAIAnalyzerInit:
    """Tests for AIAnalyzer construction."""

    def test_init_strips_trailing_slash(self, mock_session):
        a = AIAnalyzer(api_url="http://localhost:11434/", model="m")
        assert a.api_url == "http://localhost:11434"

    def test_init_stores_model(self, mock_session):
        a = AIAnalyzer(api_url="http://localhost:11434", model="custom-model")
        assert a.model == "custom-model"

    def test_init_calls_check_connection(self, mock_session):
        """__init__ should call _check_connection once."""
        AIAnalyzer(api_url="http://localhost:11434", model="m")
        mock_session.get.assert_called_once()

    def test_init_session_created(self, mock_session):
        a = AIAnalyzer(api_url="http://localhost:11434", model="m")
        assert a.session is mock_session


# =========================================================================
# 3. _check_connection
# =========================================================================


class TestCheckConnection:
    """Tests for _check_connection."""

    def test_success(self, analyzer, mock_session):
        resp = MagicMock()
        resp.status_code = 200
        mock_session.get.return_value = resp

        result = analyzer._check_connection()

        assert result is True
        assert analyzer._ollama_available is True

    def test_non_200_status(self, analyzer, mock_session):
        resp = MagicMock()
        resp.status_code = 500
        mock_session.get.return_value = resp

        result = analyzer._check_connection()

        assert result is False
        assert analyzer._ollama_available is False

    def test_request_exception(self, analyzer, mock_session):
        import requests

        mock_session.get.side_effect = requests.exceptions.ConnectionError("refused")

        result = analyzer._check_connection()

        assert result is False
        assert analyzer._ollama_available is False

    def test_updates_timestamp(self, analyzer, mock_session):
        before = time.time()
        resp = MagicMock()
        resp.status_code = 200
        mock_session.get.return_value = resp

        analyzer._check_connection()

        assert analyzer._last_availability_check >= before


# =========================================================================
# 4. is_available property -- caching behaviour
# =========================================================================


class TestIsAvailable:
    """Tests for the is_available cached property."""

    def test_returns_cached_true(self, analyzer, mock_session):
        analyzer._ollama_available = True
        analyzer._last_availability_check = time.time()

        # Should NOT call _check_connection again (within TTL)
        mock_session.get.reset_mock()
        assert analyzer.is_available is True
        mock_session.get.assert_not_called()

    def test_returns_cached_false(self, analyzer, mock_session):
        analyzer._ollama_available = False
        analyzer._last_availability_check = time.time()

        mock_session.get.reset_mock()
        assert analyzer.is_available is False
        mock_session.get.assert_not_called()

    def test_rechecks_after_ttl_expires(self, analyzer, mock_session):
        analyzer._ollama_available = False
        # Pretend check happened long ago
        analyzer._last_availability_check = time.time() - 120

        resp = MagicMock()
        resp.status_code = 200
        mock_session.get.return_value = resp
        mock_session.get.reset_mock()

        result = analyzer.is_available

        assert result is True
        mock_session.get.assert_called_once()

    def test_rechecks_when_none(self, analyzer, mock_session):
        analyzer._ollama_available = None

        resp = MagicMock()
        resp.status_code = 200
        mock_session.get.return_value = resp
        mock_session.get.reset_mock()

        result = analyzer.is_available

        assert result is True
        mock_session.get.assert_called_once()


# =========================================================================
# 5. _call_ollama
# =========================================================================


class TestCallOllama:
    """Tests for _call_ollama with mocked HTTP."""

    def test_success_returns_response_text(self, analyzer, mock_session):
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"response": "AI says hello"}
        mock_session.post.return_value = resp

        result = analyzer._call_ollama("test prompt")

        assert result == "AI says hello"
        assert analyzer._ollama_available is True

    def test_success_with_system_prompt(self, analyzer, mock_session):
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"response": "OK"}
        mock_session.post.return_value = resp

        analyzer._call_ollama("prompt", system_prompt="system")

        call_kwargs = mock_session.post.call_args
        payload = call_kwargs[1]["json"] if "json" in call_kwargs[1] else call_kwargs.kwargs["json"]
        assert payload["system"] == "system"

    def test_no_system_prompt_key_absent(self, analyzer, mock_session):
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"response": "OK"}
        mock_session.post.return_value = resp

        analyzer._call_ollama("prompt", system_prompt=None)

        call_kwargs = mock_session.post.call_args
        payload = call_kwargs[1]["json"] if "json" in call_kwargs[1] else call_kwargs.kwargs["json"]
        assert "system" not in payload

    @patch("modules.ai_analyzer.OLLAMA_MAX_RETRIES", 3)
    @patch("modules.ai_analyzer.OLLAMA_RETRY_DELAY", 0)
    def test_timeout_retries_then_fails(self, analyzer, mock_session):
        import requests

        mock_session.post.side_effect = requests.exceptions.Timeout("timeout")

        result = analyzer._call_ollama("prompt")

        assert result is None
        assert mock_session.post.call_count == 3
        assert analyzer._ollama_available is False

    @patch("modules.ai_analyzer.OLLAMA_MAX_RETRIES", 3)
    @patch("modules.ai_analyzer.OLLAMA_RETRY_DELAY", 0)
    def test_non_200_retries(self, analyzer, mock_session):
        resp = MagicMock()
        resp.status_code = 500
        resp.text = "Internal server error"
        mock_session.post.return_value = resp

        result = analyzer._call_ollama("prompt")

        assert result is None
        assert mock_session.post.call_count == 3

    @patch("modules.ai_analyzer.OLLAMA_MAX_RETRIES", 3)
    @patch("modules.ai_analyzer.OLLAMA_RETRY_DELAY", 0)
    def test_request_exception_retries(self, analyzer, mock_session):
        import requests

        mock_session.post.side_effect = requests.exceptions.ConnectionError("down")

        result = analyzer._call_ollama("prompt")

        assert result is None
        assert mock_session.post.call_count == 3

    @patch("modules.ai_analyzer.OLLAMA_MAX_RETRIES", 3)
    @patch("modules.ai_analyzer.OLLAMA_RETRY_DELAY", 0)
    def test_json_decode_error_retries(self, analyzer, mock_session):
        resp = MagicMock()
        resp.status_code = 200
        resp.json.side_effect = json.JSONDecodeError("bad", "", 0)
        mock_session.post.return_value = resp

        result = analyzer._call_ollama("prompt")

        assert result is None

    @patch("modules.ai_analyzer.OLLAMA_MAX_RETRIES", 3)
    @patch("modules.ai_analyzer.OLLAMA_RETRY_DELAY", 0)
    def test_succeeds_on_second_attempt(self, analyzer, mock_session):
        import requests

        fail_resp = requests.exceptions.Timeout("timeout")
        ok_resp = MagicMock()
        ok_resp.status_code = 200
        ok_resp.json.return_value = {"response": "recovered"}

        mock_session.post.side_effect = [fail_resp, ok_resp]

        result = analyzer._call_ollama("prompt")

        assert result == "recovered"
        assert mock_session.post.call_count == 2

    def test_empty_response_field(self, analyzer, mock_session):
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {}  # no "response" key
        mock_session.post.return_value = resp

        result = analyzer._call_ollama("prompt")

        assert result == ""


# =========================================================================
# 6. _parse_ai_response
# =========================================================================


class TestParseAIResponse:
    """Tests for the multi-strategy JSON/text parser."""

    def test_strategy1_direct_json(self, analyzer):
        """Direct JSON parse with 'findings' key."""
        data = {
            "findings": [
                {
                    "severity": "critical",
                    "description": "Bad port",
                    "recommendation": "Close it",
                    "command": "nmap -sV host",
                }
            ]
        }
        recs = analyzer._parse_ai_response(json.dumps(data), "security")

        assert len(recs) == 1
        assert recs[0].severity == "critical"
        assert recs[0].description == "Bad port"
        assert recs[0].command == "nmap -sV host"
        assert recs[0].category == "security"

    def test_strategy2_regex_json_object(self, analyzer):
        """JSON object embedded in surrounding text."""
        text = (
            'Here is my analysis:\n'
            '{"findings": [{"severity": "warning", "description": "issue", '
            '"recommendation": "fix it"}]}\n'
            'End of analysis.'
        )
        recs = analyzer._parse_ai_response(text, "health")

        assert len(recs) == 1
        assert recs[0].severity == "warning"
        assert recs[0].category == "health"

    def test_strategy3_bare_json_array(self, analyzer):
        """Bare JSON array without outer object."""
        arr = [
            {"severity": "info", "description": "d1", "recommendation": "r1"},
            {"severity": "warning", "description": "d2", "recommendation": "r2"},
        ]
        text = f"Results: {json.dumps(arr)}"
        recs = analyzer._parse_ai_response(text, "wifi")

        assert len(recs) == 2
        assert recs[0].severity == "info"
        assert recs[1].severity == "warning"
        assert all(r.category == "wifi" for r in recs)

    def test_strategy4_individual_finding_objects(self, analyzer):
        """Individual JSON objects with 'severity' scattered in text."""
        text = (
            'Finding 1: {"severity": "critical", "description": "vuln", '
            '"recommendation": "patch"}\n'
            'Finding 2: {"severity": "info", "description": "note", '
            '"recommendation": "ok"}\n'
        )
        # Make strategies 1-3 fail by ensuring no valid outer JSON
        recs = analyzer._parse_ai_response(text, "security")

        assert len(recs) >= 2
        severities = {r.severity for r in recs}
        assert "critical" in severities
        assert "info" in severities

    def test_strategy5_text_fallback_with_critical_keywords(self, analyzer):
        """Plain text with severity keywords triggers text fallback."""
        text = (
            "This is a critical vulnerability found on the server.\n\n"
            "There is a warning about the firewall configuration.\n\n"
            "Everything else looks fine."
        )
        recs = analyzer._parse_ai_response(text, "security")

        assert len(recs) == 3
        assert recs[0].severity == SEVERITY_CRITICAL
        assert recs[1].severity == SEVERITY_WARNING
        assert recs[2].severity == SEVERITY_INFO

    def test_text_fallback_extracts_command_from_backticks(self, analyzer):
        """Text fallback should extract commands delimited by backticks."""
        text = "Run `nmap -sV 192.168.1.1` to check services."
        recs = analyzer._parse_ai_response(text, "security")

        assert len(recs) == 1
        assert recs[0].command == "nmap -sV 192.168.1.1"

    def test_empty_findings_falls_through(self, analyzer):
        """A valid JSON object with empty findings should fall through."""
        data = {"findings": []}
        recs = analyzer._parse_ai_response(json.dumps(data), "security")
        # Falls through strategy 1 (empty list), then 2, 3, 4 and
        # reaches text fallback. The text is valid JSON but has no
        # paragraph structure, so result may be minimal.
        assert isinstance(recs, list)

    def test_findings_with_missing_fields_use_defaults(self, analyzer):
        """Findings missing optional fields get defaults."""
        data = {
            "findings": [
                {"severity": "warning"}  # missing description, recommendation, command
            ]
        }
        recs = analyzer._parse_ai_response(json.dumps(data), "security")

        assert len(recs) == 1
        assert recs[0].severity == "warning"
        assert recs[0].description == ""
        assert recs[0].recommendation == ""
        assert recs[0].command is None

    def test_non_dict_findings_ignored(self, analyzer):
        """Non-dict items in findings list are skipped."""
        data = {
            "findings": [
                "not a dict",
                42,
                {"severity": "info", "description": "ok", "recommendation": "good"},
            ]
        }
        recs = analyzer._parse_ai_response(json.dumps(data), "security")

        assert len(recs) == 1
        assert recs[0].severity == "info"


# =========================================================================
# 7. analyze_security_rules
# =========================================================================


class TestAnalyzeSecurityRules:
    """Tests for rule-based security analysis."""

    def test_dangerous_ports_critical(self, analyzer):
        """Ports 21, 23, 445, 3389 should produce CRITICAL findings."""
        for port in [21, 23, 445, 3389]:
            data = {
                "devices": [
                    {
                        "ip": "10.0.0.5",
                        "vendor": "Acme",
                        "hostname": "host",
                        "open_ports": [port],
                    }
                ]
            }
            recs = analyzer.analyze_security_rules(data)
            port_recs = [
                r for r in recs
                if str(port) in r.description and r.severity == SEVERITY_CRITICAL
            ]
            assert len(port_recs) >= 1, f"Port {port} should trigger CRITICAL"

    def test_dangerous_ports_warning(self, analyzer):
        """Other dangerous ports (e.g. 25, 135, 5900) should produce WARNING."""
        for port in [25, 135, 5900, 6379]:
            data = {
                "devices": [
                    {
                        "ip": "10.0.0.5",
                        "vendor": "Acme",
                        "hostname": "host",
                        "open_ports": [port],
                    }
                ]
            }
            recs = analyzer.analyze_security_rules(data)
            port_recs = [
                r for r in recs
                if str(port) in r.description and r.severity == SEVERITY_WARNING
            ]
            assert len(port_recs) >= 1, f"Port {port} should trigger WARNING"

    def test_unknown_vendor(self, analyzer):
        """Devices with no vendor should produce a WARNING."""
        data = {
            "devices": [
                {
                    "ip": "10.0.0.5",
                    "vendor": None,
                    "mac": "AA:BB:CC:DD:EE:FF",
                    "hostname": "host",
                    "open_ports": [],
                }
            ]
        }
        recs = analyzer.analyze_security_rules(data)
        unknown_recs = [r for r in recs if "unknown" in r.description.lower()]
        assert len(unknown_recs) >= 1

    def test_unknown_vendor_string(self, analyzer):
        """Vendor == 'unknown' (case-insensitive) is treated the same as None."""
        data = {
            "devices": [
                {
                    "ip": "10.0.0.5",
                    "vendor": "Unknown",
                    "mac": "AA:BB:CC:DD:EE:FF",
                    "hostname": "host",
                    "open_ports": [],
                }
            ]
        }
        recs = analyzer.analyze_security_rules(data)
        unknown_recs = [r for r in recs if "unknown" in r.description.lower()]
        assert len(unknown_recs) >= 1

    def test_many_open_ports(self, analyzer):
        """Devices with >10 open ports should generate a WARNING."""
        data = {
            "devices": [
                {
                    "ip": "10.0.0.5",
                    "vendor": "Acme",
                    "hostname": "host",
                    "open_ports": list(range(9000, 9012)),  # 12 ports
                }
            ]
        }
        recs = analyzer.analyze_security_rules(data)
        many_recs = [r for r in recs if "12 open ports" in r.description]
        assert len(many_recs) == 1
        assert many_recs[0].severity == SEVERITY_WARNING

    def test_exactly_10_ports_no_warning(self, analyzer):
        """Exactly 10 open ports should NOT trigger the >10 rule."""
        data = {
            "devices": [
                {
                    "ip": "10.0.0.5",
                    "vendor": "Acme",
                    "hostname": "host",
                    "open_ports": list(range(9000, 9010)),  # exactly 10
                }
            ]
        }
        recs = analyzer.analyze_security_rules(data)
        many_recs = [r for r in recs if "open ports" in r.description and "unusually" in r.description]
        assert len(many_recs) == 0

    def test_risky_port_combinations(self, analyzer):
        """Known risky port combinations should produce warnings."""
        # SSH (22) + RDP (3389)
        data = {
            "devices": [
                {
                    "ip": "10.0.0.5",
                    "vendor": "Acme",
                    "hostname": "host",
                    "open_ports": [22, 3389],
                }
            ]
        }
        recs = analyzer.analyze_security_rules(data)
        combo_recs = [r for r in recs if "SSH and RDP" in r.description]
        assert len(combo_recs) >= 1

    def test_risky_combination_smb(self, analyzer):
        """Ports 139 + 445 (SMB combination) should produce a warning."""
        data = {
            "devices": [
                {
                    "ip": "10.0.0.5",
                    "vendor": "Acme",
                    "hostname": "host",
                    "open_ports": [139, 445],
                }
            ]
        }
        recs = analyzer.analyze_security_rules(data)
        combo_recs = [r for r in recs if "SMB" in r.description]
        assert len(combo_recs) >= 1

    def test_gateway_unexpected_dangerous_ports(self, analyzer):
        """Gateway with dangerous ports outside EXPECTED_GATEWAY_PORTS gets CRITICAL."""
        data = {
            "gateway": "10.0.0.1",
            "devices": [
                {
                    "ip": "10.0.0.1",
                    "vendor": "Router Co",
                    "hostname": "gw",
                    "open_ports": [80, 443, 23, 3389],  # 23 and 3389 are dangerous
                }
            ],
        }
        recs = analyzer.analyze_security_rules(data)
        gw_recs = [r for r in recs if "Gateway" in r.description and r.severity == SEVERITY_CRITICAL]
        assert len(gw_recs) >= 1

    def test_gateway_by_hostname(self, analyzer):
        """Device with hostname 'router' is treated as gateway."""
        data = {
            "devices": [
                {
                    "ip": "10.0.0.1",
                    "vendor": "Router Co",
                    "hostname": "Router",
                    "open_ports": [80, 23],
                }
            ]
        }
        recs = analyzer.analyze_security_rules(data)
        gw_recs = [r for r in recs if "Gateway" in r.description]
        assert len(gw_recs) >= 1

    def test_empty_device_list(self, analyzer):
        """Empty device list should produce an INFO recommendation."""
        data = {"devices": []}
        recs = analyzer.analyze_security_rules(data)

        assert len(recs) == 1
        assert recs[0].severity == SEVERITY_INFO
        assert "No devices" in recs[0].description

    def test_clean_network_no_issues(self, analyzer, clean_scan_data):
        """A clean network should produce exactly one INFO 'no issues' rec."""
        recs = analyzer.analyze_security_rules(clean_scan_data)

        assert len(recs) == 1
        assert recs[0].severity == SEVERITY_INFO
        assert "No obvious security issues" in recs[0].description

    def test_category_is_security(self, analyzer, risky_scan_data):
        """All recommendations from security rules should have category 'security'."""
        recs = analyzer.analyze_security_rules(risky_scan_data)
        assert all(r.category == "security" for r in recs)

    def test_command_included_for_dangerous_ports(self, analyzer):
        """Dangerous port findings should include an nmap command."""
        data = {
            "devices": [
                {
                    "ip": "10.0.0.5",
                    "vendor": "Acme",
                    "hostname": "host",
                    "open_ports": [23],
                }
            ]
        }
        recs = analyzer.analyze_security_rules(data)
        telnet_recs = [r for r in recs if "23" in r.description and r.command]
        assert len(telnet_recs) >= 1
        assert "nmap" in telnet_recs[0].command

    def test_string_port_numbers(self, analyzer):
        """Port numbers passed as strings should still be detected."""
        data = {
            "devices": [
                {
                    "ip": "10.0.0.5",
                    "vendor": "Acme",
                    "hostname": "host",
                    "open_ports": ["23", "445"],
                }
            ]
        }
        recs = analyzer.analyze_security_rules(data)
        critical_recs = [r for r in recs if r.severity == SEVERITY_CRITICAL]
        assert len(critical_recs) >= 1


# =========================================================================
# 8. analyze_anomalies
# =========================================================================


class TestAnalyzeAnomalies:
    """Tests for anomaly detection."""

    def test_new_device_detected(self, analyzer):
        """A device not seen in any previous scan should be flagged."""
        current = {
            "devices": [
                {"ip": "10.0.0.1", "vendor": "Known", "open_ports": []},
                {"ip": "10.0.0.99", "vendor": "Stranger", "mac": "XX:XX", "open_ports": []},
            ]
        }
        previous = [
            {
                "devices": [
                    {"ip": "10.0.0.1", "vendor": "Known", "open_ports": []},
                ]
            }
        ]
        recs = analyzer.analyze_anomalies(current, previous)
        new_recs = [r for r in recs if "New device" in r.description and "10.0.0.99" in r.description]
        assert len(new_recs) == 1
        assert new_recs[0].severity == SEVERITY_WARNING

    def test_disappeared_device(self, analyzer):
        """A device present in the last scan but missing now should be reported."""
        current = {
            "devices": [
                {"ip": "10.0.0.1", "vendor": "Known", "open_ports": []},
            ]
        }
        previous = [
            {
                "devices": [
                    {"ip": "10.0.0.1", "vendor": "Known", "open_ports": []},
                    {"ip": "10.0.0.50", "vendor": "OldDevice", "open_ports": []},
                ]
            }
        ]
        recs = analyzer.analyze_anomalies(current, previous)
        gone_recs = [r for r in recs if "10.0.0.50" in r.description and "no longer" in r.description]
        assert len(gone_recs) == 1
        assert gone_recs[0].severity == SEVERITY_INFO

    def test_port_opened(self, analyzer):
        """Newly opened ports should be flagged."""
        current = {
            "devices": [
                {"ip": "10.0.0.1", "vendor": "Acme", "open_ports": [22, 80, 443]},
            ]
        }
        previous = [
            {
                "devices": [
                    {"ip": "10.0.0.1", "vendor": "Acme", "open_ports": [22]},
                ]
            }
        ]
        recs = analyzer.analyze_anomalies(current, previous)
        opened_recs = [r for r in recs if "new ports opened" in r.description]
        assert len(opened_recs) == 1

    def test_dangerous_port_opened_is_critical(self, analyzer):
        """A newly opened dangerous port should be CRITICAL."""
        current = {
            "devices": [
                {"ip": "10.0.0.1", "vendor": "Acme", "open_ports": [22, 23]},
            ]
        }
        previous = [
            {
                "devices": [
                    {"ip": "10.0.0.1", "vendor": "Acme", "open_ports": [22]},
                ]
            }
        ]
        recs = analyzer.analyze_anomalies(current, previous)
        opened_recs = [r for r in recs if "new ports opened" in r.description]
        assert len(opened_recs) == 1
        assert opened_recs[0].severity == SEVERITY_CRITICAL

    def test_port_closed(self, analyzer):
        """Ports that closed since the last scan should be reported as INFO."""
        current = {
            "devices": [
                {"ip": "10.0.0.1", "vendor": "Acme", "open_ports": [22]},
            ]
        }
        previous = [
            {
                "devices": [
                    {"ip": "10.0.0.1", "vendor": "Acme", "open_ports": [22, 80]},
                ]
            }
        ]
        recs = analyzer.analyze_anomalies(current, previous)
        closed_recs = [r for r in recs if "closed since" in r.description]
        assert len(closed_recs) == 1
        assert closed_recs[0].severity == SEVERITY_INFO

    def test_no_previous_scans(self, analyzer):
        """With no previous scans, only unusual-port anomalies should appear,
        plus an INFO about no history."""
        current = {
            "devices": [
                {"ip": "10.0.0.1", "vendor": "Acme", "open_ports": [22]},
            ]
        }
        recs = analyzer.analyze_anomalies(current, None)
        info_recs = [r for r in recs if "No previous scans" in r.description]
        assert len(info_recs) == 1

    def test_no_previous_scans_empty_list(self, analyzer):
        """An empty previous_scans list behaves like None."""
        current = {
            "devices": [
                {"ip": "10.0.0.1", "vendor": "Acme", "open_ports": [22]},
            ]
        }
        recs = analyzer.analyze_anomalies(current, [])
        info_recs = [r for r in recs if "No previous scans" in r.description]
        assert len(info_recs) == 1

    def test_no_anomalies(self, analyzer):
        """Identical scans should produce a 'no anomalies' message."""
        scan = {
            "devices": [
                {"ip": "10.0.0.1", "vendor": "Acme", "open_ports": [22]},
            ]
        }
        recs = analyzer.analyze_anomalies(scan, [scan])
        no_anomaly = [r for r in recs if "No anomalies" in r.description]
        assert len(no_anomaly) == 1

    def test_unusual_ports_without_history(self, analyzer):
        """Dangerous ports should be flagged even without history."""
        current = {
            "devices": [
                {"ip": "10.0.0.1", "vendor": "Acme", "open_ports": [23, 445]},
            ]
        }
        recs = analyzer.analyze_anomalies(current, None)
        unusual_recs = [r for r in recs if "unusual ports" in r.description.lower()]
        assert len(unusual_recs) >= 1

    def test_category_is_anomaly(self, analyzer):
        """All anomaly detection results should have category 'anomaly'."""
        current = {
            "devices": [
                {"ip": "10.0.0.1", "vendor": "Acme", "open_ports": [23]},
            ]
        }
        recs = analyzer.analyze_anomalies(current, None)
        assert all(r.category == "anomaly" for r in recs)

    def test_new_device_checked_against_all_history(self, analyzer):
        """A device seen in an older scan (not the most recent) is NOT new."""
        current = {
            "devices": [
                {"ip": "10.0.0.1", "vendor": "Acme", "open_ports": []},
                {"ip": "10.0.0.50", "vendor": "Reappeared", "open_ports": []},
            ]
        }
        # 10.0.0.50 was in the older scan but not the most recent
        previous = [
            {  # most recent
                "devices": [
                    {"ip": "10.0.0.1", "vendor": "Acme", "open_ports": []},
                ]
            },
            {  # older scan
                "devices": [
                    {"ip": "10.0.0.1", "vendor": "Acme", "open_ports": []},
                    {"ip": "10.0.0.50", "vendor": "Reappeared", "open_ports": []},
                ]
            },
        ]
        recs = analyzer.analyze_anomalies(current, previous)
        new_device_recs = [r for r in recs if "New device" in r.description]
        assert len(new_device_recs) == 0


# =========================================================================
# 9. calculate_security_score
# =========================================================================


class TestCalculateSecurityScore:
    """Tests for the security scoring system."""

    def test_perfect_score(self, analyzer, clean_scan_data):
        """A clean network should score 100 / grade A."""
        result = analyzer.calculate_security_score(clean_scan_data)
        assert result["score"] == 100
        assert result["grade"] == "A"
        assert result["penalties"] == []

    def test_empty_devices_returns_50(self, analyzer):
        """No devices => score 50, grade N/A."""
        result = analyzer.calculate_security_score({"devices": []})
        assert result["score"] == 50
        assert result["grade"] == "N/A"

    def test_critical_port_penalty_8(self, analyzer):
        """Critical dangerous ports (21, 23, 445, 3389) deduct 8 points each."""
        data = {
            "devices": [
                {
                    "ip": "10.0.0.5",
                    "vendor": "Acme",
                    "hostname": "host",
                    "open_ports": [23],
                }
            ]
        }
        result = analyzer.calculate_security_score(data)
        assert result["score"] == 100 - 8
        assert any(p["points"] == 8 for p in result["penalties"])

    def test_non_critical_dangerous_port_penalty_5(self, analyzer):
        """Non-critical dangerous ports (e.g. 25, 5900) deduct 5 points each."""
        data = {
            "devices": [
                {
                    "ip": "10.0.0.5",
                    "vendor": "Acme",
                    "hostname": "host",
                    "open_ports": [5900],
                }
            ]
        }
        result = analyzer.calculate_security_score(data)
        assert result["score"] == 100 - 5

    def test_unknown_vendor_penalty_3(self, analyzer):
        """Unknown vendor deducts 3 points."""
        data = {
            "devices": [
                {
                    "ip": "10.0.0.5",
                    "vendor": None,
                    "hostname": "host",
                    "open_ports": [],
                }
            ]
        }
        result = analyzer.calculate_security_score(data)
        assert result["score"] == 100 - 3

    def test_many_open_ports_penalty_4(self, analyzer):
        """More than 10 open ports deducts 4 points."""
        data = {
            "devices": [
                {
                    "ip": "10.0.0.5",
                    "vendor": "Acme",
                    "hostname": "host",
                    "open_ports": list(range(9000, 9012)),  # 12 ports, none dangerous
                }
            ]
        }
        result = analyzer.calculate_security_score(data)
        assert result["score"] == 100 - 4

    def test_risky_combination_penalty_3(self, analyzer):
        """Risky port combination deducts 3 points."""
        data = {
            "devices": [
                {
                    "ip": "10.0.0.5",
                    "vendor": "Acme",
                    "hostname": "host",
                    "open_ports": [22, 3389],  # SSH + RDP
                }
            ]
        }
        result = analyzer.calculate_security_score(data)
        # 8 for port 3389 (critical dangerous) + 3 for combo = 11
        assert result["score"] == 100 - 8 - 3

    def test_gateway_dangerous_ports_penalty_10(self, analyzer):
        """Gateway with dangerous ports deducts 10 points."""
        data = {
            "gateway": "10.0.0.1",
            "devices": [
                {
                    "ip": "10.0.0.1",
                    "vendor": "Router Co",
                    "hostname": "gw",
                    "open_ports": [80, 443, 23],
                }
            ],
        }
        result = analyzer.calculate_security_score(data)
        gw_penalties = [p for p in result["penalties"] if p["points"] == 10]
        assert len(gw_penalties) >= 1

    def test_score_clamped_to_zero(self, analyzer):
        """Score should never go below 0."""
        data = {
            "devices": [
                {
                    "ip": f"10.0.0.{i}",
                    "vendor": None,
                    "hostname": "host",
                    "open_ports": [21, 23, 445, 3389, 139, 5900, 6379, 3306,
                                   22, 25, 135, 137, 138],
                }
                for i in range(5)
            ]
        }
        result = analyzer.calculate_security_score(data)
        assert result["score"] == 0

    def test_score_clamped_to_100(self, analyzer):
        """Score should never exceed 100 (though it starts at 100)."""
        result = analyzer.calculate_security_score(
            {"devices": [{"ip": "10.0.0.1", "vendor": "Acme",
                          "hostname": "h", "open_ports": []}]}
        )
        assert result["score"] <= 100

    def test_grade_A(self, analyzer, clean_scan_data):
        result = analyzer.calculate_security_score(clean_scan_data)
        assert result["grade"] == "A"

    def test_grade_B(self, analyzer):
        """Score 80-89 -> grade B."""
        data = {
            "devices": [
                {
                    "ip": "10.0.0.1",
                    "vendor": "Acme",
                    "hostname": "host",
                    # Two non-critical dangerous ports: -5 each = -10 => score 90
                    # Plus one unknown vendor: -3 => score 87
                },
                {
                    "ip": "10.0.0.2",
                    "vendor": None,
                    "hostname": "host",
                    "open_ports": [5900, 6379],
                },
            ]
        }
        # Fix: first device also needs open_ports
        data["devices"][0]["open_ports"] = []
        result = analyzer.calculate_security_score(data)
        assert result["grade"] == "B"

    def test_grade_C(self, analyzer):
        """Score 70-79 -> grade C."""
        data = {
            "devices": [
                {
                    "ip": "10.0.0.1",
                    "vendor": "Acme",
                    "hostname": "host",
                    "open_ports": [21, 23, 445],  # -8 * 3 = -24 => score 76
                }
            ]
        }
        result = analyzer.calculate_security_score(data)
        assert result["grade"] == "C"

    def test_grade_D(self, analyzer):
        """Score 60-69 -> grade D."""
        data = {
            "devices": [
                {
                    "ip": "10.0.0.1",
                    "vendor": "Acme",
                    "hostname": "host",
                    # -8 * 4 = -32, -3 for combo (139+445) => 65
                    "open_ports": [21, 23, 445, 3389, 139],
                }
            ]
        }
        result = analyzer.calculate_security_score(data)
        assert result["grade"] == "D"

    def test_grade_F(self, analyzer):
        """Score < 60 -> grade F."""
        data = {
            "devices": [
                {
                    "ip": "10.0.0.1",
                    "vendor": None,
                    "hostname": "host",
                    "open_ports": [21, 23, 445, 3389, 139, 5900, 6379, 3306,
                                   25, 135, 137, 138],
                }
            ]
        }
        result = analyzer.calculate_security_score(data)
        assert result["grade"] == "F"
        assert result["score"] < 60

    def test_summary_present(self, analyzer, clean_scan_data):
        result = analyzer.calculate_security_score(clean_scan_data)
        assert "summary" in result
        assert len(result["summary"]) > 0

    def test_penalties_is_list(self, analyzer, risky_scan_data):
        result = analyzer.calculate_security_score(risky_scan_data)
        assert isinstance(result["penalties"], list)
        for p in result["penalties"]:
            assert "device" in p
            assert "reason" in p
            assert "points" in p


# =========================================================================
# 10. get_quick_insights
# =========================================================================


class TestGetQuickInsights:
    """Tests for get_quick_insights."""

    def test_device_count_insight(self, analyzer, clean_scan_data):
        insights = analyzer.get_quick_insights(clean_scan_data)
        assert any("2 active devices" in i for i in insights)

    def test_vendor_breakdown(self, analyzer, clean_scan_data):
        insights = analyzer.get_quick_insights(clean_scan_data)
        assert any("Top vendors" in i for i in insights)

    def test_many_open_ports_warning(self, analyzer):
        data = {
            "devices": [
                {
                    "ip": "10.0.0.1",
                    "vendor": "Acme",
                    "open_ports": list(range(9000, 9015)),
                }
            ]
        }
        insights = analyzer.get_quick_insights(data)
        assert any("15 open ports" in i for i in insights)

    def test_unknown_vendor_count(self, analyzer):
        data = {
            "devices": [
                {"ip": "10.0.0.1", "vendor": None, "open_ports": []},
                {"ip": "10.0.0.2", "vendor": "unknown", "open_ports": []},
            ]
        }
        insights = analyzer.get_quick_insights(data)
        assert any("2 devices with unknown vendors" in i for i in insights)

    def test_dangerous_port_alert(self, analyzer):
        data = {
            "devices": [
                {"ip": "10.0.0.1", "vendor": "Acme", "open_ports": [23]},
            ]
        }
        insights = analyzer.get_quick_insights(data)
        assert any("dangerous services" in i.lower() for i in insights)

    def test_gateway_detected(self, analyzer, clean_scan_data):
        insights = analyzer.get_quick_insights(clean_scan_data)
        assert any("Gateway" in i and "192.168.1.1" in i for i in insights)

    def test_gateway_not_in_scan(self, analyzer):
        data = {
            "gateway": "10.0.0.1",
            "devices": [
                {"ip": "10.0.0.2", "vendor": "Acme", "open_ports": [22]},
            ],
        }
        insights = analyzer.get_quick_insights(data)
        assert any("not found" in i for i in insights)

    def test_security_score_included(self, analyzer, clean_scan_data):
        insights = analyzer.get_quick_insights(clean_scan_data)
        assert any("Security score" in i for i in insights)

    def test_uses_device_count_from_data(self, analyzer):
        """When device_count differs from len(devices), device_count takes precedence."""
        data = {
            "device_count": 99,
            "devices": [
                {"ip": "10.0.0.1", "vendor": "Acme", "open_ports": []},
            ],
        }
        insights = analyzer.get_quick_insights(data)
        assert any("99 active devices" in i for i in insights)


# =========================================================================
# 11. _analyze_health_rules
# =========================================================================


class TestAnalyzeHealthRules:
    """Tests for rule-based health analysis."""

    def test_high_device_count_warning(self, analyzer):
        data = {
            "device_count": 55,
            "devices": [
                {"ip": f"10.0.0.{i}", "hostname": f"host{i}", "open_ports": []}
                for i in range(55)
            ],
        }
        recs = analyzer._analyze_health_rules(data)
        high_recs = [r for r in recs if "High number" in r.description]
        assert len(high_recs) == 1
        assert high_recs[0].severity == SEVERITY_WARNING

    def test_moderate_device_count_info(self, analyzer):
        data = {
            "device_count": 30,
            "devices": [
                {"ip": f"10.0.0.{i}", "hostname": f"host{i}", "open_ports": []}
                for i in range(30)
            ],
        }
        recs = analyzer._analyze_health_rules(data)
        mod_recs = [r for r in recs if "Moderate" in r.description]
        assert len(mod_recs) == 1
        assert mod_recs[0].severity == SEVERITY_INFO

    def test_many_services_warning(self, analyzer):
        data = {
            "devices": [
                {
                    "ip": "10.0.0.1",
                    "hostname": "server",
                    "open_ports": list(range(1000, 1025)),  # 25 ports
                }
            ]
        }
        recs = analyzer._analyze_health_rules(data)
        svc_recs = [r for r in recs if "25 services" in r.description]
        assert len(svc_recs) == 1
        assert svc_recs[0].severity == SEVERITY_WARNING

    def test_duplicate_hostnames(self, analyzer):
        data = {
            "devices": [
                {"ip": "10.0.0.1", "hostname": "webserver", "open_ports": []},
                {"ip": "10.0.0.2", "hostname": "webserver", "open_ports": []},
            ]
        }
        recs = analyzer._analyze_health_rules(data)
        dup_recs = [r for r in recs if "Duplicate hostname" in r.description]
        assert len(dup_recs) == 1

    def test_no_health_issues(self, analyzer, clean_scan_data):
        recs = analyzer._analyze_health_rules(clean_scan_data)
        assert len(recs) == 1
        assert "normal" in recs[0].description.lower()

    def test_category_is_health(self, analyzer, clean_scan_data):
        recs = analyzer._analyze_health_rules(clean_scan_data)
        assert all(r.category == "health" for r in recs)

    def test_device_count_from_key(self, analyzer):
        """device_count key is used rather than len(devices)."""
        data = {
            "device_count": 60,
            "devices": [],  # empty but count says 60
        }
        recs = analyzer._analyze_health_rules(data)
        high_recs = [r for r in recs if "High number" in r.description]
        assert len(high_recs) == 1


# =========================================================================
# 12. _analyze_wifi_rules
# =========================================================================


class TestAnalyzeWifiRules:
    """Tests for rule-based WiFi analysis."""

    def test_very_weak_signal_critical(self, analyzer):
        recs = analyzer._analyze_wifi_rules({"signal_strength": -85})
        sig_recs = [r for r in recs if "very weak" in r.description.lower()]
        assert len(sig_recs) == 1
        assert sig_recs[0].severity == SEVERITY_CRITICAL

    def test_fair_signal_warning(self, analyzer):
        recs = analyzer._analyze_wifi_rules({"signal_strength": -75})
        sig_recs = [r for r in recs if "fair" in r.description.lower()]
        assert len(sig_recs) == 1
        assert sig_recs[0].severity == SEVERITY_WARNING

    def test_good_signal_info(self, analyzer):
        recs = analyzer._analyze_wifi_rules({"signal_strength": -65})
        sig_recs = [r for r in recs if "good" in r.description.lower()]
        assert len(sig_recs) == 1
        assert sig_recs[0].severity == SEVERITY_INFO

    def test_excellent_signal_info(self, analyzer):
        recs = analyzer._analyze_wifi_rules({"signal_strength": -45})
        sig_recs = [r for r in recs if "excellent" in r.description.lower()]
        assert len(sig_recs) == 1
        assert sig_recs[0].severity == SEVERITY_INFO

    def test_signal_boundary_minus_80(self, analyzer):
        """Signal exactly at -80 should be 'very weak' (< -80 is False, so it is fair)."""
        recs = analyzer._analyze_wifi_rules({"signal_strength": -80})
        # -80 is not < -80, but is < -70 => fair/warning
        sig_recs = [r for r in recs if r.severity == SEVERITY_WARNING]
        assert len(sig_recs) >= 1

    def test_signal_boundary_minus_70(self, analyzer):
        """Signal at -70 is not < -70, so good range."""
        recs = analyzer._analyze_wifi_rules({"signal_strength": -70})
        sig_recs = [r for r in recs if "good" in r.description.lower()]
        assert len(sig_recs) == 1

    def test_signal_boundary_minus_60(self, analyzer):
        """Signal at -60 is not < -60, so excellent."""
        recs = analyzer._analyze_wifi_rules({"signal_strength": -60})
        sig_recs = [r for r in recs if "excellent" in r.description.lower()]
        assert len(sig_recs) == 1

    def test_low_snr_critical(self, analyzer):
        recs = analyzer._analyze_wifi_rules({"signal_strength": -80, "noise": -85})
        snr_recs = [r for r in recs if "signal-to-noise" in r.description.lower() and "critically" in r.description.lower()]
        assert len(snr_recs) == 1
        assert snr_recs[0].severity == SEVERITY_CRITICAL

    def test_marginal_snr_warning(self, analyzer):
        recs = analyzer._analyze_wifi_rules({"signal_strength": -65, "noise": -80})
        snr_recs = [r for r in recs if "signal-to-noise" in r.description.lower() and "marginal" in r.description.lower()]
        assert len(snr_recs) == 1
        assert snr_recs[0].severity == SEVERITY_WARNING

    def test_good_snr_no_alert(self, analyzer):
        """SNR >= 20 should not produce a specific SNR warning."""
        recs = analyzer._analyze_wifi_rules({"signal_strength": -50, "noise": -90})
        snr_recs = [r for r in recs if "signal-to-noise" in r.description.lower()]
        assert len(snr_recs) == 0

    def test_channel_congestion_warning(self, analyzer):
        wifi = {
            "channel": 6,
            "neighbors": [
                {"channel": 6},
                {"channel": 6},
                {"channel": 6},
                {"channel": 6},  # 4 on same channel => > 3 threshold
            ],
        }
        recs = analyzer._analyze_wifi_rules(wifi)
        cong_recs = [r for r in recs if "congested" in r.description.lower()]
        assert len(cong_recs) == 1
        assert cong_recs[0].severity == SEVERITY_WARNING

    def test_minor_channel_interference(self, analyzer):
        wifi = {
            "channel": 6,
            "neighbors": [
                {"channel": 6},
                {"channel": 6},  # 2 on same channel
                {"channel": 1},
            ],
        }
        recs = analyzer._analyze_wifi_rules(wifi)
        minor_recs = [r for r in recs if "Minor interference" in r.description]
        assert len(minor_recs) == 1
        assert minor_recs[0].severity == SEVERITY_INFO

    def test_high_neighbor_density(self, analyzer):
        wifi = {
            "channel": 6,
            "neighbors": [{"channel": i % 11 + 1} for i in range(20)],
        }
        recs = analyzer._analyze_wifi_rules(wifi)
        density_recs = [r for r in recs if "High WiFi density" in r.description]
        assert len(density_recs) == 1

    def test_band_2_4ghz_recommendation(self, analyzer):
        recs = analyzer._analyze_wifi_rules({"band": "2.4GHz"})
        band_recs = [r for r in recs if "2.4 GHz" in r.description]
        assert len(band_recs) == 1
        assert band_recs[0].severity == SEVERITY_INFO

    def test_band_6ghz_recommendation(self, analyzer):
        recs = analyzer._analyze_wifi_rules({"band": "6GHz"})
        band_recs = [r for r in recs if "6 GHz" in r.description]
        assert len(band_recs) == 1

    def test_low_tx_rate_warning(self, analyzer):
        recs = analyzer._analyze_wifi_rules({"tx_rate": "5 Mbps"})
        rate_recs = [r for r in recs if "transmit rate" in r.description.lower()]
        assert len(rate_recs) == 1
        assert rate_recs[0].severity == SEVERITY_WARNING

    def test_low_rx_rate_warning(self, analyzer):
        recs = analyzer._analyze_wifi_rules({"rx_rate": "3 Mbps"})
        rate_recs = [r for r in recs if "receive rate" in r.description.lower()]
        assert len(rate_recs) == 1
        assert rate_recs[0].severity == SEVERITY_WARNING

    def test_no_wifi_issues(self, analyzer):
        """Empty WiFi data should produce a single 'no issues' recommendation."""
        recs = analyzer._analyze_wifi_rules({})
        assert len(recs) == 1
        assert "reasonable" in recs[0].description.lower()

    def test_category_is_wifi(self, analyzer):
        recs = analyzer._analyze_wifi_rules({"signal_strength": -85})
        assert all(r.category == "wifi" for r in recs)

    def test_signal_as_alternative_key(self, analyzer):
        """'signal' key should work as alternative to 'signal_strength'."""
        recs = analyzer._analyze_wifi_rules({"signal": -85})
        sig_recs = [r for r in recs if "very weak" in r.description.lower()]
        assert len(sig_recs) == 1

    def test_noise_alternative_key(self, analyzer):
        """'noise_level' key should work as alternative to 'noise'."""
        recs = analyzer._analyze_wifi_rules(
            {"signal_strength": -80, "noise_level": -85}
        )
        snr_recs = [r for r in recs if "signal-to-noise" in r.description.lower()]
        assert len(snr_recs) >= 1

    def test_tx_bitrate_alternative_key(self, analyzer):
        """'tx_bitrate' key should work as alternative to 'tx_rate'."""
        recs = analyzer._analyze_wifi_rules({"tx_bitrate": "2 Mbps"})
        rate_recs = [r for r in recs if "transmit rate" in r.description.lower()]
        assert len(rate_recs) == 1

    def test_nearby_networks_alternative_key(self, analyzer):
        """'nearby_networks' should work as alternative to 'neighbors'."""
        wifi = {
            "channel": 1,
            "nearby_networks": [
                {"channel": 1},
                {"channel": 1},
                {"channel": 1},
                {"channel": 1},
            ],
        }
        recs = analyzer._analyze_wifi_rules(wifi)
        cong_recs = [r for r in recs if "congested" in r.description.lower()]
        assert len(cong_recs) == 1


# =========================================================================
# 13. analyze_security / analyze_network_health / analyze_wifi_optimization
#     -- fallback to rules when Ollama unavailable
# =========================================================================


class TestFallbackBehaviour:
    """Tests that the high-level analyze_* methods fall back to rules."""

    def test_analyze_security_falls_back(self, offline_analyzer, clean_scan_data):
        recs = offline_analyzer.analyze_security(clean_scan_data)
        # Should get rule-based results
        assert isinstance(recs, list)
        assert len(recs) >= 1
        assert all(isinstance(r, AIRecommendation) for r in recs)

    def test_analyze_network_health_falls_back(self, offline_analyzer, clean_scan_data):
        recs = offline_analyzer.analyze_network_health(clean_scan_data)
        assert isinstance(recs, list)
        assert len(recs) >= 1

    def test_analyze_wifi_falls_back(self, offline_analyzer):
        wifi = {"signal_strength": -85}
        recs = offline_analyzer.analyze_wifi_optimization(wifi)
        assert isinstance(recs, list)
        assert len(recs) >= 1

    def test_analyze_security_uses_ai_when_available(self, analyzer, mock_session):
        """When Ollama is available and responds, AI results are returned."""
        ai_response = json.dumps(
            {
                "findings": [
                    {
                        "severity": "critical",
                        "description": "AI found an issue",
                        "recommendation": "Fix it",
                    }
                ]
            }
        )
        post_resp = MagicMock()
        post_resp.status_code = 200
        post_resp.json.return_value = {"response": ai_response}
        mock_session.post.return_value = post_resp

        recs = analyzer.analyze_security({"devices": []})

        assert len(recs) == 1
        assert recs[0].description == "AI found an issue"

    def test_analyze_security_falls_back_when_ai_returns_none(
        self, analyzer, mock_session
    ):
        """If _call_ollama returns None, fallback to rules."""
        import requests as req_lib

        mock_session.post.side_effect = req_lib.exceptions.Timeout("timeout")

        recs = analyzer.analyze_security({"devices": []})
        # Should fall back to rule-based -- empty devices produces INFO
        assert isinstance(recs, list)
        assert len(recs) >= 1

    def test_analyze_network_health_uses_ai_when_available(
        self, analyzer, mock_session
    ):
        ai_response = json.dumps(
            {
                "findings": [
                    {
                        "severity": "info",
                        "description": "Network looks healthy",
                        "recommendation": "No action",
                    }
                ]
            }
        )
        post_resp = MagicMock()
        post_resp.status_code = 200
        post_resp.json.return_value = {"response": ai_response}
        mock_session.post.return_value = post_resp

        recs = analyzer.analyze_network_health({"devices": []})

        assert len(recs) == 1
        assert "healthy" in recs[0].description.lower()

    def test_analyze_wifi_uses_ai_when_available(self, analyzer, mock_session):
        ai_response = json.dumps(
            {
                "findings": [
                    {
                        "severity": "warning",
                        "description": "Switch channel",
                        "recommendation": "Use channel 36",
                    }
                ]
            }
        )
        post_resp = MagicMock()
        post_resp.status_code = 200
        post_resp.json.return_value = {"response": ai_response}
        mock_session.post.return_value = post_resp

        recs = analyzer.analyze_wifi_optimization({"signal_strength": -70})

        assert len(recs) == 1
        assert "channel" in recs[0].description.lower()


# =========================================================================
# 14. analyze_comprehensive
# =========================================================================


class TestAnalyzeComprehensive:
    """Tests for analyze_comprehensive."""

    def test_returns_all_categories(self, offline_analyzer, clean_scan_data):
        result = offline_analyzer.analyze_comprehensive(clean_scan_data)
        assert "security" in result
        assert "health" in result
        assert "wifi" in result

    def test_wifi_populated_when_data_provided(self, offline_analyzer, clean_scan_data):
        wifi = {"signal_strength": -85}
        result = offline_analyzer.analyze_comprehensive(clean_scan_data, wifi_data=wifi)
        assert len(result["wifi"]) >= 1

    def test_wifi_empty_when_no_data(self, offline_analyzer, clean_scan_data):
        result = offline_analyzer.analyze_comprehensive(clean_scan_data, wifi_data=None)
        assert result["wifi"] == []

    def test_security_and_health_always_populated(
        self, offline_analyzer, clean_scan_data
    ):
        result = offline_analyzer.analyze_comprehensive(clean_scan_data)
        assert len(result["security"]) >= 1
        assert len(result["health"]) >= 1

    def test_exception_in_one_category_does_not_block_others(self, analyzer, mock_session):
        """If security analysis raises, health and wifi should still run."""
        original_security = analyzer.analyze_security

        def broken_security(scan_data):
            raise RuntimeError("boom")

        analyzer.analyze_security = broken_security

        result = analyzer.analyze_comprehensive(
            {"devices": []},
            wifi_data={"signal_strength": -50},
        )
        # Security should be empty due to exception
        assert result["security"] == []
        # Health should have run
        assert isinstance(result["health"], list)

        # Restore
        analyzer.analyze_security = original_security

    def test_all_recommendation_objects(self, offline_analyzer, clean_scan_data):
        """All values in the result should be lists of AIRecommendation."""
        result = offline_analyzer.analyze_comprehensive(
            clean_scan_data, wifi_data={"signal_strength": -70}
        )
        for category, recs in result.items():
            assert isinstance(recs, list), f"{category} is not a list"
            for r in recs:
                assert isinstance(r, AIRecommendation), (
                    f"{category} contains non-AIRecommendation"
                )


# =========================================================================
# Module-level constants sanity checks
# =========================================================================


class TestModuleConstants:
    """Sanity checks for module-level constants."""

    def test_dangerous_ports_dict(self):
        assert isinstance(DANGEROUS_PORTS, dict)
        assert 23 in DANGEROUS_PORTS
        assert 445 in DANGEROUS_PORTS

    def test_expected_gateway_ports_set(self):
        assert isinstance(EXPECTED_GATEWAY_PORTS, set)
        assert 80 in EXPECTED_GATEWAY_PORTS
        assert 443 in EXPECTED_GATEWAY_PORTS

    def test_risky_combinations_list(self):
        assert isinstance(RISKY_COMBINATIONS, list)
        for combo_ports, desc in RISKY_COMBINATIONS:
            assert isinstance(combo_ports, set)
            assert isinstance(desc, str)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
