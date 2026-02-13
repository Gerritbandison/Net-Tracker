"""
AI Analyzer Module

Integrates with Ollama for network security and optimization analysis.
Provides rule-based offline analysis when Ollama is not available,
anomaly detection, trend analysis, security scoring, and WiFi
optimization recommendations.
"""

import re
import logging
import json
import time
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import requests

from config import (
    OLLAMA_API_URL,
    OLLAMA_MODEL,
    OLLAMA_TIMEOUT,
    OLLAMA_MAX_RETRIES,
    OLLAMA_RETRY_DELAY,
    AI_SYSTEM_PROMPT,
    AI_SECURITY_ANALYSIS_PROMPT,
    AI_NETWORK_HEALTH_PROMPT,
    AI_WIFI_OPTIMIZATION_PROMPT,
    SEVERITY_CRITICAL,
    SEVERITY_WARNING,
    SEVERITY_INFO,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Port classification for rule-based analysis
# ---------------------------------------------------------------------------

# Ports considered dangerous when exposed on the local network
DANGEROUS_PORTS = {
    21: ("FTP", "Unencrypted file transfer protocol - credentials sent in plaintext"),
    23: ("Telnet", "Unencrypted remote shell - credentials sent in plaintext"),
    25: ("SMTP", "Mail relay - can be abused for spam if misconfigured"),
    69: ("TFTP", "Trivial FTP with no authentication"),
    135: ("MS-RPC", "Windows RPC - common target for exploits"),
    137: ("NetBIOS-NS", "NetBIOS name service - information disclosure risk"),
    138: ("NetBIOS-DGM", "NetBIOS datagram service - information disclosure risk"),
    139: ("NetBIOS-SSN", "NetBIOS session service - lateral movement risk"),
    445: ("SMB", "Server Message Block - frequent target for ransomware and exploits"),
    1433: ("MSSQL", "Microsoft SQL Server - database exposure risk"),
    1521: ("Oracle DB", "Oracle database - database exposure risk"),
    3306: ("MySQL", "MySQL database - database exposure risk"),
    3389: ("RDP", "Remote Desktop Protocol - brute-force and exploit target"),
    5432: ("PostgreSQL", "PostgreSQL database - database exposure risk"),
    5900: ("VNC", "Virtual Network Computing - often weakly authenticated"),
    5985: ("WinRM", "Windows Remote Management - lateral movement risk"),
    6379: ("Redis", "Redis - often runs without authentication"),
    8080: ("HTTP-Alt", "Alternative HTTP - may expose admin panels"),
    8443: ("HTTPS-Alt", "Alternative HTTPS - may expose admin panels"),
    27017: ("MongoDB", "MongoDB - often runs without authentication"),
}

# Ports typically expected on a gateway/router
EXPECTED_GATEWAY_PORTS = {53, 80, 443, 8080, 8443}

# High-risk port combinations
RISKY_COMBINATIONS = [
    ({22, 3389}, "Device has both SSH and RDP open - unusual and increases attack surface"),
    ({21, 22}, "Device has both FTP and SSH - consider disabling FTP in favour of SFTP"),
    ({80, 8080}, "Device exposes multiple HTTP services - review for unnecessary admin panels"),
    ({139, 445}, "Device has SMB services open - verify these are intentional and patched"),
    ({5900, 3389}, "Device has both VNC and RDP open - redundant remote access increases risk"),
]


class AIRecommendation:
    """AI-generated recommendation container."""

    def __init__(
        self,
        severity: str,
        description: str,
        recommendation: str,
        command: Optional[str] = None,
        category: str = "general",
    ):
        self.severity = severity
        self.description = description
        self.recommendation = recommendation
        self.command = command
        self.category = category

    def to_dict(self) -> Dict:
        """Convert to dictionary representation."""
        return {
            "severity": self.severity,
            "description": self.description,
            "recommendation": self.recommendation,
            "command": self.command,
            "category": self.category,
        }

    def __repr__(self) -> str:
        return f"<AIRecommendation [{self.severity}] {self.description[:50]}...>"


class AIAnalyzer:
    """AI-powered network analysis using Ollama with rule-based fallback."""

    def __init__(self, api_url: str = OLLAMA_API_URL, model: str = OLLAMA_MODEL):
        """
        Initialize AI analyzer.

        Args:
            api_url: Ollama API URL
            model: Model name to use
        """
        self.api_url = api_url.rstrip("/")
        self.model = model
        self.session = requests.Session()
        self._ollama_available: Optional[bool] = None
        self._last_availability_check: float = 0.0
        self._availability_cache_ttl: float = 60.0  # recheck every 60 s
        # Run initial check (non-blocking: result cached)
        self._check_connection()

    # ------------------------------------------------------------------
    # Ollama connectivity
    # ------------------------------------------------------------------

    def _check_connection(self) -> bool:
        """
        Check if Ollama is running and accessible.

        Returns:
            True if connection successful
        """
        try:
            response = self.session.get(f"{self.api_url}/api/tags", timeout=5)
            if response.status_code == 200:
                logger.info("Successfully connected to Ollama API")
                self._ollama_available = True
                self._last_availability_check = time.time()
                return True
            else:
                logger.warning(f"Ollama API returned status {response.status_code}")
                self._ollama_available = False
                self._last_availability_check = time.time()
                return False
        except requests.exceptions.RequestException as e:
            logger.warning(f"Cannot connect to Ollama API: {e}")
            self._ollama_available = False
            self._last_availability_check = time.time()
            return False

    @property
    def is_available(self) -> bool:
        """Check whether Ollama is reachable (cached with TTL)."""
        now = time.time()
        if (
            self._ollama_available is None
            or (now - self._last_availability_check) > self._availability_cache_ttl
        ):
            self._check_connection()
        return bool(self._ollama_available)

    # ------------------------------------------------------------------
    # Ollama API call
    # ------------------------------------------------------------------

    def _call_ollama(
        self, prompt: str, system_prompt: Optional[str] = None
    ) -> Optional[str]:
        """
        Call Ollama API with retry logic.

        Args:
            prompt: User prompt
            system_prompt: System prompt (optional)

        Returns:
            Model response text or None if failed
        """
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
        }

        if system_prompt:
            payload["system"] = system_prompt

        for attempt in range(OLLAMA_MAX_RETRIES):
            try:
                logger.debug(
                    f"Calling Ollama API (attempt {attempt + 1}/{OLLAMA_MAX_RETRIES})"
                )

                response = self.session.post(
                    f"{self.api_url}/api/generate",
                    json=payload,
                    timeout=OLLAMA_TIMEOUT,
                )

                if response.status_code == 200:
                    result = response.json()
                    self._ollama_available = True
                    self._last_availability_check = time.time()
                    return result.get("response", "")
                else:
                    logger.warning(
                        f"Ollama API returned status {response.status_code}: {response.text}"
                    )

            except requests.exceptions.Timeout:
                logger.warning(f"Ollama API timeout (attempt {attempt + 1})")
            except requests.exceptions.RequestException as e:
                logger.error(f"Ollama API request failed: {e}")
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse Ollama response: {e}")

            if attempt < OLLAMA_MAX_RETRIES - 1:
                time.sleep(OLLAMA_RETRY_DELAY)

        logger.error("All Ollama API attempts failed")
        self._ollama_available = False
        self._last_availability_check = time.time()
        return None

    # ------------------------------------------------------------------
    # JSON / text response parsing (enhanced with regex fallback)
    # ------------------------------------------------------------------

    def _parse_ai_response(
        self, response: str, category: str
    ) -> List[AIRecommendation]:
        """
        Parse AI response into recommendation objects.

        Attempts multiple strategies in order:
        1. Direct JSON parse
        2. Regex extraction of a JSON object
        3. Regex extraction of a JSON array for findings
        4. Plain-text heuristic fallback

        Args:
            response: AI response text
            category: Category of analysis

        Returns:
            List of AIRecommendation objects
        """
        recommendations: List[AIRecommendation] = []

        # ---- Strategy 1: try direct JSON parse ----
        try:
            data = json.loads(response)
            recommendations = self._extract_findings(data, category)
            if recommendations:
                return recommendations
        except (json.JSONDecodeError, ValueError):
            pass

        # ---- Strategy 2: regex for outermost JSON object ----
        try:
            json_obj_match = re.search(r"\{[\s\S]*\}", response)
            if json_obj_match:
                data = json.loads(json_obj_match.group(0))
                recommendations = self._extract_findings(data, category)
                if recommendations:
                    return recommendations
        except (json.JSONDecodeError, ValueError):
            pass

        # ---- Strategy 3: regex for JSON array (bare findings list) ----
        try:
            json_arr_match = re.search(r"\[[\s\S]*\]", response)
            if json_arr_match:
                arr = json.loads(json_arr_match.group(0))
                if isinstance(arr, list):
                    recommendations = self._findings_list_to_recs(arr, category)
                    if recommendations:
                        return recommendations
        except (json.JSONDecodeError, ValueError):
            pass

        # ---- Strategy 4: regex extraction of individual finding objects ----
        try:
            finding_pattern = re.compile(
                r'\{\s*"severity"\s*:\s*"[^"]*"[\s\S]*?\}', re.MULTILINE
            )
            matches = finding_pattern.findall(response)
            for match_str in matches:
                try:
                    finding = json.loads(match_str)
                    if isinstance(finding, dict) and "severity" in finding:
                        rec = AIRecommendation(
                            severity=finding.get("severity", SEVERITY_INFO),
                            description=finding.get("description", ""),
                            recommendation=finding.get("recommendation", ""),
                            command=finding.get("command"),
                            category=category,
                        )
                        recommendations.append(rec)
                except (json.JSONDecodeError, ValueError):
                    continue
            if recommendations:
                return recommendations
        except Exception:
            pass

        # ---- Strategy 5: plain-text heuristic ----
        logger.warning(
            "Could not parse AI response as JSON, falling back to text parsing"
        )
        return self._parse_text_response(response, category)

    def _extract_findings(
        self, data: dict, category: str
    ) -> List[AIRecommendation]:
        """Extract findings from a parsed JSON dict."""
        findings = data.get("findings", [])
        if not isinstance(findings, list):
            return []
        return self._findings_list_to_recs(findings, category)

    def _findings_list_to_recs(
        self, findings: list, category: str
    ) -> List[AIRecommendation]:
        """Convert a list of finding dicts to AIRecommendation objects."""
        recs: List[AIRecommendation] = []
        for finding in findings:
            if isinstance(finding, dict):
                rec = AIRecommendation(
                    severity=finding.get("severity", SEVERITY_INFO),
                    description=finding.get("description", ""),
                    recommendation=finding.get("recommendation", ""),
                    command=finding.get("command"),
                    category=category,
                )
                recs.append(rec)
        return recs

    def _parse_text_response(
        self, response: str, category: str
    ) -> List[AIRecommendation]:
        """
        Fallback parser for non-JSON responses.

        Args:
            response: AI response text
            category: Category of analysis

        Returns:
            List of AIRecommendation objects
        """
        recommendations: List[AIRecommendation] = []

        # Split by paragraphs and look for key indicators
        paragraphs = [p.strip() for p in response.split("\n\n") if p.strip()]

        for para in paragraphs:
            severity = SEVERITY_INFO

            # Determine severity from keywords
            para_lower = para.lower()
            if any(
                word in para_lower
                for word in [
                    "critical",
                    "severe",
                    "urgent",
                    "vulnerable",
                    "compromised",
                    "exploit",
                    "breach",
                ]
            ):
                severity = SEVERITY_CRITICAL
            elif any(
                word in para_lower
                for word in [
                    "warning",
                    "concern",
                    "issue",
                    "problem",
                    "risk",
                    "caution",
                    "attention",
                ]
            ):
                severity = SEVERITY_WARNING

            # Extract command if present (backtick-delimited)
            command = None
            cmd_match = re.search(r"`([^`]+)`", para)
            if cmd_match:
                command = cmd_match.group(1)

            rec = AIRecommendation(
                severity=severity,
                description=para[:200],
                recommendation=para,
                command=command,
                category=category,
            )
            recommendations.append(rec)

        return recommendations

    # ------------------------------------------------------------------
    # AI-backed analysis methods (existing, enhanced with fallback)
    # ------------------------------------------------------------------

    def analyze_security(self, scan_data: Dict) -> List[AIRecommendation]:
        """
        Perform security analysis on scan data.

        Falls back to rule-based analysis when Ollama is not available.

        Args:
            scan_data: Network scan data dictionary

        Returns:
            List of security recommendations
        """
        logger.info("Performing security analysis")

        # Try AI analysis first
        if self.is_available:
            scan_json = json.dumps(scan_data, indent=2)
            prompt = AI_SECURITY_ANALYSIS_PROMPT.format(scan_data=scan_json)
            response = self._call_ollama(prompt, AI_SYSTEM_PROMPT)

            if response:
                recommendations = self._parse_ai_response(response, "security")
                logger.info(
                    f"AI generated {len(recommendations)} security recommendations"
                )
                return recommendations

        # Fallback to rule-based analysis
        logger.info("Ollama unavailable - using rule-based security analysis")
        return self.analyze_security_rules(scan_data)

    def analyze_network_health(self, scan_data: Dict) -> List[AIRecommendation]:
        """
        Perform network health analysis.

        Falls back to rule-based analysis when Ollama is not available.

        Args:
            scan_data: Network scan data dictionary

        Returns:
            List of health recommendations
        """
        logger.info("Performing network health analysis")

        if self.is_available:
            scan_json = json.dumps(scan_data, indent=2)
            prompt = AI_NETWORK_HEALTH_PROMPT.format(scan_data=scan_json)
            response = self._call_ollama(prompt, AI_SYSTEM_PROMPT)

            if response:
                recommendations = self._parse_ai_response(response, "health")
                logger.info(
                    f"AI generated {len(recommendations)} health recommendations"
                )
                return recommendations

        # Fallback: derive health insights from rules
        logger.info("Ollama unavailable - using rule-based health analysis")
        return self._analyze_health_rules(scan_data)

    def analyze_wifi_optimization(
        self, wifi_data: Dict
    ) -> List[AIRecommendation]:
        """
        Perform WiFi optimization analysis.

        Falls back to rule-based analysis when Ollama is not available.

        Args:
            wifi_data: WiFi metrics and scan data

        Returns:
            List of optimization recommendations
        """
        logger.info("Performing WiFi optimization analysis")

        if self.is_available:
            wifi_json = json.dumps(wifi_data, indent=2)
            prompt = AI_WIFI_OPTIMIZATION_PROMPT.format(scan_data=wifi_json)
            response = self._call_ollama(prompt, AI_SYSTEM_PROMPT)

            if response:
                recommendations = self._parse_ai_response(response, "wifi")
                logger.info(
                    f"AI generated {len(recommendations)} WiFi recommendations"
                )
                return recommendations

        # Fallback: rule-based WiFi analysis
        logger.info("Ollama unavailable - using rule-based WiFi analysis")
        return self._analyze_wifi_rules(wifi_data)

    def analyze_comprehensive(
        self,
        scan_data: Dict,
        wifi_data: Optional[Dict] = None,
    ) -> Dict[str, List[AIRecommendation]]:
        """
        Perform comprehensive analysis across all categories.

        Args:
            scan_data: Network scan data
            wifi_data: WiFi metrics (optional)

        Returns:
            Dictionary mapping category to recommendations
        """
        logger.info("Performing comprehensive analysis")

        results: Dict[str, List[AIRecommendation]] = {
            "security": [],
            "health": [],
            "wifi": [],
        }

        # Security analysis
        try:
            results["security"] = self.analyze_security(scan_data)
        except Exception as e:
            logger.error(f"Security analysis failed: {e}")

        # Network health analysis
        try:
            results["health"] = self.analyze_network_health(scan_data)
        except Exception as e:
            logger.error(f"Health analysis failed: {e}")

        # WiFi optimization (if data available)
        if wifi_data:
            try:
                results["wifi"] = self.analyze_wifi_optimization(wifi_data)
            except Exception as e:
                logger.error(f"WiFi analysis failed: {e}")

        total_recommendations = sum(len(recs) for recs in results.values())
        logger.info(
            f"Comprehensive analysis complete: {total_recommendations} total recommendations"
        )

        return results

    # ------------------------------------------------------------------
    # Rule-based offline analysis
    # ------------------------------------------------------------------

    def analyze_security_rules(self, scan_data: Dict) -> List[AIRecommendation]:
        """
        Rule-based security analysis that works without Ollama.

        Checks for:
        - Devices with dangerous ports open (telnet, FTP, RDP, SMB, etc.)
        - Unknown vendor devices
        - Devices with many open ports (>10)
        - Risky port combinations (e.g. SSH + RDP)
        - Default gateway having unexpected ports open

        Args:
            scan_data: Network scan data dictionary

        Returns:
            List of security recommendations
        """
        recommendations: List[AIRecommendation] = []
        devices = scan_data.get("devices", [])
        gateway_ip = scan_data.get("gateway", scan_data.get("gateway_ip"))

        for device in devices:
            ip = device.get("ip", "unknown")
            vendor = device.get("vendor") or ""
            hostname = device.get("hostname", "")
            open_ports = device.get("open_ports", [])
            is_gateway = (gateway_ip and ip == gateway_ip) or hostname.lower() in (
                "router",
                "gateway",
            )

            # --- Dangerous ports ---
            for port in open_ports:
                port_int = int(port) if not isinstance(port, int) else port
                if port_int in DANGEROUS_PORTS:
                    port_name, risk_desc = DANGEROUS_PORTS[port_int]
                    sev = SEVERITY_CRITICAL if port_int in (23, 21, 445, 3389) else SEVERITY_WARNING
                    recommendations.append(
                        AIRecommendation(
                            severity=sev,
                            description=(
                                f"Device {ip} has port {port_int}/{port_name} open. "
                                f"{risk_desc}."
                            ),
                            recommendation=(
                                f"Disable {port_name} on {ip} if not explicitly required. "
                                f"Replace with encrypted alternatives where possible "
                                f"(e.g. SFTP instead of FTP, SSH instead of Telnet)."
                            ),
                            command=f"nmap -sV -p {port_int} {ip}",
                            category="security",
                        )
                    )

            # --- Risky port combinations ---
            port_set = set(
                int(p) if not isinstance(p, int) else p for p in open_ports
            )
            for combo_ports, combo_desc in RISKY_COMBINATIONS:
                if combo_ports.issubset(port_set):
                    recommendations.append(
                        AIRecommendation(
                            severity=SEVERITY_WARNING,
                            description=f"Device {ip}: {combo_desc}.",
                            recommendation=(
                                f"Review remote-access services on {ip} and disable "
                                f"redundant or insecure protocols."
                            ),
                            category="security",
                        )
                    )

            # --- Too many open ports ---
            if len(open_ports) > 10:
                recommendations.append(
                    AIRecommendation(
                        severity=SEVERITY_WARNING,
                        description=(
                            f"Device {ip} has {len(open_ports)} open ports, which is "
                            f"unusually high and increases the attack surface."
                        ),
                        recommendation=(
                            f"Audit all services on {ip}. Disable any that are not "
                            f"explicitly required. Consider host-based firewall rules."
                        ),
                        command=f"nmap -sV -T4 {ip}",
                        category="security",
                    )
                )

            # --- Unknown vendor ---
            if not vendor or vendor.lower() in ("unknown", ""):
                recommendations.append(
                    AIRecommendation(
                        severity=SEVERITY_WARNING,
                        description=(
                            f"Device {ip} has an unknown or missing vendor identifier "
                            f"(MAC: {device.get('mac', 'N/A')}). This could indicate a "
                            f"spoofed MAC address or an unrecognised device."
                        ),
                        recommendation=(
                            f"Investigate device at {ip}. Verify it belongs to your "
                            f"network. Check MAC address against manufacturer databases."
                        ),
                        command=f"nmap -sV -O {ip}",
                        category="security",
                    )
                )

            # --- Gateway with unexpected ports ---
            if is_gateway:
                unexpected = port_set - EXPECTED_GATEWAY_PORTS
                dangerous_on_gw = {
                    p for p in unexpected if p in DANGEROUS_PORTS
                }
                if dangerous_on_gw:
                    port_list = ", ".join(
                        f"{p}/{DANGEROUS_PORTS[p][0]}" for p in sorted(dangerous_on_gw)
                    )
                    recommendations.append(
                        AIRecommendation(
                            severity=SEVERITY_CRITICAL,
                            description=(
                                f"Gateway {ip} has unexpected dangerous ports open: "
                                f"{port_list}."
                            ),
                            recommendation=(
                                f"Immediately review gateway configuration. Disable "
                                f"unnecessary services. A compromised gateway puts the "
                                f"entire network at risk."
                            ),
                            command=f"nmap -sV -p- {ip}",
                            category="security",
                        )
                    )

        # --- Network-level observations ---
        if not devices:
            recommendations.append(
                AIRecommendation(
                    severity=SEVERITY_INFO,
                    description="No devices detected in the scan data.",
                    recommendation=(
                        "Verify scanner configuration and network connectivity. "
                        "Ensure nmap has appropriate permissions."
                    ),
                    command="nmap -sn 192.168.1.0/24",
                    category="security",
                )
            )

        if not recommendations:
            recommendations.append(
                AIRecommendation(
                    severity=SEVERITY_INFO,
                    description=(
                        "No obvious security issues detected by rule-based analysis."
                    ),
                    recommendation=(
                        "Continue monitoring. Consider running a full vulnerability "
                        "scan periodically for deeper analysis."
                    ),
                    category="security",
                )
            )

        logger.info(
            f"Rule-based analysis produced {len(recommendations)} security findings"
        )
        return recommendations

    # ------------------------------------------------------------------
    # Anomaly detection
    # ------------------------------------------------------------------

    def analyze_anomalies(
        self,
        current_scan: Dict,
        previous_scans: Optional[List[Dict]] = None,
    ) -> List[AIRecommendation]:
        """
        Detect anomalies by comparing the current scan against previous scans.

        Detects:
        - New devices not seen before
        - Devices that disappeared
        - Ports that opened or closed since last scan
        - Unusual ports on any device
        - Devices with significantly changed open-port counts

        Args:
            current_scan: The latest network scan data
            previous_scans: List of earlier scan data dicts (most recent first).
                            May be None or empty.

        Returns:
            List of anomaly recommendations
        """
        recommendations: List[AIRecommendation] = []
        current_devices = {
            d.get("ip"): d for d in current_scan.get("devices", [])
        }

        # --- Unusual ports on current devices (no history needed) ---
        for ip, device in current_devices.items():
            open_ports = device.get("open_ports", [])
            port_set = set(
                int(p) if not isinstance(p, int) else p for p in open_ports
            )
            unusual = port_set & set(DANGEROUS_PORTS.keys())
            if unusual:
                port_desc = ", ".join(
                    f"{p}/{DANGEROUS_PORTS[p][0]}" for p in sorted(unusual)
                )
                recommendations.append(
                    AIRecommendation(
                        severity=SEVERITY_WARNING,
                        description=(
                            f"Anomaly: Device {ip} has unusual ports open: {port_desc}."
                        ),
                        recommendation=(
                            f"Investigate whether these services are expected on {ip}."
                        ),
                        category="anomaly",
                    )
                )

        # --- Trend-based anomalies (require at least one previous scan) ---
        if not previous_scans:
            if not recommendations:
                recommendations.append(
                    AIRecommendation(
                        severity=SEVERITY_INFO,
                        description=(
                            "No previous scans available for trend-based anomaly detection."
                        ),
                        recommendation=(
                            "Anomaly detection will improve as more scan history "
                            "accumulates."
                        ),
                        category="anomaly",
                    )
                )
            return recommendations

        # Use the most recent previous scan for comparison
        prev_scan = previous_scans[0]
        prev_devices = {
            d.get("ip"): d for d in prev_scan.get("devices", [])
        }

        # Build set of all IPs ever seen across all history
        all_historical_ips: set = set()
        for scan in previous_scans:
            for d in scan.get("devices", []):
                if d.get("ip"):
                    all_historical_ips.add(d["ip"])

        # -- New devices --
        new_ips = set(current_devices.keys()) - all_historical_ips
        for ip in sorted(new_ips):
            dev = current_devices[ip]
            vendor = dev.get("vendor") or "unknown vendor"
            recommendations.append(
                AIRecommendation(
                    severity=SEVERITY_WARNING,
                    description=(
                        f"Anomaly: New device detected at {ip} ({vendor}) - "
                        f"never seen in previous scans."
                    ),
                    recommendation=(
                        f"Verify this device is authorised to be on the network. "
                        f"Check MAC address {dev.get('mac', 'N/A')} against "
                        f"known inventory."
                    ),
                    command=f"nmap -sV -O {ip}",
                    category="anomaly",
                )
            )

        # -- Disappeared devices (present in last scan, missing now) --
        disappeared_ips = set(prev_devices.keys()) - set(current_devices.keys())
        for ip in sorted(disappeared_ips):
            prev_dev = prev_devices[ip]
            vendor = prev_dev.get("vendor") or "unknown vendor"
            recommendations.append(
                AIRecommendation(
                    severity=SEVERITY_INFO,
                    description=(
                        f"Device {ip} ({vendor}) was present in the previous scan "
                        f"but is no longer detected."
                    ),
                    recommendation=(
                        f"This may be normal (device powered off or moved). "
                        f"Investigate if the device is expected to be always-on."
                    ),
                    category="anomaly",
                )
            )

        # -- Port changes on existing devices --
        for ip in sorted(set(current_devices.keys()) & set(prev_devices.keys())):
            curr_ports = set(
                int(p) if not isinstance(p, int) else p
                for p in current_devices[ip].get("open_ports", [])
            )
            prev_ports = set(
                int(p) if not isinstance(p, int) else p
                for p in prev_devices[ip].get("open_ports", [])
            )

            opened = curr_ports - prev_ports
            closed = prev_ports - curr_ports

            if opened:
                port_list = ", ".join(str(p) for p in sorted(opened))
                sev = SEVERITY_WARNING
                # Escalate if any newly opened port is dangerous
                if opened & set(DANGEROUS_PORTS.keys()):
                    sev = SEVERITY_CRITICAL
                recommendations.append(
                    AIRecommendation(
                        severity=sev,
                        description=(
                            f"Anomaly: Device {ip} has new ports opened since last "
                            f"scan: {port_list}."
                        ),
                        recommendation=(
                            f"Investigate why new services appeared on {ip}. "
                            f"This could indicate new software installs or compromise."
                        ),
                        command=f"nmap -sV -p {port_list.replace(' ', '')} {ip}",
                        category="anomaly",
                    )
                )

            if closed:
                port_list = ", ".join(str(p) for p in sorted(closed))
                recommendations.append(
                    AIRecommendation(
                        severity=SEVERITY_INFO,
                        description=(
                            f"Device {ip} has ports that closed since last scan: "
                            f"{port_list}."
                        ),
                        recommendation=(
                            f"Typically benign. Verify services on {ip} are running "
                            f"as expected."
                        ),
                        category="anomaly",
                    )
                )

        if not recommendations:
            recommendations.append(
                AIRecommendation(
                    severity=SEVERITY_INFO,
                    description="No anomalies detected compared to previous scans.",
                    recommendation="Network appears stable. Continue monitoring.",
                    category="anomaly",
                )
            )

        logger.info(
            f"Anomaly detection produced {len(recommendations)} findings"
        )
        return recommendations

    # ------------------------------------------------------------------
    # Security scoring
    # ------------------------------------------------------------------

    def calculate_security_score(self, scan_data: Dict) -> Dict:
        """
        Calculate a 0-100 security score for the network.

        Scoring methodology (start at 100 and subtract penalties):
        - Each device with a dangerous port open: -5 (critical ports -8)
        - Each unknown-vendor device: -3
        - Each device with >10 open ports: -4
        - Each risky port combination: -3
        - Gateway with dangerous ports: -10
        - No devices found: score fixed at 50 (uncertain)

        The score is clamped to the range [0, 100].

        Args:
            scan_data: Network scan data dictionary

        Returns:
            Dictionary with 'score', 'grade', 'penalties', and 'summary' keys
        """
        score = 100
        penalties: List[Dict[str, object]] = []
        devices = scan_data.get("devices", [])
        gateway_ip = scan_data.get("gateway", scan_data.get("gateway_ip"))

        if not devices:
            return {
                "score": 50,
                "grade": "N/A",
                "penalties": [],
                "summary": "No devices found - unable to assess network security.",
            }

        critical_dangerous = {23, 21, 445, 3389}

        for device in devices:
            ip = device.get("ip", "unknown")
            vendor = device.get("vendor") or ""
            hostname = device.get("hostname", "")
            open_ports = device.get("open_ports", [])
            port_set = set(
                int(p) if not isinstance(p, int) else p for p in open_ports
            )
            is_gateway = (gateway_ip and ip == gateway_ip) or hostname.lower() in (
                "router",
                "gateway",
            )

            # Dangerous ports
            for port_int in port_set:
                if port_int in DANGEROUS_PORTS:
                    if port_int in critical_dangerous:
                        penalty = 8
                    else:
                        penalty = 5
                    port_name = DANGEROUS_PORTS[port_int][0]
                    score -= penalty
                    penalties.append(
                        {
                            "device": ip,
                            "reason": f"Port {port_int}/{port_name} open",
                            "points": penalty,
                        }
                    )

            # Unknown vendor
            if not vendor or vendor.lower() in ("unknown", ""):
                score -= 3
                penalties.append(
                    {
                        "device": ip,
                        "reason": "Unknown vendor",
                        "points": 3,
                    }
                )

            # Many open ports
            if len(open_ports) > 10:
                score -= 4
                penalties.append(
                    {
                        "device": ip,
                        "reason": f"{len(open_ports)} open ports",
                        "points": 4,
                    }
                )

            # Risky combinations
            for combo_ports, combo_desc in RISKY_COMBINATIONS:
                if combo_ports.issubset(port_set):
                    score -= 3
                    penalties.append(
                        {
                            "device": ip,
                            "reason": combo_desc,
                            "points": 3,
                        }
                    )

            # Gateway-specific
            if is_gateway:
                dangerous_on_gw = port_set & set(DANGEROUS_PORTS.keys()) - EXPECTED_GATEWAY_PORTS
                if dangerous_on_gw:
                    score -= 10
                    penalties.append(
                        {
                            "device": ip,
                            "reason": "Gateway has dangerous ports open",
                            "points": 10,
                        }
                    )

        score = max(0, min(100, score))

        # Grade
        if score >= 90:
            grade = "A"
        elif score >= 80:
            grade = "B"
        elif score >= 70:
            grade = "C"
        elif score >= 60:
            grade = "D"
        else:
            grade = "F"

        # Summary
        if score >= 90:
            summary = "Excellent security posture. No significant risks detected."
        elif score >= 80:
            summary = "Good security posture with minor issues to address."
        elif score >= 70:
            summary = "Fair security posture. Several issues should be reviewed."
        elif score >= 60:
            summary = "Below average security. Multiple issues require attention."
        else:
            summary = "Poor security posture. Immediate action recommended."

        result = {
            "score": score,
            "grade": grade,
            "penalties": penalties,
            "summary": summary,
        }

        logger.info(f"Security score: {score}/100 (Grade: {grade})")
        return result

    # ------------------------------------------------------------------
    # Quick insights (enhanced)
    # ------------------------------------------------------------------

    def get_quick_insights(self, scan_data: Dict) -> List[str]:
        """
        Get quick insights without full analysis.

        Enhanced to include more insight types:
        - Device count and overview
        - Devices with many open ports
        - Unknown-vendor devices
        - Dangerous-port exposure summary
        - Gateway status
        - Security score summary

        Args:
            scan_data: Network scan data

        Returns:
            List of quick insight strings
        """
        insights: List[str] = []
        devices = scan_data.get("devices", [])
        device_count = scan_data.get("device_count", len(devices))
        gateway_ip = scan_data.get("gateway", scan_data.get("gateway_ip"))

        # Device count
        insights.append(f"Detected {device_count} active devices on the network")

        # Vendor breakdown
        vendors: Dict[str, int] = {}
        for device in devices:
            v = device.get("vendor") or "Unknown"
            vendors[v] = vendors.get(v, 0) + 1
        if vendors:
            top_vendors = sorted(vendors.items(), key=lambda x: x[1], reverse=True)[:3]
            vendor_str = ", ".join(f"{v} ({c})" for v, c in top_vendors)
            insights.append(f"Top vendors: {vendor_str}")

        # Devices with many open ports
        for device in devices:
            open_ports = device.get("open_ports", [])
            if len(open_ports) > 10:
                insights.append(
                    f"Warning: Device {device.get('ip')} has {len(open_ports)} open ports"
                )

        # Unknown devices
        unknown_devices = [
            d
            for d in devices
            if not d.get("vendor") or d.get("vendor", "").lower() in ("unknown", "")
        ]
        if unknown_devices:
            insights.append(
                f"Found {len(unknown_devices)} devices with unknown vendors"
            )

        # Dangerous port exposure
        dangerous_count = 0
        critical_ports_found: List[str] = []
        for device in devices:
            port_set = set(
                int(p) if not isinstance(p, int) else p
                for p in device.get("open_ports", [])
            )
            dangerous = port_set & set(DANGEROUS_PORTS.keys())
            if dangerous:
                dangerous_count += 1
                for p in dangerous:
                    critical_ports_found.append(
                        f"{device.get('ip')}:{p}/{DANGEROUS_PORTS[p][0]}"
                    )
        if dangerous_count:
            insights.append(
                f"Alert: {dangerous_count} device(s) expose potentially dangerous services"
            )
            # List up to 5 specific findings
            for entry in critical_ports_found[:5]:
                insights.append(f"  - {entry}")
            if len(critical_ports_found) > 5:
                insights.append(
                    f"  ...and {len(critical_ports_found) - 5} more"
                )

        # Gateway status
        if gateway_ip:
            gw_device = next(
                (d for d in devices if d.get("ip") == gateway_ip), None
            )
            if gw_device:
                gw_ports = len(gw_device.get("open_ports", []))
                insights.append(
                    f"Gateway ({gateway_ip}) detected with {gw_ports} open port(s)"
                )
            else:
                insights.append(
                    f"Gateway ({gateway_ip}) was not found in scan results"
                )

        # Quick security score
        score_data = self.calculate_security_score(scan_data)
        insights.append(
            f"Security score: {score_data['score']}/100 (Grade: {score_data['grade']}) "
            f"- {score_data['summary']}"
        )

        return insights

    # ------------------------------------------------------------------
    # Rule-based health analysis (offline fallback)
    # ------------------------------------------------------------------

    def _analyze_health_rules(self, scan_data: Dict) -> List[AIRecommendation]:
        """
        Rule-based network health analysis (offline fallback).

        Args:
            scan_data: Network scan data dictionary

        Returns:
            List of health recommendations
        """
        recommendations: List[AIRecommendation] = []
        devices = scan_data.get("devices", [])
        device_count = scan_data.get("device_count", len(devices))

        # High device count
        if device_count > 50:
            recommendations.append(
                AIRecommendation(
                    severity=SEVERITY_WARNING,
                    description=(
                        f"High number of devices detected ({device_count}). "
                        f"This may indicate network congestion or unauthorised devices."
                    ),
                    recommendation=(
                        "Review the device list and remove any unauthorised devices. "
                        "Consider segmenting the network with VLANs."
                    ),
                    category="health",
                )
            )
        elif device_count > 25:
            recommendations.append(
                AIRecommendation(
                    severity=SEVERITY_INFO,
                    description=(
                        f"Moderate number of devices detected ({device_count})."
                    ),
                    recommendation=(
                        "Monitor for growth. Consider VLAN segmentation if device "
                        "count continues increasing."
                    ),
                    category="health",
                )
            )

        # Devices running many services (performance perspective)
        for device in devices:
            ip = device.get("ip", "unknown")
            open_ports = device.get("open_ports", [])
            if len(open_ports) > 20:
                recommendations.append(
                    AIRecommendation(
                        severity=SEVERITY_WARNING,
                        description=(
                            f"Device {ip} runs {len(open_ports)} services. "
                            f"High service count can degrade performance and "
                            f"complicate maintenance."
                        ),
                        recommendation=(
                            f"Audit services on {ip}. Consolidate or decommission "
                            f"any services that are no longer needed."
                        ),
                        category="health",
                    )
                )

        # Check for duplicate hostnames (possible misconfiguration)
        hostnames: Dict[str, List[str]] = {}
        for device in devices:
            hn = device.get("hostname")
            if hn and hn.lower() not in ("unknown", ""):
                hostnames.setdefault(hn.lower(), []).append(device.get("ip", "unknown"))
        for hn, ips in hostnames.items():
            if len(ips) > 1:
                ip_list = ", ".join(ips)
                recommendations.append(
                    AIRecommendation(
                        severity=SEVERITY_WARNING,
                        description=(
                            f"Duplicate hostname '{hn}' found on multiple devices: "
                            f"{ip_list}."
                        ),
                        recommendation=(
                            "Resolve hostname conflicts to prevent DNS and "
                            "connectivity issues."
                        ),
                        category="health",
                    )
                )

        if not recommendations:
            recommendations.append(
                AIRecommendation(
                    severity=SEVERITY_INFO,
                    description="Network health appears normal based on rule-based analysis.",
                    recommendation=(
                        "No significant health issues detected. "
                        "Continue regular monitoring."
                    ),
                    category="health",
                )
            )

        return recommendations

    # ------------------------------------------------------------------
    # Rule-based WiFi analysis (offline fallback)
    # ------------------------------------------------------------------

    def _analyze_wifi_rules(self, wifi_data: Dict) -> List[AIRecommendation]:
        """
        Rule-based WiFi optimization without AI.

        Analyses signal strength, channel utilisation, band usage, noise,
        and neighbouring network interference.

        Args:
            wifi_data: WiFi metrics and scan data. Expected keys include
                       'signal_strength', 'noise', 'channel', 'frequency',
                       'band', 'tx_rate', 'rx_rate', 'neighbors', etc.

        Returns:
            List of WiFi optimization recommendations
        """
        recommendations: List[AIRecommendation] = []

        signal = wifi_data.get("signal_strength") or wifi_data.get("signal")
        noise = wifi_data.get("noise") or wifi_data.get("noise_level")
        channel = wifi_data.get("channel")
        frequency = wifi_data.get("frequency")
        band = wifi_data.get("band", "")
        tx_rate = wifi_data.get("tx_rate") or wifi_data.get("tx_bitrate")
        rx_rate = wifi_data.get("rx_rate") or wifi_data.get("rx_bitrate")
        neighbors = wifi_data.get("neighbors", wifi_data.get("nearby_networks", []))

        # --- Signal strength ---
        if signal is not None:
            try:
                signal_val = int(signal)
            except (ValueError, TypeError):
                signal_val = None

            if signal_val is not None:
                if signal_val < -80:
                    recommendations.append(
                        AIRecommendation(
                            severity=SEVERITY_CRITICAL,
                            description=(
                                f"WiFi signal is very weak ({signal_val} dBm). "
                                f"Connection will be unreliable with frequent drops."
                            ),
                            recommendation=(
                                "Move closer to the access point, reduce physical "
                                "obstructions, or add a WiFi extender/mesh node. "
                                "Consider switching to 2.4 GHz for better range."
                            ),
                            command="iwconfig",
                            category="wifi",
                        )
                    )
                elif signal_val < -70:
                    recommendations.append(
                        AIRecommendation(
                            severity=SEVERITY_WARNING,
                            description=(
                                f"WiFi signal is fair ({signal_val} dBm). "
                                f"May experience reduced throughput."
                            ),
                            recommendation=(
                                "Reposition the router or device for better line of "
                                "sight. Remove sources of interference (microwave ovens, "
                                "cordless phones near 2.4 GHz)."
                            ),
                            category="wifi",
                        )
                    )
                elif signal_val < -60:
                    recommendations.append(
                        AIRecommendation(
                            severity=SEVERITY_INFO,
                            description=(
                                f"WiFi signal is good ({signal_val} dBm)."
                            ),
                            recommendation=(
                                "Signal is adequate. For optimal performance, try to "
                                "achieve -50 dBm or better."
                            ),
                            category="wifi",
                        )
                    )
                else:
                    recommendations.append(
                        AIRecommendation(
                            severity=SEVERITY_INFO,
                            description=(
                                f"WiFi signal is excellent ({signal_val} dBm)."
                            ),
                            recommendation="No action needed for signal strength.",
                            category="wifi",
                        )
                    )

        # --- Signal-to-noise ratio ---
        if signal is not None and noise is not None:
            try:
                snr = int(signal) - int(noise)
                if snr < 10:
                    recommendations.append(
                        AIRecommendation(
                            severity=SEVERITY_CRITICAL,
                            description=(
                                f"Signal-to-noise ratio is critically low ({snr} dB). "
                                f"Connection quality will be severely degraded."
                            ),
                            recommendation=(
                                "Identify and eliminate sources of RF interference. "
                                "Consider switching bands or channels. A directional "
                                "antenna may help."
                            ),
                            category="wifi",
                        )
                    )
                elif snr < 20:
                    recommendations.append(
                        AIRecommendation(
                            severity=SEVERITY_WARNING,
                            description=(
                                f"Signal-to-noise ratio is marginal ({snr} dB). "
                                f"Throughput may be reduced."
                            ),
                            recommendation=(
                                "Try changing WiFi channels or moving away from "
                                "sources of interference."
                            ),
                            category="wifi",
                        )
                    )
            except (ValueError, TypeError):
                pass

        # --- Channel congestion from neighbours ---
        if channel is not None and neighbors:
            same_channel_count = 0
            for neighbor in neighbors:
                n_channel = neighbor.get("channel")
                if n_channel is not None:
                    try:
                        if int(n_channel) == int(channel):
                            same_channel_count += 1
                    except (ValueError, TypeError):
                        pass

            if same_channel_count > 3:
                recommendations.append(
                    AIRecommendation(
                        severity=SEVERITY_WARNING,
                        description=(
                            f"Channel {channel} is congested - "
                            f"{same_channel_count} neighbouring networks on the "
                            f"same channel."
                        ),
                        recommendation=(
                            "Switch to a less congested channel. For 2.4 GHz, use "
                            "channels 1, 6, or 11 (non-overlapping). For 5 GHz, use "
                            "DFS channels (52-144) if supported."
                        ),
                        command="iwlist scan",
                        category="wifi",
                    )
                )
            elif same_channel_count > 1:
                recommendations.append(
                    AIRecommendation(
                        severity=SEVERITY_INFO,
                        description=(
                            f"Channel {channel} has {same_channel_count} neighbouring "
                            f"network(s). Minor interference possible."
                        ),
                        recommendation=(
                            "Consider switching channels if you notice performance "
                            "degradation."
                        ),
                        category="wifi",
                    )
                )

            # Overall neighbour density
            if len(neighbors) > 15:
                recommendations.append(
                    AIRecommendation(
                        severity=SEVERITY_WARNING,
                        description=(
                            f"High WiFi density detected - {len(neighbors)} nearby "
                            f"networks. This can cause significant interference."
                        ),
                        recommendation=(
                            "Use 5 GHz or 6 GHz band if available. Reduce transmit "
                            "power if devices are close to the AP to minimise "
                            "interference with neighbours."
                        ),
                        category="wifi",
                    )
                )

        # --- Band recommendations ---
        if band:
            band_lower = band.lower().replace(" ", "")
            if "2.4" in band_lower:
                recommendations.append(
                    AIRecommendation(
                        severity=SEVERITY_INFO,
                        description=(
                            "Currently connected on the 2.4 GHz band which offers "
                            "better range but lower throughput."
                        ),
                        recommendation=(
                            "If you are close to the router and need higher speeds, "
                            "switch to 5 GHz. 2.4 GHz is best for IoT devices and "
                            "long-range connections."
                        ),
                        category="wifi",
                    )
                )
            elif "6" in band_lower and "5" not in band_lower:
                recommendations.append(
                    AIRecommendation(
                        severity=SEVERITY_INFO,
                        description=(
                            "Connected on 6 GHz band - excellent for high throughput "
                            "and low interference."
                        ),
                        recommendation=(
                            "6 GHz offers the best performance. Ensure all critical "
                            "devices support WiFi 6E or later."
                        ),
                        category="wifi",
                    )
                )

        # --- Link speed ---
        for rate_val, rate_label in [
            (tx_rate, "transmit"),
            (rx_rate, "receive"),
        ]:
            if rate_val is not None:
                try:
                    rate_num = float(str(rate_val).split()[0])
                    if rate_num < 10:
                        recommendations.append(
                            AIRecommendation(
                                severity=SEVERITY_WARNING,
                                description=(
                                    f"WiFi {rate_label} rate is very low "
                                    f"({rate_val}). This indicates poor link quality."
                                ),
                                recommendation=(
                                    "Check signal strength, reduce interference, or "
                                    "move closer to the access point."
                                ),
                                category="wifi",
                            )
                        )
                except (ValueError, TypeError, IndexError):
                    pass

        if not recommendations:
            recommendations.append(
                AIRecommendation(
                    severity=SEVERITY_INFO,
                    description="WiFi configuration appears reasonable.",
                    recommendation=(
                        "No significant WiFi issues detected. "
                        "Continue monitoring for changes."
                    ),
                    category="wifi",
                )
            )

        return recommendations


if __name__ == "__main__":
    # Test the AI analyzer
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    # Sample scan data
    sample_data = {
        "device_count": 5,
        "gateway": "192.168.1.1",
        "devices": [
            {
                "ip": "192.168.1.1",
                "mac": "00:11:22:33:44:55",
                "hostname": "router",
                "vendor": "Netgear",
                "open_ports": [80, 443, 23],
            },
            {
                "ip": "192.168.1.100",
                "mac": "AA:BB:CC:DD:EE:FF",
                "hostname": "unknown",
                "vendor": None,
                "open_ports": [22, 23, 3389],
            },
            {
                "ip": "192.168.1.101",
                "mac": "11:22:33:44:55:66",
                "hostname": "fileserver",
                "vendor": "Dell",
                "open_ports": [22, 80, 443, 139, 445, 3306, 8080],
            },
            {
                "ip": "192.168.1.102",
                "mac": "22:33:44:55:66:77",
                "hostname": "workstation",
                "vendor": "Lenovo",
                "open_ports": [22],
            },
            {
                "ip": "192.168.1.200",
                "mac": "33:44:55:66:77:88",
                "hostname": "printer",
                "vendor": "HP",
                "open_ports": [80, 443, 631, 9100],
            },
        ],
    }

    # Previous scan for anomaly testing
    previous_data = {
        "device_count": 4,
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
                "ip": "192.168.1.100",
                "mac": "AA:BB:CC:DD:EE:FF",
                "hostname": "unknown",
                "vendor": None,
                "open_ports": [22],
            },
            {
                "ip": "192.168.1.101",
                "mac": "11:22:33:44:55:66",
                "hostname": "fileserver",
                "vendor": "Dell",
                "open_ports": [22, 80, 443],
            },
            {
                "ip": "192.168.1.103",
                "mac": "44:55:66:77:88:99",
                "hostname": "laptop",
                "vendor": "Apple",
                "open_ports": [],
            },
        ],
    }

    sample_wifi = {
        "signal_strength": -72,
        "noise": -85,
        "channel": 6,
        "band": "2.4GHz",
        "tx_rate": "54 Mbps",
        "rx_rate": "48 Mbps",
        "neighbors": [
            {"ssid": "Neighbor1", "channel": 6, "signal": -65},
            {"ssid": "Neighbor2", "channel": 6, "signal": -70},
            {"ssid": "Neighbor3", "channel": 6, "signal": -75},
            {"ssid": "Neighbor4", "channel": 6, "signal": -80},
            {"ssid": "Neighbor5", "channel": 11, "signal": -72},
        ],
    }

    analyzer = AIAnalyzer()

    print("\n=== Quick Insights ===")
    insights = analyzer.get_quick_insights(sample_data)
    for insight in insights:
        print(f"  - {insight}")

    print("\n=== Security Score ===")
    score = analyzer.calculate_security_score(sample_data)
    print(f"  Score: {score['score']}/100  Grade: {score['grade']}")
    print(f"  Summary: {score['summary']}")
    if score["penalties"]:
        print("  Penalties:")
        for p in score["penalties"]:
            print(f"    - {p['device']}: {p['reason']} (-{p['points']})")

    print("\n=== Rule-Based Security Analysis ===")
    recommendations = analyzer.analyze_security_rules(sample_data)
    print(f"  Found {len(recommendations)} findings:")
    for rec in recommendations:
        print(f"\n  [{rec.severity.upper()}] {rec.description}")
        print(f"    Recommendation: {rec.recommendation}")
        if rec.command:
            print(f"    Command: {rec.command}")

    print("\n=== Anomaly Detection ===")
    anomalies = analyzer.analyze_anomalies(sample_data, [previous_data])
    print(f"  Found {len(anomalies)} anomalies:")
    for rec in anomalies:
        print(f"\n  [{rec.severity.upper()}] {rec.description}")
        print(f"    Recommendation: {rec.recommendation}")

    print("\n=== WiFi Optimization (Rule-Based) ===")
    wifi_recs = analyzer._analyze_wifi_rules(sample_wifi)
    print(f"  Found {len(wifi_recs)} recommendations:")
    for rec in wifi_recs:
        print(f"\n  [{rec.severity.upper()}] {rec.description}")
        print(f"    Recommendation: {rec.recommendation}")
