"""
AI Analyzer Module

Integrates with Ollama for network security and optimization analysis.
"""

import logging
import json
import time
from typing import Dict, List, Optional
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
    """AI-powered network analysis using Ollama."""

    def __init__(self, api_url: str = OLLAMA_API_URL, model: str = OLLAMA_MODEL):
        """
        Initialize AI analyzer.

        Args:
            api_url: Ollama API URL
            model: Model name to use
        """
        self.api_url = api_url.rstrip('/')
        self.model = model
        self.session = requests.Session()
        self._check_connection()

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
                return True
            else:
                logger.warning(f"Ollama API returned status {response.status_code}")
                return False
        except requests.exceptions.RequestException as e:
            logger.warning(f"Cannot connect to Ollama API: {e}")
            return False

    def _call_ollama(self, prompt: str, system_prompt: Optional[str] = None) -> Optional[str]:
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
                logger.debug(f"Calling Ollama API (attempt {attempt + 1}/{OLLAMA_MAX_RETRIES})")

                response = self.session.post(
                    f"{self.api_url}/api/generate",
                    json=payload,
                    timeout=OLLAMA_TIMEOUT,
                )

                if response.status_code == 200:
                    result = response.json()
                    return result.get("response", "")
                else:
                    logger.warning(f"Ollama API returned status {response.status_code}: {response.text}")

            except requests.exceptions.Timeout:
                logger.warning(f"Ollama API timeout (attempt {attempt + 1})")
            except requests.exceptions.RequestException as e:
                logger.error(f"Ollama API request failed: {e}")
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse Ollama response: {e}")

            if attempt < OLLAMA_MAX_RETRIES - 1:
                time.sleep(OLLAMA_RETRY_DELAY)

        logger.error("All Ollama API attempts failed")
        return None

    def _parse_ai_response(self, response: str, category: str) -> List[AIRecommendation]:
        """
        Parse AI response into recommendation objects.

        Args:
            response: AI response text
            category: Category of analysis

        Returns:
            List of AIRecommendation objects
        """
        recommendations = []

        try:
            # Try to extract JSON from response
            # Look for JSON block in response
            json_match = re.search(r'\{[\s\S]*\}', response)
            if json_match:
                json_str = json_match.group(0)
                data = json.loads(json_str)
            else:
                data = json.loads(response)

            findings = data.get("findings", [])

            for finding in findings:
                if isinstance(finding, dict):
                    rec = AIRecommendation(
                        severity=finding.get("severity", SEVERITY_INFO),
                        description=finding.get("description", ""),
                        recommendation=finding.get("recommendation", ""),
                        command=finding.get("command"),
                        category=category,
                    )
                    recommendations.append(rec)

        except json.JSONDecodeError:
            logger.warning("Could not parse AI response as JSON, attempting text parsing")
            # Fallback: parse as structured text
            recommendations = self._parse_text_response(response, category)

        except Exception as e:
            logger.error(f"Error parsing AI response: {e}")

        return recommendations

    def _parse_text_response(self, response: str, category: str) -> List[AIRecommendation]:
        """
        Fallback parser for non-JSON responses.

        Args:
            response: AI response text
            category: Category of analysis

        Returns:
            List of AIRecommendation objects
        """
        recommendations = []

        # Simple heuristic: split by paragraphs and look for key indicators
        paragraphs = [p.strip() for p in response.split('\n\n') if p.strip()]

        for para in paragraphs:
            severity = SEVERITY_INFO

            # Determine severity from keywords
            para_lower = para.lower()
            if any(word in para_lower for word in ['critical', 'severe', 'urgent', 'vulnerable', 'compromised']):
                severity = SEVERITY_CRITICAL
            elif any(word in para_lower for word in ['warning', 'concern', 'issue', 'problem', 'risk']):
                severity = SEVERITY_WARNING

            # Extract command if present
            command = None
            if '`' in para:
                cmd_match = re.search(r'`([^`]+)`', para)
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

    def analyze_security(self, scan_data: Dict) -> List[AIRecommendation]:
        """
        Perform security analysis on scan data.

        Args:
            scan_data: Network scan data dictionary

        Returns:
            List of security recommendations
        """
        logger.info("Performing AI security analysis")

        # Format scan data as JSON
        scan_json = json.dumps(scan_data, indent=2)

        # Create prompt
        prompt = AI_SECURITY_ANALYSIS_PROMPT.format(scan_data=scan_json)

        # Call Ollama
        response = self._call_ollama(prompt, AI_SYSTEM_PROMPT)

        if not response:
            logger.warning("No response from Ollama for security analysis")
            return []

        # Parse response
        recommendations = self._parse_ai_response(response, "security")

        logger.info(f"Generated {len(recommendations)} security recommendations")
        return recommendations

    def analyze_network_health(self, scan_data: Dict) -> List[AIRecommendation]:
        """
        Perform network health analysis.

        Args:
            scan_data: Network scan data dictionary

        Returns:
            List of health recommendations
        """
        logger.info("Performing AI network health analysis")

        scan_json = json.dumps(scan_data, indent=2)
        prompt = AI_NETWORK_HEALTH_PROMPT.format(scan_data=scan_json)

        response = self._call_ollama(prompt, AI_SYSTEM_PROMPT)

        if not response:
            logger.warning("No response from Ollama for health analysis")
            return []

        recommendations = self._parse_ai_response(response, "health")

        logger.info(f"Generated {len(recommendations)} health recommendations")
        return recommendations

    def analyze_wifi_optimization(self, wifi_data: Dict) -> List[AIRecommendation]:
        """
        Perform WiFi optimization analysis.

        Args:
            wifi_data: WiFi metrics and scan data

        Returns:
            List of optimization recommendations
        """
        logger.info("Performing AI WiFi optimization analysis")

        wifi_json = json.dumps(wifi_data, indent=2)
        prompt = AI_WIFI_OPTIMIZATION_PROMPT.format(scan_data=wifi_json)

        response = self._call_ollama(prompt, AI_SYSTEM_PROMPT)

        if not response:
            logger.warning("No response from Ollama for WiFi analysis")
            return []

        recommendations = self._parse_ai_response(response, "wifi")

        logger.info(f"Generated {len(recommendations)} WiFi recommendations")
        return recommendations

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
        logger.info("Performing comprehensive AI analysis")

        results = {
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
        logger.info(f"Comprehensive analysis complete: {total_recommendations} total recommendations")

        return results

    def get_quick_insights(self, scan_data: Dict) -> List[str]:
        """
        Get quick insights without full analysis.

        Args:
            scan_data: Network scan data

        Returns:
            List of quick insight strings
        """
        insights = []

        # Device count
        device_count = scan_data.get("device_count", 0)
        insights.append(f"Detected {device_count} active devices on the network")

        # Check for devices with many open ports
        devices = scan_data.get("devices", [])
        for device in devices:
            open_ports = device.get("open_ports", [])
            if len(open_ports) > 10:
                insights.append(
                    f"Warning: Device {device.get('ip')} has {len(open_ports)} open ports"
                )

        # Check for unknown devices
        unknown_devices = [d for d in devices if not d.get("vendor")]
        if unknown_devices:
            insights.append(
                f"Found {len(unknown_devices)} devices with unknown vendors"
            )

        return insights


# Import re for regex operations
import re


if __name__ == "__main__":
    # Test the AI analyzer
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # Sample scan data
    sample_data = {
        "device_count": 3,
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
                "open_ports": [22, 23, 3389],
            },
        ],
    }

    analyzer = AIAnalyzer()

    print("\nQuick Insights:")
    insights = analyzer.get_quick_insights(sample_data)
    for insight in insights:
        print(f"  - {insight}")

    print("\nPerforming security analysis...")
    recommendations = analyzer.analyze_security(sample_data)

    print(f"\nFound {len(recommendations)} recommendations:")
    for rec in recommendations:
        print(f"\n[{rec.severity.upper()}] {rec.description}")
        print(f"  Recommendation: {rec.recommendation}")
        if rec.command:
            print(f"  Command: {rec.command}")
