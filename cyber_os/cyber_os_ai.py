"""
CyberOS AI Reasoning Layer
Provides AI-powered threat analysis and explanation.
"""

import json
from typing import Dict, Any, List, Optional
from datetime import datetime

try:
    from key_manager import AiApi, MockRoleKeyManager
    KEY_MANAGER_AVAILABLE = True
except ImportError:
    KEY_MANAGER_AVAILABLE = False


class CyberOSAI:
    """AI reasoning layer for CyberOS threat analysis."""

    def __init__(self, use_mock: bool = True):
        self.use_mock = use_mock
        self.api = None
        if KEY_MANAGER_AVAILABLE:
            try:
                self.api = AiApi(use_mock=use_mock)
            except Exception:
                self.api = None

    def analyze_threat(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze a threat alert and generate AI reasoning."""
        if self.api and not self.use_mock:
            return self._analyze_with_api(alert)
        else:
            return self._analyze_with_template(alert)

    def _analyze_with_api(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Use KeyManager API for analysis."""
        try:
            prompt = f"""
            Analyze this security alert and provide structured reasoning:
            
            Alert Type: {alert.get('alert_type', 'unknown')}
            Severity: {alert.get('severity', 'unknown')}
            Summary: {alert.get('summary', 'N/A')}
            Evidence: {json.dumps(alert.get('evidence', []), indent=2)}
            
            Provide:
            1. Plain-language explanation of what happened
            2. Blast radius assessment
            3. Recommended containment actions
            4. Priority level (1-10)
            """
            
            response = self.api.chat_with_role(
                "incident_responder",
                "You are a SOC incident analyst. Analyze security alerts and provide actionable intelligence.",
                prompt
            )
            
            return {
                "source": "ai_api",
                "analysis": response.choices[0].message.content,
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            return self._analyze_with_template(alert)

    def _analyze_with_template(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Use template-based analysis as fallback."""
        alert_type = alert.get("alert_type", "unknown")
        severity = alert.get("severity", "MEDIUM")
        summary = alert.get("summary", "")
        
        templates = {
            "brute_force": {
                "explanation": "Multiple failed authentication attempts detected. This indicates an automated password spraying or brute force attack attempting to gain unauthorized access.",
                "blast_radius": "If successful, attacker gains access to the compromised account and can pivot to other systems.",
                "actions": ["Block source IP", "Lock target account", "Enable additional authentication factors", "Alert SOC team"],
                "priority": 8
            },
            "powershell_obfuscation": {
                "explanation": "PowerShell executed with obfuscation techniques. This is a common malware delivery method used to evade detection and execute malicious code.",
                "blast_radius": "Potential for code execution, file download, credential theft, lateral movement, or persistence installation.",
                "actions": ["Terminate malicious process", "Block suspicious URLs", "Quarantine dropped files", "Scan for persistence"],
                "priority": 9
            },
            "port_scan": {
                "explanation": "Systematic port scanning detected. Attacker is mapping available services to identify attack vectors.",
                "blast_radius": "Attacker now knows which services are running and can target specific vulnerabilities.",
                "actions": ["Block source IP", "Enable intrusion prevention", "Review exposed services", "Enable rate limiting"],
                "priority": 7
            },
            "ransomware_behavior": {
                "explanation": "Ransomware-like encryption activity detected. Multiple files modified with suspicious patterns in a short time window.",
                "blast_radius": "Immediate risk of data loss, operational disruption, and potential lateral spread to network shares.",
                "actions": ["Isolate affected system", "Restore from backup", "Block malicious process", "Preserve evidence for forensics"],
                "priority": 10
            },
            "suspicious_process_chain": {
                "explanation": "Unusual parent-child process relationship detected. Office application spawning command interpreter is a common malware pattern.",
                "blast_radius": "Potential code execution from compromised document, leading to data exfiltration or lateral movement.",
                "actions": ["Terminate suspicious child process", "Scan parent document for malware", "Check for macros", "Review recent documents"],
                "priority": 8
            }
        }
        
        template = templates.get(alert_type, {
            "explanation": f"Security alert detected: {summary}",
            "blast_radius": "Potential security impact requires investigation.",
            "actions": ["Investigate further", "Review logs", "Apply defense in depth"],
            "priority": 5
        })
        
        return {
            "source": "template",
            "analysis": {
                "explanation": template["explanation"],
                "blast_radius": template["blast_radius"],
                "recommended_actions": template["actions"],
                "priority": template["priority"],
                "confidence": 0.85,
                "mitre_technique": alert.get("mitre_technique", "unknown"),
                "technique_name": alert.get("technique_name", "unknown")
            },
            "timestamp": datetime.now().isoformat()
        }

    def generate_incident_report(self, alert: Dict[str, Any], analysis: Dict[str, Any]) -> str:
        """Generate a formatted incident report."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        report = f"""
════════════════════════════════════════════════════════════════
  CYBEROS INCIDENT REPORT
════════════════════════════════════════════════════════════════
  Generated: {timestamp}
  Alert ID: {alert.get('event_id', 'N/A')}
  Severity: {alert.get('severity', 'UNKNOWN')}
  MITRE Technique: {alert.get('mitre_technique', 'N/A')} - {alert.get('technique_name', 'N/A')}
════════════════════════════════════════════════════════════════

📋 SUMMARY
{'-' * 60}
{alert.get('summary', 'No summary available')}

🧠 AI ANALYSIS
{'-' * 60}
{analysis.get('analysis', {}).get('explanation', 'No analysis available')}

💥 BLAST RADIUS
{'-' * 60}
{analysis.get('analysis', {}).get('blast_radius', 'Unknown')}

✅ RECOMMENDED ACTIONS
{'-' * 60}
"""
        for action in analysis.get('analysis', {}).get('recommended_actions', []):
            report += f"  • {action}\n"
        
        report += f"""
📊 EVIDENCE
{'-' * 60}
"""
        for evidence in alert.get('evidence', []):
            report += f"  • {evidence}\n"
        
        if alert.get('autonomous_action_taken'):
            report += f"""
🤖 AUTONOMOUS ACTIONS TAKEN
{'-' * 60}
"""
            for action in alert.get('actions_taken', []):
                report += f"  ✓ {action}\n"
        
        report += f"""
════════════════════════════════════════════════════════════════
  END OF REPORT
════════════════════════════════════════════════════════════════
"""
        return report
