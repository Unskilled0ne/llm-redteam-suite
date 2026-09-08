import os
import json
import time
import logging
from typing import Dict, Any, Optional
import requests

logger = logging.getLogger("soar_bridge")

SOAR_WEBHOOK_URL = os.environ.get("SOAR_WEBHOOK_URL", "http://127.0.0.1:8082/api/v1/alerts/webhook")
LOG_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "logs")
os.makedirs(LOG_DIR, exist_ok=True)
AUDIT_LOG_FILE = os.path.join(LOG_DIR, "llm_security_events.jsonl")

class SOARBridge:
    """
    Connects LLM security guardrails to enterprise SIEM/SOAR platforms (e.g. Aegis-SOAR).
    Dispatches real-time incident webhooks when critical adversarial attacks are intercepted.
    """
    @staticmethod
    def emit_incident(
        event_type: str,
        category: str,
        trigger_reason: str,
        user_prompt: str,
        caller_role: str = "customer",
        client_ip: str = "127.0.0.1"
    ) -> Dict[str, Any]:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
        incident_id = f"INC-LLM-{int(time.time() * 1000) % 1000000}"

        payload = {
            "incident_id": incident_id,
            "timestamp": timestamp,
            "event_type": event_type,
            "category": category,
            "severity": "CRITICAL" if any(k in category for k in ["AGENCY", "LEAK", "SSRF"]) else "HIGH",
            "trigger_reason": trigger_reason,
            "prompt_sample": user_prompt[:120] + ("..." if len(user_prompt) > 120 else ""),
            "caller_role": caller_role,
            "source_ip": client_ip,
            "containment_action": "BLOCKED_BY_GUARDRAIL",
            "soar_status": "DISPATCHED"
        }

        # 1. Log locally to SIEM audit log
        try:
            with open(AUDIT_LOG_FILE, "a", encoding="utf-8") as f:
                f.write(json.dumps(payload) + "\n")
        except Exception as e:
            logger.error(f"Failed to append to audit log: {e}")

        # 2. Forward to Aegis-SOAR Webhook endpoint if available
        try:
            soar_alert = {
                "playbook": "bruteforce_containment" if "AGENCY" in category else "phishing_triage",
                "attacker_ip": client_ip,
                "service": f"FinCorp LLM Gateway ({category})",
                "attempt_count": 1,
                "extracted_urls": ["https://attacker-c2.com"] if "SSRF" in category else []
            }
            resp = requests.post(SOAR_WEBHOOK_URL, json=soar_alert, timeout=1.0)
            if resp.status_code in [200, 201]:
                payload["soar_status"] = "PROCESSED_BY_AEGIS_SOAR"
            else:
                payload["soar_status"] = f"BUFFERED_LOCAL (SOAR HTTP {resp.status_code})"
        except Exception:
            payload["soar_status"] = "BUFFERED_LOCAL (SOAR Offline)"

        return payload

    @staticmethod
    def get_recent_incidents(limit: int = 10):
        if not os.path.exists(AUDIT_LOG_FILE):
            return []
        events = []
        try:
            with open(AUDIT_LOG_FILE, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        events.append(json.loads(line))
        except Exception:
            pass
        return events[-limit:][::-1]
