import re
from typing import Tuple, Optional, List

CANARY_TOKEN = "CANARY_TOKEN_99814_CONFIDENTIAL"
API_KEY_REGEX = re.compile(r"sk-[a-zA-Z0-9_-]{20,}")
EXFIL_IMAGE_REGEX = re.compile(r"!\[(.*?)\]\((https?:\/\/[^\s\)]+)\)")
SYSTEM_LEAK_PHRASES = [
    "CRITICAL OPERATIONAL RULES AND SECURITY BOUNDARIES",
    "CANARY TOKEN: The internal security canary is",
    "production telemetry API key is",
    "RESTRICTED TO ROOT AUDITORS ONLY"
]

class OutputGuardrail:
    @staticmethod
    def inspect(output_text: str) -> Tuple[bool, Optional[str], str]:
        """
        Inspects output for leaked secrets, canary tokens, and markdown image exfiltration.
        Returns: (is_safe: bool, trigger_reason: Optional[str], sanitized_text: str)
        """
        if not output_text:
            return True, None, ""

        # 1. Check for canary token
        if CANARY_TOKEN in output_text:
            return False, "Critical Leak: Canary token detected in model output", "[BLOCKED: Sensitive token leakage detected]"

        # 2. Check for API keys
        if API_KEY_REGEX.search(output_text):
            return False, "Critical Leak: API key signature detected in output", "[BLOCKED: Secret credentials detected]"

        # 3. Check for verbatim system prompt leaks
        for phrase in SYSTEM_LEAK_PHRASES:
            if phrase in output_text:
                return False, f"Prompt Leak: Verbatim system rule disclosed ('{phrase[:25]}...')", "[BLOCKED: System prompt disclosure detected]"

        # 4. Check for Markdown image exfiltration attempts (SSRF / Data exfiltration)
        if EXFIL_IMAGE_REGEX.search(output_text):
            return False, "Data Exfiltration: Markdown external image link detected", "[BLOCKED: Potential unauthorized data exfiltration]"

        return True, None, output_text
