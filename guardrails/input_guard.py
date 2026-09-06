import re
from typing import Tuple, Optional

INJECTION_PATTERNS = [
    r"(?i)ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts|rules)",
    r"(?i)system\s+override",
    r"(?i)you\s+are\s+now\s+(in\s+)?developer\s+mode",
    r"(?i)dan\s+mode|jailbreak|unrestricted\s+mode",
    r"(?i)disregard\s+(the\s+)?(guardrails|guidelines|policies)",
    r"(?i)reveal\s+(your\s+)?(system\s+prompt|instructions|initial\s+prompt)",
    r"(?i)repeat\s+(everything|the\s+words)\s+above",
    r"(?i)<\/?system>",
    r"(?i)<\/?user_input>",
    r"(?i)base64\s+decode|rot13|hex\s+decode"
]

COMPILED_PATTERNS = [re.compile(p) for p in INJECTION_PATTERNS]

class InputGuardrail:
    @staticmethod
    def inspect(user_input: str) -> Tuple[bool, Optional[str]]:
        """
        Inspects input for malicious prompt injection patterns.
        Returns: (is_safe: bool, trigger_reason: Optional[str])
        """
        if not user_input or not user_input.strip():
            return True, None

        for pattern in COMPILED_PATTERNS:
            match = pattern.search(user_input)
            if match:
                return False, f"Adversarial signature detected: '{match.group(0)}'"

        return True, None

    @staticmethod
    def sanitize_and_wrap(user_input: str) -> str:
        """
        Encloses input in boundary tags to prevent prompt escaping.
        """
        cleaned = user_input.replace("<user_input>", "").replace("</user_input>", "")
        return f"<user_input>\n{cleaned.strip()}\n</user_input>"
