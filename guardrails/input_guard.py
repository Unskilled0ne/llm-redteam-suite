import base64
import math
import re
import unicodedata
from collections import Counter
from typing import Tuple, Optional
from guardrails.ai_guard import AIGuardrail

ai_guard = AIGuardrail()

INJECTION_PATTERNS = [
    r"(?i)ignore\s+(all\s+)?(previous\s+|prior\s+|above\s+|preceding\s+|existing\s+)?(instructions|prompts|rules|directives|commands)",
    r"(?i)system\s+override",
    r"(?i)disregard\s+(all\s+)?(the\s+)?(guardrails|guidelines|policies|constraints|instructions|rules)",
    r"(?i)forget\s+(all\s+)?(previous|prior|above)\s+(instructions|rules|conversations)",
    
    r"(?i)you\s+are\s+now\s+(in\s+)?developer\s+mode",
    r"(?i)dan\s+mode|jailbreak|unrestricted\s+mode|do\s+anything\s+now|developer\s+mode",
    r"(?i)aim\s+persona|evil\s+confidant|bypass\s+all\s+(filters|safety|guardrails)",
    r"(?i)hypothetical\s+(scenario|mode)\s+where\s+(you\s+have\s+no|there\s+are\s+no)\s+(rules|ethics|limits)",
    
    r"(?i)reveal\s+(your\s+)?(system\s+prompt|instructions|initial\s+prompt|hidden\s+rules)",
    r"(?i)repeat\s+(everything|the\s+words|the\s+text|all\s+text)\s+(above|before|from\s+the\s+beginning)",
    r"(?i)(print|output|display|show)\s+(your\s+)?(initial|system|original|base)\s+(prompt|instructions)",
    r"(?i)what\s+(is|are)\s+your\s+(exact\s+)?(system\s+prompt|initial\s+instructions|system\s+rules)",
    
    r"(?i)<\/?system>",
    r"(?i)<\/?user_input>",
    r"(?i)<\/?instruction>",
    r"(?i)```\s*(system|admin|root|secret)",
    
    r"(?i)base64\s+decode|rot13|hex\s+decode"
]

COMPILED_PATTERNS = [re.compile(p) for p in INJECTION_PATTERNS]
BASE64_CHUNK_REGEX = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")

class InputGuardrail:
    HOMOGLYPH_MAP = str.maketrans(
        "аеорсхуіјѕАЕОРСХУІЈЅ",
        "aeopcxyijsAEOPCXYIJS"
    )

    @staticmethod
    def normalize_text(text: str) -> str:
        """
        Strips zero-width characters, maps homoglyphs, normalizes unicode, and collapses excessive whitespace.
        """
        if not text:
            return ""
        cleaned = re.sub(r"[\u200B-\u200D\uFEFF\u00AD\u2060\u200E\u200F]", "", text)
        cleaned = unicodedata.normalize("NFKC", cleaned)
        cleaned = cleaned.translate(InputGuardrail.HOMOGLYPH_MAP)
        return cleaned

    @staticmethod
    def inspect(user_input: str) -> Tuple[bool, Optional[str]]:
        """
        Inspects input for malicious prompt injection patterns, token smuggling, and obfuscation.
        Returns: (is_safe: bool, trigger_reason: Optional[str])
        """
        if not user_input or not user_input.strip():
            return True, None

        normalized = InputGuardrail.normalize_text(user_input)

        for pattern in COMPILED_PATTERNS:
            match = pattern.search(normalized)
            if match:
                return False, f"Adversarial signature detected: '{match.group(0)}'"

        b64_matches = BASE64_CHUNK_REGEX.findall(normalized)
        for chunk in b64_matches:
            try:
                decoded_bytes = base64.b64decode(chunk, validate=True)
                decoded_str = decoded_bytes.decode("utf-8", errors="ignore")
                if decoded_str and len(decoded_str) >= 6:
                    for pattern in COMPILED_PATTERNS:
                        sub_match = pattern.search(decoded_str)
                        if sub_match:
                            return False, f"Adversarial signature detected in decoded base64 payload: '{sub_match.group(0)}'"
            except Exception:
                continue

        has_suffix_anomaly, suffix_reason = InputGuardrail.detect_adversarial_suffix(normalized)
        if has_suffix_anomaly:
            return False, suffix_reason

        is_safe_ai, ai_reason = ai_guard.inspect(normalized)
        if not is_safe_ai:
            return False, ai_reason

        return True, None

    @staticmethod
    def calculate_entropy(text: str) -> float:
        """Calculates Shannon entropy of character frequencies."""
        if not text or len(text) < 15:
            return 0.0
        counts = Counter(text)
        total = len(text)
        return -sum((cnt / total) * math.log2(cnt / total) for cnt in counts.values())

    @staticmethod
    def detect_adversarial_suffix(text: str) -> Tuple[bool, Optional[str]]:
        """
        Detects gradient-based adversarial suffixes (e.g. GCG attacks) and symbol spam
        characterized by abnormal non-alphanumeric symbol density or repetitive punctuation noise.
        """
        if not text or len(text) < 20:
            return False, None
        
        symbol_run = re.search(r"([!@#$%^&*()_+=\[\]{};:\"\\|,.<>/?`~-]\s*){7,}", text)
        if symbol_run:
            snippet = symbol_run.group(0).strip()
            if len(snippet) > 20:
                snippet = snippet[:20] + "..."
            return True, f"Adversarial GCG suffix noise detected: '{snippet}'"
            
        return False, None

    @staticmethod
    def sanitize_and_wrap(user_input: str) -> str:
        """
        Neutralizes boundary breakout attempts and encloses input in structural boundary tags.
        """
        cleaned = InputGuardrail.normalize_text(user_input)
        cleaned = cleaned.replace("<user_input>", "&lt;user_input&gt;").replace("</user_input>", "&lt;/user_input&gt;")
        cleaned = cleaned.replace("<system>", "&lt;system&gt;").replace("</system>", "&lt;/system&gt;")
        return f"<user_input>\n{cleaned.strip()}\n</user_input>"
