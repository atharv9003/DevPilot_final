"""
Input Security Guardrails
Detects and neutralizes prompt injections, system overrides, and abusive/toxic language
while preserving technical context, file paths, and stack traces.
"""
import re
from typing import Tuple, List, Dict
from pydantic import BaseModel, Field


class GuardrailCheckResult(BaseModel):
    is_safe: bool
    sanitized_prompt: str
    injection_detected: bool = False
    toxicity_detected: bool = False
    detected_patterns: List[str] = Field(default_factory=list)
    mitigation_notes: List[str] = Field(default_factory=list)


class InputSecurityGuardrail:
    # Common prompt injection patterns (system prompt leakage, jailbreak attempts, tool abuse)
    INJECTION_PATTERNS = [
        (r"(?i)ignore\s+(all\s+)?(previous|prior|above)\s+instructions?", "INSTRUCTION_OVERRIDE"),
        (r"(?i)disregard\s+(the\s+)?system\s+prompt", "SYSTEM_PROMPT_OVERRIDE"),
        (r"(?i)you\s+are\s+now\s+(a\s+)?DAN|jailbroken|unrestricted", "JAILBREAK_ATTEMPT"),
        (r"(?i)print\s+(the\s+)?system\s+prompt|reveal\s+instructions", "PROMPT_EXTRACTION"),
        (r"(?i)run\s+rm\s+-rf\s+/|format\s+c:|os\.system\(['\"]rm\s+-rf", "DESTRUCTIVE_COMMAND"),
        (r"(?i)curl\s+https?://|wget\s+https?://|nc\s+-e", "NETWORK_EXFILTRATION"),
        (r"(?i)bypass\s+all\s+(security|sandbox|safety)", "SAFETY_BYPASS"),
    ]

    # Toxic / abusive profanity / aggressive emotional words to neutralize
    TOXIC_PATTERNS = [
        (r"(?i)\b(damn|hell|crap|shit|fuck|fucking|bitch|bastard|idiot|stupid|moron|dumbass|useless)\b", "[NEUTRALIZED]"),
        (r"(?i)\b(fix\s+this\s+piece\s+of\s+garbage|your\s+trash\s+code)\b", "resolve the bug in this implementation"),
        (r"(?i)\b(whoever\s+wrote\s+this\s+is\s+an\s+incompetent\s+clown)\b", "the original implementation contains flaws"),
    ]

    def evaluate_prompt(self, raw_prompt: str) -> GuardrailCheckResult:
        if raw_prompt is None:
            raw_prompt = ""

        detected_patterns = []
        mitigation_notes = []
        injection_detected = False
        toxicity_detected = False

        #  Check  prompt injection
        for pattern, label in self.INJECTION_PATTERNS:
            if re.search(pattern, raw_prompt):
                injection_detected = True
                detected_patterns.append(label)
                mitigation_notes.append(f"Blocked injection trigger matching: {label}")

        if injection_detected:
            # Strip out malicious directives while retaining code / error snippets
            cleaned = raw_prompt
            for pattern, label in self.INJECTION_PATTERNS:
                cleaned = re.sub(pattern, f"/* [SECURITY GUARD: BLOCKED {label}] */", cleaned)
        else:
            cleaned = raw_prompt

        # 2. Check and sanitize toxicity
        for pattern, replacement in self.TOXIC_PATTERNS:
            if re.search(pattern, cleaned):
                toxicity_detected = True
                detected_patterns.append("TOXIC_LANGUAGE")
                mitigation_notes.append("Sanitized aggressive/toxic phrases to professional technical phrasing.")
                cleaned = re.sub(pattern, replacement, cleaned)

        is_safe = not injection_detected

        return GuardrailCheckResult(
            is_safe=is_safe,
            sanitized_prompt=cleaned.strip(),
            injection_detected=injection_detected,
            toxicity_detected=toxicity_detected,
            detected_patterns=list(set(detected_patterns)),
            mitigation_notes=mitigation_notes
        )

