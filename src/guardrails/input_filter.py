"""
Multi-Layer Security Guardrails & Tool Boundary Defenses
Implements:
1. Input Prompt Injection & System Override Defenses
2. Toxic / Abusive Language Sanitization (preserving debugging intent)
3. Tool Execution Boundary Validation (path traversal, command injection, exfiltration)
4. Obfuscation & Encoding Anomaly Detection
"""
import re
import os
import base64
from typing import Tuple, List, Dict, Any, Optional
from pydantic import BaseModel, Field


class GuardrailCheckResult(BaseModel):
    is_safe: bool
    sanitized_prompt: str
    injection_detected: bool = False
    toxicity_detected: bool = False
    detected_patterns: List[str] = Field(default_factory=list)
    mitigation_notes: List[str] = Field(default_factory=list)


class ToolValidationResult(BaseModel):
    is_allowed: bool
    tool_name: str
    sanitized_arguments: Dict[str, Any]
    violations: List[str] = Field(default_factory=list)


class InputSecurityGuardrail:
    # Expanded prompt injection patterns (system overrides, jailbreaks, data exfiltration, command abuse)
    INJECTION_PATTERNS = [
        (r"(?i)ignore\s+(all\s+)?(previous|prior|above|former)\s+(instructions?|rules?|directives?)", "INSTRUCTION_OVERRIDE"),
        (r"(?i)disregard\s+(the\s+)?(system\s+prompt|guidelines?|safety\s+checks?)", "SYSTEM_PROMPT_OVERRIDE"),
        (r"(?i)you\s+are\s+now\s+(a\s+)?(DAN|jailbroken|unrestricted|godmode|root)", "JAILBREAK_ATTEMPT"),
        (r"(?i)(print|reveal|show|display|leak)\s+(the\s+)?(system\s+prompt|initial\s+prompt|hidden\s+instructions?)", "PROMPT_EXTRACTION"),
        (r"(?i)(echo|print|cat|type)\s+.*(\.env|environ|api_key|token|password|secret)", "SECRET_EXTRACTION"),
        (r"(?i)run\s+rm\s+-rf\s+/|format\s+c:|os\.system\(['\"]rm\s+-rf|shutil\.rmtree\(['\"]/['\"]", "DESTRUCTIVE_COMMAND"),
        (r"(?i)curl\s+https?://|wget\s+https?://|nc\s+-e|invoke-webrequest", "NETWORK_EXFILTRATION"),
        (r"(?i)bypass\s+all\s+(security|sandbox|safety|filters?|guardrails?)", "SAFETY_BYPASS"),
        (r"(?i)forget\s+(everything|all\s+instructions?)\s+and\s+(start\s+fresh|say)", "CONTEXT_RESET_INJECTION"),
        (r"(?i)base64\s*-d|base64\.b64decode\(|eval\(compile\(", "ENCODED_PAYLOAD_EXECUTION"),
    ]

    # Toxic / abusive profanity to neutralize while preserving technical context
    TOXIC_PATTERNS = [
        (r"(?i)\b(damn|hell|crap|shit|fuck|fucking|bitch|bastard|idiot|stupid|moron|dumbass|useless)\b", "[NEUTRALIZED]"),
        (r"(?i)\b(fix\s+this\s+piece\s+of\s+garbage|your\s+trash\s+code)\b", "resolve the bug in this implementation"),
        (r"(?i)\b(whoever\s+wrote\s+this\s+is\s+an\s+incompetent\s+clown)\b", "the original implementation contains flaws"),
    ]

    # Tool Boundary Traversal & Dangerous Arguments Patterns
    DANGEROUS_PATH_PATTERNS = [
        r"\.\.[\\/]\.\.[\\/]",
        r"[\\/](etc|proc|sys|root|windows|system32)[\\/]",
        r"^[a-zA-Z]:[\\/](windows|system32)",
    ]

    def evaluate_prompt(self, raw_prompt: str) -> GuardrailCheckResult:
        if raw_prompt is None:
            raw_prompt = ""

        detected_patterns = []
        mitigation_notes = []
        injection_detected = False
        toxicity_detected = False

        # 1. Obfuscation pre-check (detect suspicious base64 payloads)
        b64_matches = re.findall(r"(?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?", raw_prompt)
        for cand in b64_matches:
            try:
                decoded = base64.b64decode(cand).decode("utf-8", errors="ignore").lower()
                for pattern, label in self.INJECTION_PATTERNS:
                    if re.search(pattern, decoded):
                        injection_detected = True
                        detected_patterns.append(f"OBFUSCATED_{label}")
                        mitigation_notes.append(f"Detected Base64 obfuscated payload matching: {label}")
            except Exception:
                pass

        # 2. Check plaintext injection patterns
        for pattern, label in self.INJECTION_PATTERNS:
            if re.search(pattern, raw_prompt):
                injection_detected = True
                detected_patterns.append(label)
                mitigation_notes.append(f"Blocked injection directive matching: {label}")

        cleaned = raw_prompt
        if injection_detected:
            for pattern, label in self.INJECTION_PATTERNS:
                cleaned = re.sub(pattern, f"/* [SECURITY GUARD: BLOCKED {label}] */", cleaned)

        # 3. Check and neutralize toxic wording while preserving technical bug semantics
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

    def validate_tool_arguments(self, tool_name: str, arguments: Dict[str, Any]) -> ToolValidationResult:
        """Validates tool arguments at the execution boundary to prevent path traversal or secret leaks."""
        violations = []
        sanitized = dict(arguments)

        # Path argument validation
        for key in ["repo_path", "repo_dir", "test_file_path", "file_path"]:
            val = arguments.get(key)
            if isinstance(val, str) and val:
                for bad_pat in self.DANGEROUS_PATH_PATTERNS:
                    if re.search(bad_pat, val, re.IGNORECASE):
                        violations.append(f"Suspicious path traversal attempt in argument '{key}': {val}")
                        sanitized[key] = os.path.basename(val)

        # Search query secret protection
        if tool_name == "tavily_web_search":
            q = arguments.get("query", "")
            if isinstance(q, str):
                for sec_pat in [r"AKIA[0-9A-Z]{16}", r"ghp_[a-zA-Z0-9]{36}", r"(?i)api[_-]?key"]:
                    if re.search(sec_pat, q):
                        violations.append("Attempted web search containing API key or secret token pattern.")
                        sanitized["query"] = re.sub(sec_pat, "[REDACTED]", q)

        return ToolValidationResult(
            is_allowed=(len(violations) == 0),
            tool_name=tool_name,
            sanitized_arguments=sanitized,
            violations=violations
        )
