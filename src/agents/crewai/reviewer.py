"""
CrewAI Patch Reviewer Agent
Performs security review, secret redaction, static quality verification,
and compiles the structured Pydantic final diagnosis report.
"""
import re
from typing import Dict, Any, List, Optional, Union
from src.blackboard.store import BlackboardStore
from src.blackboard.schema import SecurityAuditReport
from src.reporting.formats import ReportFormatter
from config.settings import settings, is_online
from src.agents.google_adk.gemini_fallback import generate_content_with_fallback


class PatchReviewerAgent:
    SECRET_PATTERNS = [
        (r"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*['\"][a-zA-Z0-9_\-]{8,}['\"]", "[REDACTED_SECRET]"),
        (r"AKIA[0-9A-Z]{16}", "[REDACTED_AWS_KEY]"),
        (r"ghp_[a-zA-Z0-9]{36}", "[REDACTED_GITHUB_TOKEN]"),
        (r"-----BEGIN PRIVATE KEY-----", "[REDACTED_PRIVATE_KEY]"),
    ]

    def __init__(self, agent_id: str = "crewai_patch_reviewer"):
        self.agent_id = agent_id
        self.gemini_client = None

        # Genuine CrewAI Agent initialization
        try:
            from crewai import Agent
            self.crewai_agent = Agent(
                role="Patch Security & Regression Reviewer",
                goal="Inspect code diffs, verify static safety, redact credentials, and prepare structured review reports for human approval.",
                backstory="Principal Application Security Engineer specializing in vulnerability prevention, diff verification, and secret redaction.",
                verbose=False
            )
        except Exception:
            self.crewai_agent = None

        if settings.gemini_api_key and settings.gemini_api_key.strip() and is_online():
            try:
                from google import genai
                from google.genai import types
                if settings.clean_gemini_base_url and "googleapis.com" not in settings.clean_gemini_base_url:
                    opts = types.HttpOptions(base_url=settings.clean_gemini_base_url, api_version="v1beta")
                    self.gemini_client = genai.Client(api_key=settings.gemini_api_key, http_options=opts)
                else:
                    self.gemini_client = genai.Client(api_key=settings.gemini_api_key)
            except Exception:
                self.gemini_client = None

    def review_and_finalize(self, target: Union[BlackboardStore, str, Dict[str, Any]]) -> Dict[str, Any]:
        if isinstance(target, BlackboardStore):
            blackboard = target
            run_id = blackboard.run_id
        elif isinstance(target, dict):
            run_id = target.get("run_id", "default_run")
            blackboard = BlackboardStore(run_id=run_id)
        else:
            run_id = target if isinstance(target, str) else str(target)
            blackboard = BlackboardStore(run_id=run_id)

        state = blackboard.get_state()
        patch = state.candidate_patches[-1] if state.candidate_patches else None

        if not patch:
            return {"status": "error", "message": "No candidate patch found on Blackboard."}

        # 1. Secret Scanning & Redaction
        secrets_detected = []
        redacted_diff = patch.diff
        for pattern, replacement in self.SECRET_PATTERNS:
            matches = re.findall(pattern, redacted_diff)
            if matches:
                secrets_detected.extend([str(m) for m in matches])
                redacted_diff = re.sub(pattern, replacement, redacted_diff)

        # 2. Static Checks on Patched Code
        linter_warnings = []
        if len(patch.patched_code_snippet) > 500:
            linter_warnings.append("Patch hunk exceeds recommended 500-char single-line change limit.")

        # 3. Optional LLM Security Audit
        llm_approved = True
        if self.gemini_client:
            try:
                prompt = f"""Review this code patch diff for security, secrets, and regression risks:
```diff
{redacted_diff}
```
Does this patch look safe to apply without breaking existing functionality?
Answer STRICTLY with 'APPROVED' or 'REJECTED: <reason>'."""
                res = generate_content_with_fallback(
                    client=self.gemini_client,
                    contents=prompt,
                    preferred_model=settings.gemini_model,
                )
                if "REJECTED" in res.text:
                    llm_approved = False
                    linter_warnings.append(f"LLM Security Flag: {res.text.strip()}")
            except Exception:
                pass

        # Static automated safety score calculation
        latest_test = state.test_runs[-1] if state.test_runs else None
        tests_passed = latest_test.all_passed if latest_test else False
        no_regression = (latest_test and not latest_test.regression_detected) if latest_test else False

        safety_score = 1.0
        if secrets_detected:
            safety_score -= 0.5
        if not tests_passed:
            safety_score -= 0.4
        if not no_regression:
            safety_score -= 0.3
        if not llm_approved:
            safety_score -= 0.3

        safety_score = max(0.0, min(1.0, safety_score))

        # Enforce Human-in-the-Loop approval gate: automated score qualifies readiness, but human approval defaults to 'pending'
        audit_report = SecurityAuditReport(
            passed_static_checks=(len(linter_warnings) == 0),
            secrets_detected=secrets_detected,
            linter_warnings=linter_warnings,
            safety_score=round(safety_score, 2),
            approval_granted=False,
            human_approval_status="pending",
            applied_to_repository=False
        )
        blackboard.post_security_audit(agent_name=self.agent_id, audit=audit_report)

        # 4. Generate Tri-Format Final Report
        reports = ReportFormatter.generate_all_formats(blackboard.get_state())
        report_obj = reports.get("report_obj")
        if isinstance(report_obj, FinalDiagnosisReport):
            blackboard.post_final_report(agent_name=self.agent_id, report=report_obj)

        return {
            "status": "success",
            "run_id": run_id,
            "human_approval_status": "pending",
            "safety_score": safety_score,
            "secrets_redacted_count": len(secrets_detected),
            "reports": {
                "json": reports["json"],
                "table": reports["table"],
                "markdown": reports["markdown"]
            }
        }
