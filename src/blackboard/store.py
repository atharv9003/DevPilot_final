"""
Centralized Blackboard Store Implementation
Supports both Thread-Safe In-Memory state management and Redis backend.
"""
from typing import Optional, Dict, Any
import threading
import json
from src.blackboard.schema import (
    BlackboardState,
    BlackboardEvent,
    ASTAnalysisResult,
    Hypothesis,
    CandidatePatch,
    SandboxTestExecution,
    SecurityAuditReport,
    FinalDiagnosisReport
)


class BlackboardStore:
    def __init__(self, run_id: str, backend: str = "memory", redis_client: Optional[Any] = None):
        self.run_id = run_id
        self.backend = backend
        self.redis_client = redis_client
        self._lock = threading.RLock()
        self._state = BlackboardState(run_id=run_id)

    def get_state(self) -> BlackboardState:
        with self._lock:
            if self.backend == "redis" and self.redis_client:
                try:
                    raw = self.redis_client.get(f"blackboard:{self.run_id}")
                    if raw:
                        return BlackboardState.model_validate_json(raw)
                except Exception:
                    pass
            return self._state.model_copy(deep=True)

    def _sync(self, agent_name: str, key: str, action: str = "write", details: Optional[Dict[str, Any]] = None):
        event = BlackboardEvent(
            agent_name=agent_name,
            action=action,
            key=key,
            details=details or {}
        )
        self._state.events.append(event)
        if self.backend == "redis" and self.redis_client:
            try:
                self.redis_client.set(f"blackboard:{self.run_id}", self._state.model_dump_json())
            except Exception:
                pass

    def update_input(self, agent_name: str, prompt: str, sanitized_prompt: str, persona: str, repo_path: str, error_trace: str):
        with self._lock:
            self._state.user_prompt = prompt
            self._state.sanitized_prompt = sanitized_prompt
            self._state.persona_name = persona
            self._state.repo_path = repo_path
            self._state.target_error_trace = error_trace
            self._sync(agent_name, "input_context", details={"persona": persona, "repo_path": repo_path})

    def post_ast_analysis(self, agent_name: str, ast_result: ASTAnalysisResult):
        with self._lock:
            self._state.ast_analysis = ast_result
            self._state.status = "analyzed"
            self._sync(agent_name, "ast_analysis", details={"files": len(ast_result.files_analyzed), "symbols": len(ast_result.symbols)})

    def post_hypotheses(self, agent_name: str, hypotheses: list[Hypothesis]):
        with self._lock:
            self._state.hypotheses = hypotheses
            if hypotheses:
                # Select highest confidence hypothesis by default
                best = max(hypotheses, key=lambda h: h.confidence_score)
                self._state.selected_hypothesis_id = best.id
            self._state.status = "hypothesized"
            self._sync(agent_name, "hypotheses", details={"count": len(hypotheses)})

    def post_candidate_patch(self, agent_name: str, patch: CandidatePatch):
        with self._lock:
            self._state.candidate_patches.append(patch)
            self._state.selected_patch_id = patch.id
            self._state.status = "patched"
            self._sync(agent_name, "candidate_patches", details={"patch_id": patch.id, "file": patch.file_path, "hash": patch.patch_hash})

    def post_test_result(self, agent_name: str, test_run: SandboxTestExecution):
        with self._lock:
            self._state.test_runs.append(test_run)
            self._state.status = "tested" if test_run.all_passed else "re-evaluating"
            self._sync(agent_name, "test_runs", details={
                "exit_code": test_run.exit_code,
                "all_passed": test_run.all_passed,
                "regression": test_run.regression_detected
            })

    def post_security_audit(self, agent_name: str, audit: SecurityAuditReport):
        with self._lock:
            self._state.security_audit = audit
            self._sync(agent_name, "security_audit", details={"approved": audit.approval_granted, "score": audit.safety_score})

    def post_final_report(self, agent_name: str, report: FinalDiagnosisReport):
        with self._lock:
            self._state.final_report = report
            self._state.status = "completed"
            self._sync(agent_name, "final_report", details={"code": report.diagnosis_code, "hash": report.audit_hash})

    def set_status(self, agent_name: str, status: str):
        with self._lock:
            self._state.status = status
            self._sync(agent_name, "status", details={"new_status": status})

