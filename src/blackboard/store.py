"""
Centralized Blackboard Store Implementation
Supports both Thread-Safe In-Memory state management and Redis backend.
"""
from typing import Optional, Dict, Any
import threading
import json
import os
from config.settings import settings
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


_MEMORY_REGISTRY: Dict[str, BlackboardState] = {}
_REGISTRY_LOCK = threading.RLock()


class BlackboardStore:
    def __init__(self, run_id: str, backend: Optional[str] = None, redis_client: Optional[Any] = None):
        self.run_id = run_id
        self.backend = backend if backend is not None else settings.blackboard_backend
        self.redis_client = redis_client
        self._lock = threading.RLock()

        if self.backend == "redis":
            self._state = BlackboardState(run_id=run_id)
            if self.redis_client is None:
                try:
                    import redis
                    self.redis_client = redis.Redis(
                        host=settings.redis_host,
                        port=settings.redis_port,
                        db=settings.redis_db,
                        decode_responses=True
                    )
                    self.redis_client.ping()
                except Exception as e:
                    raise ConnectionError(
                        f"Failed to connect to required Redis Blackboard backend at {settings.redis_host}:{settings.redis_port}: {e}"
                    )
            
            # Load existing state from Redis if available
            existing = self.redis_client.get(f"blackboard:{self.run_id}")
            if existing:
                try:
                    self._state = BlackboardState.model_validate_json(existing)
                except Exception:
                    pass
            else:
                self.redis_client.set(f"blackboard:{self.run_id}", self._state.model_dump_json())
        else:
            with _REGISTRY_LOCK:
                if self.run_id in _MEMORY_REGISTRY:
                    self._state = _MEMORY_REGISTRY[self.run_id]
                else:
                    self._state = BlackboardState(run_id=run_id)
                    _MEMORY_REGISTRY[self.run_id] = self._state

    def get_state(self) -> BlackboardState:
        with self._lock:
            if self.backend == "redis" and self.redis_client:
                raw = self.redis_client.get(f"blackboard:{self.run_id}")
                if raw:
                    self._state = BlackboardState.model_validate_json(raw)
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
            self.redis_client.set(f"blackboard:{self.run_id}", self._state.model_dump_json())
        else:
            with _REGISTRY_LOCK:
                _MEMORY_REGISTRY[self.run_id] = self._state

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

    def record_human_approval(self, agent_name: str, approved: bool, notes: Optional[str] = None):
        """Records human reviewer approval or rejection decision."""
        with self._lock:
            status_str = "approved" if approved else "rejected"
            self._state.human_approval_state = status_str
            if self._state.security_audit:
                self._state.security_audit.human_approval_status = status_str
                self._state.security_audit.human_reviewer_notes = notes
                self._state.security_audit.approval_granted = approved
            self._state.status = "patch_approved" if approved else "patch_rejected"
            self._sync(agent_name, "human_approval", details={"status": status_str, "notes": notes})

    def apply_approved_patch(self, agent_name: str) -> bool:
        """Applies the candidate patch to the target repository ONLY if affirmative human approval has been recorded."""
        with self._lock:
            if self._state.human_approval_state != "approved":
                raise PermissionError(
                    f"Patch application blocked: Human approval status is '{self._state.human_approval_state}'. "
                    "Only affirmative human approval allows applying patches to the repository."
                )
            if not self._state.candidate_patches:
                raise ValueError("No candidate patch available on Blackboard to apply.")

            patch = self._state.candidate_patches[-1]
            repo_path = self._state.repo_path
            patch_root = os.path.dirname(os.path.abspath(repo_path)) if os.path.isfile(repo_path) else repo_path
            abs_target = os.path.join(patch_root, patch.file_path)

            if not os.path.exists(abs_target):
                raise FileNotFoundError(f"Target file {abs_target} does not exist.")

            from src.mcp_tools.docker_sandbox import DockerSandboxTool
            DockerSandboxTool._apply_patch(patch_root, patch.diff)

            if self._state.security_audit:
                self._state.security_audit.applied_to_repository = True
            self._state.status = "patch_applied"
            self._sync(agent_name, "apply_approved_patch", details={"file": patch.file_path, "patch_id": patch.id})
            return True

