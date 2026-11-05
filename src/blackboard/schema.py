"""
Blackboard Schema Definitions
Defines all structured Pydantic models for shared-state management across DevPilot agents.
"""
from pydantic import BaseModel, Field, field_validator
from typing import List, Dict, Optional, Any
from datetime import datetime, timezone
import hashlib


class ASTSymbol(BaseModel):
    name: str
    symbol_type: str  # 'function', 'class', 'import', 'method'
    file_path: str
    line_start: int
    line_end: int
    docstring: Optional[str] = None
    parameters: List[str] = Field(default_factory=list)
    calls: List[str] = Field(default_factory=list)


class ASTAnalysisResult(BaseModel):
    repo_path: str
    files_analyzed: List[str] = Field(default_factory=list)
    symbols: List[ASTSymbol] = Field(default_factory=list)
    call_graph: Dict[str, List[str]] = Field(default_factory=dict)
    syntax_errors: List[Dict[str, Any]] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class Hypothesis(BaseModel):
    id: str
    category: str  # 'syntax', 'logic', 'runtime', 'config'
    root_cause_explanation: str
    suspected_files: List[str] = Field(default_factory=list)
    suspected_lines: List[int] = Field(default_factory=list)
    confidence_score: float = Field(default=0.9, ge=0.0, le=1.0)
    proposed_remediation: str
    supporting_evidence: List[str] = Field(default_factory=list)

    @field_validator("confidence_score", mode="before")
    @classmethod
    def clamp_confidence(cls, v: Any) -> float:
        try:
            return max(0.0, min(1.0, float(v)))
        except (ValueError, TypeError):
            return 0.5


class CandidatePatch(BaseModel):
    id: str
    hypothesis_id: str
    file_path: str
    original_code_snippet: str
    patched_code_snippet: str
    diff: str
    patch_hash: str = ""

    def model_post_init(self, __context: Any) -> None:
        if not self.patch_hash:
            self.patch_hash = hashlib.sha256(self.diff.encode('utf-8')).hexdigest()


class TestCaseResult(BaseModel):
    test_name: str
    status: str  # 'passed', 'failed', 'error', 'skipped'
    duration_seconds: float
    error_message: Optional[str] = None


class SandboxTestExecution(BaseModel):
    execution_id: str
    candidate_patch_id: Optional[str] = None
    exit_code: int
    all_passed: bool
    total_tests: int
    passed_tests: int
    failed_tests: int
    regression_detected: bool = False
    stdout: str = ""
    stderr: str = ""
    test_cases: List[TestCaseResult] = Field(default_factory=list)
    execution_duration_sec: float = 0.0


class SecurityAuditReport(BaseModel):
    passed_static_checks: bool
    secrets_detected: List[str] = Field(default_factory=list)
    linter_warnings: List[str] = Field(default_factory=list)
    safety_score: float = Field(ge=0.0, le=1.0, default=1.0)
    approval_granted: bool = False

    @field_validator("safety_score", mode="before")
    @classmethod
    def clamp_safety(cls, v: Any) -> float:
        try:
            return max(0.0, min(1.0, float(v)))
        except (ValueError, TypeError):
            return 1.0


class BlackboardEvent(BaseModel):
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    agent_name: str
    action: str  # 'read', 'write', 'update'
    key: str
    details: Dict[str, Any] = Field(default_factory=dict)


class FinalDiagnosisReport(BaseModel):
    diagnosis_code: str
    category: str
    confidence_score: float
    root_cause: str
    files_modified: List[str]
    tests_summary: Dict[str, Any]
    patch_diff: str
    human_explanation: str
    audit_hash: str


class CodeIssue(BaseModel):
    id: str
    title: str
    category: str  # 'syntax', 'runtime', 'logic', 'security', 'quality', 'config'
    severity: str  # 'critical', 'high', 'medium', 'low'
    file_path: str
    line_number: int
    language: str = "Python"
    function_name: Optional[str] = None
    original_code: str
    what_is_wrong: str
    root_cause: str
    potential_impact: str
    corrected_code: str
    explanation_of_correction: str
    verified: bool = False
    status: str = "confirmed"  # 'confirmed', 'uncertain', 'rejected_false_positive'
    confidence: float = Field(default=0.9, ge=0.0, le=1.0)
    agent_source: str = "static_analysis"
    test_results: Dict[str, Any] = Field(default_factory=dict)
    remaining_risks: str = "No remaining critical risks; behavior verified with automated regression and boundary tests."


class FullInspectionReport(BaseModel):
    run_id: str
    repo_path: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    total_files: int = 0
    total_loc: int = 0
    languages_detected: List[str] = Field(default_factory=list)
    language_breakdown: Dict[str, Any] = Field(default_factory=dict)
    manifests_detected: List[str] = Field(default_factory=list)
    toolchains_active: Dict[str, Any] = Field(default_factory=dict)
    total_issues: int = 0
    critical_issues: int = 0
    high_issues: int = 0
    medium_issues: int = 0
    low_issues: int = 0
    security_issues: int = 0
    runtime_issues: int = 0
    logical_issues: int = 0
    quality_issues: int = 0
    syntax_issues: int = 0
    config_issues: int = 0
    verified_patches: int = 0
    rejected_patches: int = 0
    unverified_patches: int = 0
    false_positives_rejected: int = 0
    duration_sec: float = 0.0
    timings: Dict[str, float] = Field(default_factory=dict)
    issues: List[CodeIssue] = Field(default_factory=list)
    unified_patch: str = ""
    tests_summary: Dict[str, Any] = Field(default_factory=dict)
    security_comparison: List[Dict[str, Any]] = Field(default_factory=list)
    coverage_report: Dict[str, Any] = Field(default_factory=dict)
    state_sha256: str = ""


class BlackboardState(BaseModel):
    run_id: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    status: str = "initialized"  # 'initialized', 'analyzing', 'debugging', 'testing', 'reviewing', 'completed', 'failed'
    
    # Input Context
    user_prompt: str = ""
    sanitized_prompt: str = ""
    persona_name: str = "constructive"
    repo_path: str = ""
    target_error_trace: str = ""
    
    # Shared Artifacts
    ast_analysis: Optional[ASTAnalysisResult] = None
    hypotheses: List[Hypothesis] = Field(default_factory=list)
    selected_hypothesis_id: Optional[str] = None
    candidate_patches: List[CandidatePatch] = Field(default_factory=list)
    selected_patch_id: Optional[str] = None
    test_runs: List[SandboxTestExecution] = Field(default_factory=list)
    security_audit: Optional[SecurityAuditReport] = None
    inspection_report: Optional[FullInspectionReport] = None
    
    # Audit trail & Events
    events: List[BlackboardEvent] = Field(default_factory=list)
    final_report: Optional[FinalDiagnosisReport] = None

    def get_state_hash(self) -> str:
        """Returns SHA-256 hash representing current snapshot of blackboard state."""
        state_dump = self.model_dump_json(exclude={'events', 'created_at'})
        return hashlib.sha256(state_dump.encode('utf-8')).hexdigest()

