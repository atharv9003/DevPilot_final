"""
Tests for Blackboard State and Input Guardrails.
"""
import pytest
from src.blackboard.store import BlackboardStore
from src.blackboard.schema import (
    ASTAnalysisResult,
    ASTSymbol,
    Hypothesis,
    CandidatePatch,
    SandboxTestExecution,
    SecurityAuditReport
)
from src.guardrails.input_filter import InputSecurityGuardrail
from src.guardrails.personas import get_persona_prompt


def test_blackboard_lifecycle():
    store = BlackboardStore(run_id="test_run_001")
    
    # 1. Update Input
    store.update_input(
        agent_name="Coordinator",
        prompt="Fix IndexError in binary_search",
        sanitized_prompt="Fix IndexError in binary_search",
        persona="constructive",
        repo_path="/test/repo",
        error_trace="Traceback: IndexError: list index out of range"
    )
    state = store.get_state()
    assert state.repo_path == "/test/repo"
    assert len(state.events) == 1
    
    # 2. Post AST Analysis
    ast_res = ASTAnalysisResult(
        repo_path="/test/repo",
        files_analyzed=["main.py"],
        symbols=[
            ASTSymbol(name="binary_search", symbol_type="function", file_path="main.py", line_start=1, line_end=15)
        ]
    )
    store.post_ast_analysis("CodebaseAnalyst", ast_res)
    assert store.get_state().status == "analyzed"
    assert len(store.get_state().ast_analysis.symbols) == 1

    # 3. Post Hypothesis
    hypo = Hypothesis(
        id="hypo_1",
        category="logic",
        root_cause_explanation="Off-by-one condition in loop bounds",
        suspected_files=["main.py"],
        suspected_lines=[10],
        confidence_score=0.92,
        proposed_remediation="Change `high = len(arr)` to `high = len(arr) - 1`"
    )
    store.post_hypotheses("DebuggingAgent", [hypo])
    assert store.get_state().selected_hypothesis_id == "hypo_1"

    # 4. Post Candidate Patch
    patch = CandidatePatch(
        id="patch_1",
        hypothesis_id="hypo_1",
        file_path="main.py",
        original_code_snippet="high = len(arr)",
        patched_code_snippet="high = len(arr) - 1",
        diff="--- a/main.py\n+++ b/main.py\n@@ -10 +10 @@\n-high = len(arr)\n+high = len(arr) - 1"
    )
    store.post_candidate_patch("DebuggingAgent", patch)
    assert len(store.get_state().candidate_patches) == 1
    assert store.get_state().candidate_patches[0].patch_hash != ""

    # 5. Post Test Result
    test_run = SandboxTestExecution(
        execution_id="exec_1",
        candidate_patch_id="patch_1",
        exit_code=0,
        all_passed=True,
        total_tests=5,
        passed_tests=5,
        failed_tests=0
    )
    store.post_test_result("TestingAgent", test_run)
    assert store.get_state().status == "tested"


def test_guardrails_constructive():
    guard = InputSecurityGuardrail()
    prompt = get_persona_prompt("constructive", "KeyError in auth token lookup", "Traceback...")
    res = guard.evaluate_prompt(prompt)
    assert res.is_safe is True
    assert res.injection_detected is False
    assert res.toxicity_detected is False


def test_guardrails_toxic():
    guard = InputSecurityGuardrail()
    prompt = get_persona_prompt("stressed", "KeyError in auth token lookup", "Traceback...")
    res = guard.evaluate_prompt(prompt)
    assert res.toxicity_detected is True
    assert "[NEUTRALIZED]" in res.sanitized_prompt or "resolve the bug" in res.sanitized_prompt


def test_guardrails_adversarial():
    guard = InputSecurityGuardrail()
    prompt = get_persona_prompt("adversarial", "DivisionByZero in calculator", "Traceback...")
    res = guard.evaluate_prompt(prompt)
    assert res.is_safe is False
    assert res.injection_detected is True
    assert "INSTRUCTION_OVERRIDE" in res.detected_patterns
    assert "[SECURITY GUARD: BLOCKED" in res.sanitized_prompt


def test_guardrails_none_and_empty():
    guard = InputSecurityGuardrail()
    res_none = guard.evaluate_prompt(None)
    assert res_none.is_safe is True
    assert res_none.sanitized_prompt == ""

    res_empty = guard.evaluate_prompt("")
    assert res_empty.is_safe is True
    assert res_empty.sanitized_prompt == ""

