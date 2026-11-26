"""
CrewAI Coordinator Agent with Telemetry and Callback Integration
Orchestrates the entire multi-agent lifecycle:
- Hierarchical single-bug debugging sessions via A2A Gateway
- Complete Multi-Agent Code Inspection across all 5 specialized agents
- Autonomous Code Correction, patch diffing, and anti-hallucination verification
"""
import time
import os
import uuid
from typing import Dict, Any, Optional, List
from src.blackboard.store import BlackboardStore
from src.blackboard.schema import FullInspectionReport, CodeIssue
from src.a2a.gateway import A2AGateway
from src.agents.google_adk.codebase_analyst import CodebaseAnalystAgent
from src.agents.google_adk.debugging_agent import DebuggingAgent
from src.agents.google_adk.testing_agent import TestingAgent
from src.agents.google_adk.static_analysis_agent import StaticAnalysisAgent
from src.agents.google_adk.security_analysis_agent import SecurityAnalysisAgent
from src.agents.google_adk.runtime_dependency_agent import RuntimeDependencyAgent
from src.agents.google_adk.evaluator_critic_agent import EvaluatorCriticAgent
from src.agents.google_adk.llm_code_review_agent import LLMCodeReviewAgent
from src.analysis.corrector import AutonomousCodeCorrector
from src.agents.crewai.reviewer import PatchReviewerAgent
from src.guardrails.input_filter import InputSecurityGuardrail
from src.telemetry.callbacks import TelemetryTracker
from src.telemetry.tracer import DevPilotTracer


class CoordinatorAgent:
    def __init__(self, agent_id: str = "crewai_coordinator", max_backtrack_retries: int = 2, gateway: Optional[A2AGateway] = None):
        self.agent_id = agent_id
        self.max_backtrack_retries = max_backtrack_retries
        self.guardrail = InputSecurityGuardrail()
        self.gateway = gateway if gateway is not None else A2AGateway()

        # Multi-Agent Roster
        # CrewAI Agents
        self.reviewer = PatchReviewerAgent()

        # Initialize CrewAI Core Agent
        try:
            from crewai import Agent
            self.crewai_agent = Agent(
                role="Autonomous Debugging Coordinator",
                goal="Coordinate multi-agent investigations, evaluate root-cause hypotheses, manage A2A agent delegations, and supervise patch review.",
                backstory="Staff Systems Architect overseeing end-to-end multi-agent debugging workflows with CrewAI and Google ADK.",
                verbose=False
            )
        except Exception:
            self.crewai_agent = None

        # Google ADK Agents
        self.analyst = CodebaseAnalystAgent()
        self.static_agent = StaticAnalysisAgent()
        self.security_agent = SecurityAnalysisAgent()
        self.runtime_agent = RuntimeDependencyAgent()
        self.evaluator_agent = EvaluatorCriticAgent()
        self.debugger = DebuggingAgent()
        self.llm_code_review = LLMCodeReviewAgent(client=self.debugger.gemini_client)
        self.tester = TestingAgent()

        # Autonomous Correction Engine
        self.corrector = AutonomousCodeCorrector()

        # Register Agent Roster and Capabilities into A2A Gateway
        self.gateway.register_agent("adk_codebase_analyst", "Google ADK", ["analyze_codebase"])
        self.gateway.register_agent("adk_debugging_agent", "Google ADK", ["diagnose_root_cause"])
        self.gateway.register_agent("adk_testing_agent", "Google ADK", ["execute_sandbox_tests"])
        self.gateway.register_agent("crewai_patch_reviewer", "CrewAI", ["review_patch"])

        # Wire workers into A2A Gateway using serializable JSON-RPC parameter handlers
        self.gateway.register_method("analyze_codebase", lambda params: self.analyst.execute_analysis(params))
        self.gateway.register_method("diagnose_root_cause", lambda params: self.debugger.execute_debugging(params))
        self.gateway.register_method("execute_sandbox_tests", lambda params: self.tester.execute_testing(params))
        self.gateway.register_method("review_patch", lambda params: self.reviewer.review_and_finalize(params))
        self.gateway.register_method("ping", lambda params: {"status": "ok"})

    def create_investigation_plan(self, prompt: str, trace: str) -> Dict[str, Any]:
        """Creates a structured multi-agent investigation plan."""
        return {
            "plan_id": f"plan_{uuid.uuid4().hex[:6]}",
            "stages": [
                {"stage": 1, "agent": "adk_codebase_analyst", "goal": "Map codebase AST, extract symbol hierarchies, and index semantic vectors via MCP."},
                {"stage": 2, "agent": "adk_debugging_agent", "goal": "Execute ReAct cycle, query documentation, and formulate ranked hypotheses."},
                {"stage": 3, "agent": "adk_testing_agent", "goal": "Execute test suite inside hardened Docker sandbox and detect regressions."},
                {"stage": 4, "agent": "crewai_patch_reviewer", "goal": "Audit candidate diff for security, redact secrets, and generate tri-format review report for human approval."}
            ]
        }

    def run_full_inspection(
        self,
        repo_path: str,
        optional_context: str = "",
        test_file: Optional[str] = None
    ) -> FullInspectionReport:
        """
        Executes the Complete 5-Agent Code Inspection:
        1. Agent 1: Maps codebase structure, LOC, detected languages.
        2. Agent 2: Static Analysis (syntax, logic, quality).
        3. Agent 3: Security Analysis (SQLi, cmd injection, secrets, path traversal, unsafe eval).
        4. Agent 4: Runtime & Dependency Analysis (ZeroDivision, KeyError, NoneType, missing env).
        5. Agent 5: Evaluator / Critic Agent (anti-hallucination verification, false positive elimination).
        6. Autonomous Code Correction: generates unified patch and diffs.
        """
        start_time = time.time()
        run_id = f"insp_{uuid.uuid4().hex[:8]}"
        clean_path = os.path.abspath(repo_path.strip(' "\''))
        timings: Dict[str, float] = {}
        blackboard = BlackboardStore(run_id=run_id)
        blackboard.update_input(
            agent_name=self.agent_id,
            prompt=optional_context or "Inspect uploaded source code.",
            sanitized_prompt=optional_context or "Inspect uploaded source code.",
            persona="constructive",
            repo_path=clean_path,
            error_trace="",
        )
        blackboard.set_status(self.agent_id, "analyzing")

        # Step 1: Agent 1 - Code Understanding
        t_agent_start = time.time()
        code_meta = self.analyst.inspect_codebase(clean_path)
        files_to_scan = code_meta["python_files"]
        timings["agent_analysis_sec"] = round(time.time() - t_agent_start, 3)
        t_mcp_start = time.time()
        try:
            # This A2A handler performs MCP AST parsing and vector indexing.
            worker_url = os.getenv("A2A_WORKER_URL")
            dispatch_params = {"run_id": run_id, "repo_path": clean_path}
            if worker_url and clean_path.startswith(os.path.abspath("devpilot_uploads") + os.sep):
                self.gateway.dispatch_http(
                    worker_url, "analyze_codebase", dispatch_params,
                    token=os.getenv("A2A_TOKEN"),
                )
            else:
                self.gateway.dispatch("analyze_codebase", dispatch_params)
            # The worker writes to the shared Redis state from another process.
            # Refresh before this coordinator posts its next status update.
            blackboard.get_state()
            mcp_status = "completed"
        except Exception as exc:
            mcp_status = f"unavailable: {type(exc).__name__}"
        timings["mcp_analysis_sec"] = round(time.time() - t_mcp_start, 3)

        # Step 2: Agent 2, 3, 4 - Static & Specialized Analysis
        t_static_start = time.time()
        static_findings = self.static_agent.analyze_files(files_to_scan, repo_root=clean_path)
        security_findings = self.security_agent.analyze_files(files_to_scan, repo_root=clean_path)
        runtime_findings = self.runtime_agent.analyze_files(files_to_scan, repo_root=clean_path)
        all_candidate_issues = static_findings + security_findings + runtime_findings
        if os.path.isfile(clean_path):
            for issue in all_candidate_issues:
                if issue.file_path in (".", ""):
                    issue.file_path = os.path.basename(clean_path)
        timings["static_analysis_sec"] = round(time.time() - t_static_start, 3)

        # Add model review of the actual inspected source files. Model findings
        # are line-grounded by the reviewer and remain unverified until tests pass.
        t_llm_start = time.time()
        blackboard.set_status(self.agent_id, "reviewing_source")
        # Prioritize core application files over auxiliary test suites for high-velocity deep LLM review
        core_files = [f for f in files_to_scan if not any(t in f.replace("\\", "/").lower() for t in ["/test", "/tests", "test_"])]
        if not core_files:
            core_files = files_to_scan
        llm_files_to_scan = core_files[:10] + [f for f in files_to_scan if f not in core_files][:3]
        llm_result = self.llm_code_review.review_files(llm_files_to_scan, repo_root=clean_path)
        for issue in llm_result["issues"]:
            detected_language = self.analyst.lang_manager.detect_file_language(issue.file_path)
            if detected_language:
                issue.language = detected_language
        timings["llm_review_sec"] = round(time.time() - t_llm_start, 3)

        # Step 3: Agent 5 - Evaluator / Critic Agent & Dynamic Verification
        t_eval_start = time.time()
        blackboard.set_status(self.agent_id, "verifying")
        verified_issues, false_positives_rejected, verification_summary, coverage_report = self.evaluator_agent.evaluate_and_verify(
            all_candidate_issues,
            repo_root=clean_path,
            test_file=test_file,
        )
        # Model findings cite actual source lines but their suggested replacements
        # have not passed a patch test. Keep them in the report without feeding
        # them into the correction engine or changing static finding verification.
        existing = {(issue.file_path.replace("\\", "/"), issue.line_number, issue.category) for issue in verified_issues}
        for issue in llm_result["issues"]:
            key = (issue.file_path.replace("\\", "/"), issue.line_number, issue.category)
            if key not in existing:
                verified_issues.append(issue)
                existing.add(key)
        coverage_report = self.evaluator_agent._generate_coverage_report(clean_path, verified_issues, false_positives_rejected)
        timings["evaluator_verification_sec"] = round(time.time() - t_eval_start, 3)

        # Step 4: Autonomous Correction & Unified Diff Generation
        t_patch_start = time.time()
        unified_diff_str = ""
        # Never publish generated diffs from rule-template suggestions that have
        # not passed a relevant runtime check. The UI may still show these as
        # review suggestions, but they are not safe to present as patches.
        patchable_issues = [issue for issue in verified_issues if issue.verified and issue.status != "rejected_syntax_error"]
        if patchable_issues:
            if os.path.isfile(clean_path):
                try:
                    with open(clean_path, "r", encoding="utf-8", errors="replace", newline="") as f:
                        orig_text = f.read()
                    corr_text = self.corrector.generate_corrected_file(orig_text, patchable_issues)
                    unified_diff_str = self.corrector.generate_unified_patch(
                        orig_text, corr_text, os.path.basename(clean_path)
                    )
                except Exception:
                    pass
            else:
                diff_blocks = []
                issues_by_file: Dict[str, List[CodeIssue]] = {}
                for iss in patchable_issues:
                    issues_by_file.setdefault(iss.file_path, []).append(iss)
                for rel_file, file_iss in issues_by_file.items():
                    full_p = os.path.join(clean_path, rel_file)
                    if os.path.exists(full_p):
                        try:
                            with open(full_p, "r", encoding="utf-8", errors="replace", newline="") as f:
                                orig = f.read()
                            corr = self.corrector.generate_corrected_file(orig, file_iss)
                            diff_blocks.append(self.corrector.generate_unified_patch(orig, corr, rel_file.replace("\\", "/")))
                        except Exception:
                            pass
                unified_diff_str = "\n".join(diff_blocks)
        timings["patch_generation_sec"] = round(time.time() - t_patch_start, 3)

        # Step 5: Sandbox Testing Timing
        t_test_start = time.time()
        test_summary = {
            "status": verification_summary["status"],
            "reason": verification_summary.get("reason"),
            "sandbox_tested": verification_summary.get("sandbox_tested", False),
            "overall_passed": verification_summary.get("overall_passed", False),
            "total_checks": verification_summary.get("total_checks", 0),
            "passed_checks": verification_summary.get("passed_checks", 0),
            "failed_checks": verification_summary.get("failed_checks", 0),
            "test_details": verification_summary.get("tests", {}),
            "mcp_analysis": mcp_status,
            "llm_review": {
                "status": llm_result["status"],
                "files_reviewed": llm_result.get("files_reviewed", 0),
                "chunks_reviewed": llm_result.get("chunks_reviewed", 0),
                "failed_chunks": llm_result.get("failed_chunks", 0),
                "findings_added": len(llm_result["issues"]),
                "reason": llm_result.get("reason"),
            }
        }
        if test_file:
            test_summary["test_file"] = test_file
        timings["sandbox_testing_sec"] = round(time.time() - t_test_start, 3)

        total_duration = round(time.time() - start_time, 3)
        timings["total_duration_sec"] = total_duration

        # Categorize metrics
        crit_count = sum(1 for i in verified_issues if i.severity == "critical")
        high_count = sum(1 for i in verified_issues if i.severity == "high")
        med_count = sum(1 for i in verified_issues if i.severity == "medium")
        low_count = sum(1 for i in verified_issues if i.severity == "low")

        sec_count = sum(1 for i in verified_issues if i.category == "security")
        run_count = sum(1 for i in verified_issues if i.category == "runtime")
        log_count = sum(1 for i in verified_issues if i.category == "logic")
        qua_count = sum(1 for i in verified_issues if i.category == "quality")
        syn_count = sum(1 for i in verified_issues if i.category == "syntax")
        cfg_count = sum(1 for i in verified_issues if i.category == "config")

        verified_patches = sum(1 for i in verified_issues if i.verified)
        rejected_patches = false_positives_rejected + sum(1 for i in verified_issues if i.status == "rejected_syntax_error")
        unverified_patches = sum(1 for i in verified_issues if not i.verified and i.status != "rejected_syntax_error")

        # Multi-language breakdown
        lang_breakdown: Dict[str, Any] = {}
        for lang, files in code_meta.get("files_by_language", {}).items():
            if len(files) > 0:
                issues_in_lang = sum(1 for iss in verified_issues if (
                    getattr(iss, "language", "") == lang or
                    (lang == "JavaScript" and iss.file_path.endswith((".js", ".jsx", ".mjs"))) or
                    (lang == "TypeScript" and iss.file_path.endswith((".ts", ".tsx"))) or
                    (lang == "Java" and iss.file_path.endswith(".java")) or
                    (lang == "C/C++" and iss.file_path.endswith((".c", ".cpp", ".cc", ".h", ".hpp"))) or
                    (lang == "Python" and iss.file_path.endswith((".py", ".pyw")))
                ))
                lang_breakdown[lang] = {
                    "files": len(files),
                    "issues": issues_in_lang
                }

        # Step 6: Before-and-After Security Comparison (Requirement 11)
        security_comparison: List[Dict[str, Any]] = []
        for iss in verified_issues:
            cwe = "CWE-699"
            if "SQL" in iss.title:
                cwe = "CWE-89 (SQL Injection)"
            elif "Command" in iss.title:
                cwe = "CWE-78 (OS Command Injection)"
            elif "eval" in iss.title:
                cwe = "CWE-95 (Improper Neutralization of Code in Eval)"
            elif "Path Traversal" in iss.title:
                cwe = "CWE-22 (Improper Limitation of Pathname)"
            elif "API_KEY" in iss.title or "Secret" in iss.title:
                cwe = "CWE-798 (Use of Hardcoded Credentials)"
            elif "ZeroDivision" in iss.title:
                cwe = "CWE-369 (Divide By Zero)"
            elif "KeyError" in iss.title or "None" in iss.title:
                cwe = "CWE-476 (NULL Pointer / Missing Key Dereference)"
            elif "Mutable Default" in iss.title:
                cwe = "CWE-665 (Improper Initialization: Mutable Default State)"
            elif "Boundary" in iss.title:
                cwe = "CWE-20 (Improper Input & Range Validation)"
            elif "Bare" in iss.title:
                cwe = "CWE-391 (Unchecked Error Condition / Broad Exception)"

            security_comparison.append({
                "issue_id": iss.id,
                "vulnerability": iss.title,
                "cwe": cwe,
                "file": iss.file_path,
                "line": iss.line_number,
                "before": {
                    "code": iss.original_code.strip(),
                    "defect": iss.what_is_wrong,
                    "risk_level": iss.severity.upper()
                },
                "after": {
                    "code": iss.corrected_code.strip(),
                    "mitigation": iss.explanation_of_correction,
                    "status": "Mitigated & Tested" if iss.verified else iss.status
                },
                "test_validation": {
                    "passed": iss.test_results.get("passed"),
                    "checks": iss.test_results.get("checks_passed", 0)
                },
                "remaining_risks": iss.remaining_risks
            })

        blackboard.set_status(self.agent_id, "completed")
        report = FullInspectionReport(
            run_id=run_id,
            repo_path=clean_path,
            total_files=code_meta["total_files"],
            total_loc=code_meta["total_loc"],
            languages_detected=code_meta["languages_detected"],
            language_breakdown=lang_breakdown,
            manifests_detected=code_meta.get("manifests_found", []),
            toolchains_active=code_meta.get("toolchain_status", {}),
            total_issues=len(verified_issues),
            critical_issues=crit_count,
            high_issues=high_count,
            medium_issues=med_count,
            low_issues=low_count,
            security_issues=sec_count,
            runtime_issues=run_count,
            logical_issues=log_count,
            quality_issues=qua_count,
            syntax_issues=syn_count,
            config_issues=cfg_count,
            verified_patches=verified_patches,
            rejected_patches=rejected_patches,
            unverified_patches=unverified_patches,
            false_positives_rejected=false_positives_rejected,
            duration_sec=total_duration,
            timings=timings,
            issues=verified_issues,
            unified_patch=unified_diff_str,
            tests_summary=test_summary,
            security_comparison=security_comparison,
            coverage_report=coverage_report,
            state_sha256=blackboard.get_state().get_state_hash()
        )

        return report

    def run_debugging_session(
        self,
        repo_path: str,
        user_prompt: str,
        error_trace: str,
        persona: str = "constructive",
        test_file: Optional[str] = None
    ) -> Dict[str, Any]:
        """Executes the full hierarchical multi-agent workflow with telemetry and backtracking."""
        from config.settings import settings
        run_id = f"run_{uuid.uuid4().hex[:8]}"
        blackboard = BlackboardStore(run_id=run_id, backend=settings.blackboard_backend)
        telemetry = TelemetryTracker(run_id=run_id)
        tracer = DevPilotTracer(run_id=run_id)

        # 0. Generate Investigation Plan
        plan = self.create_investigation_plan(user_prompt, error_trace)

        # 1. Intake & Guardrail Validation
        s0 = telemetry.on_step_start(self.agent_id, "intake_guardrails", est_input_tokens=150)
        guard_res = self.guardrail.evaluate_prompt(user_prompt)
        blackboard.update_input(
            agent_name=self.agent_id,
            prompt=user_prompt,
            sanitized_prompt=guard_res.sanitized_prompt,
            persona=persona,
            repo_path=repo_path,
            error_trace=error_trace
        )
        telemetry.on_step_end(s0, est_output_tokens=80)

        if not guard_res.is_safe:
            blackboard.set_status(self.agent_id, "rejected_by_guardrails")
            return {
                "run_id": run_id,
                "status": "blocked",
                "reason": "Prompt rejected by input security guardrails.",
                "detected_patterns": guard_res.detected_patterns,
                "telemetry": telemetry,
                "tracer": tracer,
                "final_state": blackboard.get_state()
            }

        # 2. Step 1: Codebase Analysis via A2A
        blackboard.set_status(self.agent_id, "analyzing")
        s1 = telemetry.on_step_start("adk_codebase_analyst", "ast_and_vector_indexing", est_input_tokens=300)
        telemetry.on_tool_start("ASTParserTool", "adk_codebase_analyst")
        analysis_res = self.gateway.dispatch("analyze_codebase", {
            "run_id": run_id,
            "repo_path": repo_path
        })
        telemetry.on_tool_end("ASTParserTool", "adk_codebase_analyst")
        telemetry.on_step_end(s1, est_output_tokens=220)

        # 3. Step 2 & 3: Diagnosis and Testing with Hierarchical Backtracking
        retries = 0
        all_passed = False

        while retries <= self.max_backtrack_retries and not all_passed:
            # Diagnosis via A2A
            blackboard.set_status(self.agent_id, "debugging")
            s2 = telemetry.on_step_start("adk_debugging_agent", f"react_diagnosis_attempt_{retries+1}", est_input_tokens=450)
            telemetry.on_tool_start("VectorCodebaseTool", "adk_debugging_agent")
            debug_res = self.gateway.dispatch("diagnose_root_cause", {
                "run_id": run_id,
                "repo_path": repo_path
            })
            telemetry.on_tool_end("VectorCodebaseTool", "adk_debugging_agent")
            telemetry.on_step_end(s2, est_output_tokens=350)

            # Testing via A2A in isolated Docker sandbox
            blackboard.set_status(self.agent_id, "testing")
            s3 = telemetry.on_step_start("adk_testing_agent", f"sandbox_pytest_attempt_{retries+1}", est_input_tokens=200)
            telemetry.on_tool_start("DockerSandboxTool", "adk_testing_agent")
            test_res = self.gateway.dispatch("execute_sandbox_tests", {
                "run_id": run_id,
                "repo_path": repo_path,
                "test_file": test_file
            })
            telemetry.on_tool_end("DockerSandboxTool", "adk_testing_agent")
            telemetry.on_step_end(s3, est_output_tokens=180)

            all_passed = test_res.get("all_passed", False)
            regression = test_res.get("regression_detected", False)

            if all_passed and not regression:
                break

            retries += 1
            if retries <= self.max_backtrack_retries:
                telemetry.on_error(s3, RuntimeError("Sandbox tests failed or regression detected."))
                blackboard.set_status(self.agent_id, f"backtracking_retry_{retries}")

        # 4. Step 4: Patch Review & Report Compilation via A2A
        blackboard.set_status(self.agent_id, "reviewing")
        s4 = telemetry.on_step_start("crewai_patch_reviewer", "security_audit_and_report", est_input_tokens=320)
        review_res = self.gateway.dispatch("review_patch", {
            "run_id": run_id,
            "repo_path": repo_path
        })
        telemetry.on_step_end(s4, est_output_tokens=400)

        final_state = blackboard.get_state()

        # Audit patch and final report with tracer
        if final_state.candidate_patches:
            tracer.log_provenance("candidate_patch", final_state.candidate_patches[-1].diff)
        if final_state.final_report:
            tracer.log_provenance("final_diagnosis", final_state.final_report.model_dump_json())

        return {
            "run_id": run_id,
            "status": final_state.status,
            "all_passed": all_passed,
            "retries": retries,
            "investigation_plan": plan,
            "analysis": analysis_res,
            "review": review_res,
            "human_approval_state": final_state.human_approval_state,
            "final_state": final_state,
            "telemetry": telemetry,
            "tracer": tracer
        }


class SequentialCoordinator:
    """
    Baseline Single-Pass Sequential Coordinator.
    Executes a linear, single-pass pipeline (Analyst -> Debugger -> Tester -> Reviewer)
    WITHOUT dynamic hierarchical backtracking, multi-hypothesis ReAct loop, or iterative refinement.
    Used for empirical ablation comparisons against the hierarchical DevPilot architecture.
    """

    def __init__(self, agent_id: str = "baseline_sequential_coordinator"):
        self.agent_id = agent_id
        self.guardrail = InputSecurityGuardrail()
        self.gateway = A2AGateway()
        self.analyst = CodebaseAnalystAgent()
        self.debugger = DebuggingAgent()
        self.tester = TestingAgent()
        self.reviewer = PatchReviewerAgent()

        self.gateway.register_agent("adk_codebase_analyst", "Google ADK", ["analyze_codebase"])
        self.gateway.register_agent("adk_debugging_agent", "Google ADK", ["diagnose_root_cause"])
        self.gateway.register_agent("adk_testing_agent", "Google ADK", ["execute_sandbox_tests"])
        self.gateway.register_agent("crewai_patch_reviewer", "CrewAI", ["review_patch"])

        self.gateway.register_method("analyze_codebase", lambda params: self.analyst.execute_analysis(params))
        self.gateway.register_method("diagnose_root_cause", lambda params: self.debugger.execute_debugging(params))
        self.gateway.register_method("execute_sandbox_tests", lambda params: self.tester.execute_testing(params))
        self.gateway.register_method("review_patch", lambda params: self.reviewer.review_and_finalize(params))

    def run_debugging_session(
        self,
        repo_path: str,
        user_prompt: str,
        error_trace: str,
        persona: str = "constructive",
        test_file: Optional[str] = None
    ) -> Dict[str, Any]:
        """Executes a single-pass linear pipeline without retry loops or backtracking."""
        from config.settings import settings
        run_id = f"seq_{uuid.uuid4().hex[:8]}"
        blackboard = BlackboardStore(run_id=run_id, backend=settings.blackboard_backend)
        telemetry = TelemetryTracker(run_id=run_id)
        tracer = DevPilotTracer(run_id=run_id)

        # 1. Intake & Guardrail
        guard_res = self.guardrail.evaluate_prompt(user_prompt)
        blackboard.update_input(
            agent_name=self.agent_id,
            prompt=user_prompt,
            sanitized_prompt=guard_res.sanitized_prompt,
            persona=persona,
            repo_path=repo_path,
            error_trace=error_trace
        )

        if not guard_res.is_safe:
            blackboard.set_status(self.agent_id, "rejected_by_guardrails")
            return {
                "run_id": run_id,
                "status": "blocked",
                "reason": "Prompt rejected by input security guardrails.",
                "all_passed": False,
                "retries": 0,
                "final_state": blackboard.get_state(),
                "telemetry": telemetry,
                "tracer": tracer
            }

        # 2. Linear Step 1: Codebase Analysis
        analysis_res = self.gateway.dispatch("analyze_codebase", {"run_id": run_id, "repo_path": repo_path})

        # 3. Linear Step 2: Single-pass Diagnosis (No ReAct iterative loops)
        debug_res = self.gateway.dispatch("diagnose_root_cause", {"run_id": run_id, "repo_path": repo_path})

        # 4. Linear Step 3: Single Test Execution (No backtracking on failure)
        test_res = self.gateway.dispatch("execute_sandbox_tests", {
            "run_id": run_id,
            "repo_path": repo_path,
            "test_file": test_file
        })
        all_passed = test_res.get("all_passed", False)

        # 5. Linear Step 4: Patch Review
        review_res = self.gateway.dispatch("review_patch", {"run_id": run_id, "repo_path": repo_path})

        final_state = blackboard.get_state()
        return {
            "run_id": run_id,
            "status": final_state.status,
            "all_passed": all_passed,
            "retries": 0,
            "investigation_plan": {"mode": "linear_single_pass"},
            "analysis": analysis_res,
            "review": review_res,
            "human_approval_state": final_state.human_approval_state,
            "final_state": final_state,
            "telemetry": telemetry,
            "tracer": tracer
        }

